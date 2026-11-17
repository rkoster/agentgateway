//! Shared operator backends are resolved by the gateway, never snapshotted with
//! upstream credentials into broker-managed instances or grants.
use serde_json::Value;

pub(crate) fn materialize_mcp_grant(
	definitions: &[Value],
	grant: &Value,
	route: &Value,
) -> anyhow::Result<Value> {
	let mut route = route.clone();
	let Some(selections) = grant.get("backendSelections").and_then(Value::as_array) else {
		return Ok(route);
	};
	let mut targets = Vec::new();
	for selection in selections {
		let definition = definitions
			.iter()
			.find(|d| d.get("name") == selection.get("name"))
			.ok_or_else(|| anyhow::anyhow!("MCP backend reference is missing"))?;
		anyhow::ensure!(
			definition.get("revision").is_some()
				&& definition.get("revision") == selection.get("revision"),
			"MCP backend revision mismatch"
		);
		let prefix = selection
			.get("targetPrefix")
			.and_then(Value::as_str)
			.ok_or_else(|| anyhow::anyhow!("targetPrefix required"))?;
		let parameters = selection
			.get("parameters")
			.and_then(Value::as_object)
			.ok_or_else(|| anyhow::anyhow!("instance parameters required"))?;
		for target in definition
			.get("targets")
			.and_then(Value::as_array)
			.ok_or_else(|| anyhow::anyhow!("MCP backend targets required"))?
		{
			let mut target = target.clone();
			let name = target
				.get("name")
				.and_then(Value::as_str)
				.ok_or_else(|| anyhow::anyhow!("MCP target name required"))?;
			target["name"] = Value::String(format!("{prefix}-{name}"));
			if let Some(client) =
				target.pointer_mut("/policies/backendAuth/oauthTokenExchange/clientAuth/clientId")
			{
				if let Some(parameter) = client.get("fromInstanceParameter").and_then(Value::as_str) {
					*client = parameters
						.get(parameter)
						.filter(|v| v.as_str().is_some_and(|s| !s.is_empty()))
						.cloned()
						.ok_or_else(|| anyhow::anyhow!("required instance identity parameter missing"))?;
				}
			}
			targets.push(target);
		}
	}
	route["backends"] = serde_json::json!([{"mcp":{"targets": targets}}]);
	Ok(route)
}

#[cfg(test)]
mod tests {
	use super::*;
	use serde_json::json;
	#[test]
	fn resolves_instance_selection_and_rotates_shared_credentials() {
		let mut definitions = json!([{"name":"tools","revision":"v1","targets":[{"name":"work","mcp":{"host":"https://tools.test"},"policies":{"backendAuth":{"oauthTokenExchange":{"clientAuth":{"clientId":{"fromInstanceParameter":"client_id"}}}},"requestHeaderModifier":{"set":{"X-Key":"old"}}}}]}]);
		let grant = json!({"backendSelections":[{"name":"tools","revision":"v1","targetPrefix":"binding-generation","parameters":{"client_id":"selected"}}]});
		let route = materialize_mcp_grant(
			definitions.as_array().unwrap(),
			&grant,
			&json!({"name":"route"}),
		)
		.unwrap();
		assert_eq!(
			route.pointer(
				"/backends/0/mcp/targets/0/policies/backendAuth/oauthTokenExchange/clientAuth/clientId"
			),
			Some(&json!("selected"))
		);
		assert_eq!(
			route.pointer("/backends/0/mcp/targets/0/name"),
			Some(&json!("binding-generation-work"))
		);
		definitions[0]["targets"][0]["policies"]["requestHeaderModifier"]["set"]["X-Key"] =
			json!("new");
		let rotated =
			materialize_mcp_grant(definitions.as_array().unwrap(), &grant, &json!({})).unwrap();
		assert_eq!(
			rotated.pointer("/backends/0/mcp/targets/0/policies/requestHeaderModifier/set/X-Key"),
			Some(&json!("new"))
		);
		assert!(!grant.to_string().contains("X-Key"));
		definitions[0]["revision"] = json!("v2");
		assert!(materialize_mcp_grant(definitions.as_array().unwrap(), &grant, &json!({})).is_err());
		assert!(materialize_mcp_grant(&[], &grant, &json!({})).is_err());
	}
}
