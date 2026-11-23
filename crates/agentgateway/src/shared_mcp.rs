//! Shared operator backends are resolved by the gateway, never snapshotted with
//! upstream credentials into broker-managed instances or grants.
use serde_json::Value;

pub(crate) fn materialize_mcp_grant(
	definitions: &[Value],
	grant: &Value,
	route: &Value,
) -> anyhow::Result<Option<Value>> {
	let mut route = route.clone();
	let Some(selections) = grant.get("backendSelections").and_then(Value::as_array) else {
		return Ok(Some(route));
	};
	let mut targets = Vec::new();
	for selection in selections {
		let Some(definition) = definitions
			.iter()
			.find(|d| d.get("name") == selection.get("name"))
		else {
			return Ok(None);
		};
		if definition.get("revision").is_none()
			|| definition.get("revision") != selection.get("revision")
		{
			return Ok(None);
		}
		if definition.get("teamOAuth").and_then(Value::as_bool) == Some(true) {
			if selections.len() != 1
				|| grant.pointer("/metadata/instance/backend/auth/method").and_then(Value::as_str)
					!= Some("team_oauth")
			{
				return Ok(None);
			}
			let tools = definition.get("allowedTools").and_then(Value::as_array);
			let Some(tools) = tools.filter(|tools| !tools.is_empty()) else {
				return Ok(None);
			};
			let mut rules = Vec::new();
			for tool in tools {
				if !tool.is_string() {
					return Ok(None);
				}
				rules.push(format!(
					r#"mcp.tool.name == {tool} && (mcp.methodName == "tools/list" || mcp.methodName == "tools/call")"#
				));
			}
			route["policies"]["mcpAuthorization"] = serde_json::json!({"rules": rules});
		} else if grant.pointer("/metadata/instance/backend/auth/method").and_then(Value::as_str)
			== Some("team_oauth")
		{
			return Ok(None);
		}
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
	Ok(Some(route))
}

#[cfg(test)]
mod tests {
	use super::*;
	use serde_json::json;

	#[test]
	fn unavailable_backend_omits_the_entire_grant_without_aborting_configuration() {
		let definitions = json!([{"name":"available","revision":"v2","targets":[{"name":"work","mcp":{"host":"https://tools.test"}}]}]);
		for unavailable in [
			json!({"name":"missing","revision":"v2"}),
			json!({"name":"available","revision":"v1"}),
		] {
			// A compatible first selection must not result in a partially exposed grant.
			let mut selection = unavailable;
			selection["targetPrefix"] = json!("generation");
			selection["parameters"] = json!({});
			let grant = json!({"backendSelections":[{"name":"available","revision":"v2","targetPrefix":"generation","parameters":{}},selection]});
			let route = materialize_mcp_grant(
				definitions.as_array().unwrap(),
				&grant,
				&json!({"name":"unavailable"}),
			)
			.expect("unavailable grant must not prevent gateway startup");
			assert!(
				route.is_none(),
				"no route from an incompatible grant may be exposed"
			);
		}
	}

	#[test]
	fn resolves_instance_selection_and_rotates_shared_credentials() {
		let mut definitions = json!([{"name":"tools","revision":"v1","targets":[{"name":"work","mcp":{"host":"https://tools.test"},"policies":{"backendAuth":{"oauthTokenExchange":{"clientAuth":{"clientId":{"fromInstanceParameter":"client_id"}}}},"requestHeaderModifier":{"set":{"X-Key":"old"}}}}]}]);
		let grant = json!({"backendSelections":[{"name":"tools","revision":"v1","targetPrefix":"binding-generation","parameters":{"client_id":"selected"}}]});
		let route = materialize_mcp_grant(
			definitions.as_array().unwrap(),
			&grant,
			&json!({"name":"route"}),
		)
		.unwrap()
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
		let rotated = materialize_mcp_grant(definitions.as_array().unwrap(), &grant, &json!({}))
			.unwrap()
			.unwrap();
		assert_eq!(
			rotated.pointer("/backends/0/mcp/targets/0/policies/requestHeaderModifier/set/X-Key"),
			Some(&json!("new"))
		);
		assert!(!grant.to_string().contains("X-Key"));
		definitions[0]["revision"] = json!("v2");
		assert!(
			materialize_mcp_grant(definitions.as_array().unwrap(), &grant, &json!({}))
				.unwrap()
				.is_none()
		);
		assert!(
			materialize_mcp_grant(&[], &grant, &json!({}))
				.unwrap()
				.is_none()
		);
	}
}
