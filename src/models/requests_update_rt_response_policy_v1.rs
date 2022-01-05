/*
 * CrowdStrike API Specification
 *
 * Use this API specification as a reference for the API endpoints you can use to interact with your Falcon environment. These endpoints support authentication via OAuth2 and interact with detections and network containment. For detailed usage guides and more information about API endpoints that don't yet support OAuth2, see our [documentation inside the Falcon console](https://falcon.crowdstrike.com/support/documentation). To use the APIs described below, combine the base URL with the path shown for each API endpoint. For commercial cloud customers, your base URL is `https://api.crowdstrike.com`. Each API endpoint requires authorization via an OAuth2 token. Your first API request should retrieve an OAuth2 token using the `oauth2/token` endpoint, such as `https://api.crowdstrike.com/oauth2/token`. For subsequent requests, include the OAuth2 token in an HTTP authorization header. Tokens expire after 30 minutes, after which you should make a new token request to continue making API requests.
 *
 * The version of the OpenAPI document: rolling
 *
 * Generated by: https://openapi-generator.tech
 */

/// RequestsUpdateRtResponsePolicyV1 : An update for a specific policy

#[derive(Clone, Debug, PartialEq, Default, Serialize, Deserialize)]
pub struct RequestsUpdateRtResponsePolicyV1 {
    /// The new description to assign to the policy
    #[serde(rename = "description", skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// The id of the policy to update
    #[serde(rename = "id")]
    pub id: String,
    /// The new name to assign to the policy
    #[serde(rename = "name", skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// A collection of realtime response policy settings to update
    #[serde(rename = "settings")]
    pub settings: Vec<crate::models::RequestsPreventionSettingV1>,
}

impl RequestsUpdateRtResponsePolicyV1 {
    /// An update for a specific policy
    pub fn new(id: String, settings: Vec<crate::models::RequestsPreventionSettingV1>) -> RequestsUpdateRtResponsePolicyV1 {
        RequestsUpdateRtResponsePolicyV1 { description: None, id, name: None, settings }
    }
}
