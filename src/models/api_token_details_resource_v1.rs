/*
 * CrowdStrike API Specification
 *
 * Use this API specification as a reference for the API endpoints you can use to interact with your Falcon environment. These endpoints support authentication via OAuth2 and interact with detections and network containment. For detailed usage guides and more information about API endpoints that don't yet support OAuth2, see our [documentation inside the Falcon console](https://falcon.crowdstrike.com/support/documentation). To use the APIs described below, combine the base URL with the path shown for each API endpoint. For commercial cloud customers, your base URL is `https://api.crowdstrike.com`. Each API endpoint requires authorization via an OAuth2 token. Your first API request should retrieve an OAuth2 token using the `oauth2/token` endpoint, such as `https://api.crowdstrike.com/oauth2/token`. For subsequent requests, include the OAuth2 token in an HTTP authorization header. Tokens expire after 30 minutes, after which you should make a new token request to continue making API requests.
 *
 * The version of the OpenAPI document: rolling
 *
 * Generated by: https://openapi-generator.tech
 */

#[derive(Clone, Debug, PartialEq, Default, Serialize, Deserialize)]
pub struct ApiTokenDetailsResourceV1 {
    #[serde(rename = "created_timestamp")]
    pub created_timestamp: String,
    #[serde(rename = "expires_timestamp")]
    pub expires_timestamp: String,
    #[serde(rename = "id")]
    pub id: String,
    #[serde(rename = "label")]
    pub label: String,
    #[serde(rename = "last_used_timestamp")]
    pub last_used_timestamp: String,
    #[serde(rename = "revoked_timestamp")]
    pub revoked_timestamp: String,
    #[serde(rename = "status")]
    pub status: String,
    #[serde(rename = "type")]
    pub _type: String,
    #[serde(rename = "value")]
    pub value: String,
}

impl ApiTokenDetailsResourceV1 {
    pub fn new(created_timestamp: String, expires_timestamp: String, id: String, label: String, last_used_timestamp: String, revoked_timestamp: String, status: String, _type: String, value: String) -> ApiTokenDetailsResourceV1 {
        ApiTokenDetailsResourceV1 {
            created_timestamp,
            expires_timestamp,
            id,
            label,
            last_used_timestamp,
            revoked_timestamp,
            status,
            _type,
            value,
        }
    }
}
