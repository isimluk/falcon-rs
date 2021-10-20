/*
 * CrowdStrike API Specification
 *
 * Use this API specification as a reference for the API endpoints you can use to interact with your Falcon environment. These endpoints support authentication via OAuth2 and interact with detections and network containment. For detailed usage guides and more information about API endpoints that don't yet support OAuth2, see our [documentation inside the Falcon console](https://falcon.crowdstrike.com/support/documentation). To use the APIs described below, combine the base URL with the path shown for each API endpoint. For commercial cloud customers, your base URL is `https://api.crowdstrike.com`. Each API endpoint requires authorization via an OAuth2 token. Your first API request should retrieve an OAuth2 token using the `oauth2/token` endpoint, such as `https://api.crowdstrike.com/oauth2/token`. For subsequent requests, include the OAuth2 token in an HTTP authorization header. Tokens expire after 30 minutes, after which you should make a new token request to continue making API requests.
 *
 * The version of the OpenAPI document: 2021-10-05T19:33:53Z
 * 
 * Generated by: https://openapi-generator.tech
 */




#[derive(Clone, Debug, PartialEq, Default, Serialize, Deserialize)]
pub struct DomainActionV1 {
    /// The ID of the customer who created the action
    #[serde(rename = "cid")]
    pub cid: String,
    /// The date when the action was created
    #[serde(rename = "created_timestamp")]
    pub created_timestamp: String,
    #[serde(rename = "frequency")]
    pub frequency: String,
    /// The ID of the action
    #[serde(rename = "id")]
    pub id: String,
    /// The address list who will be notified by this action.
    #[serde(rename = "recipients")]
    pub recipients: Vec<String>,
    /// The ID of the rule on which this action is attached
    #[serde(rename = "rule_id")]
    pub rule_id: String,
    /// The action status. It can be either 'enabled' or 'muted'.
    #[serde(rename = "status")]
    pub status: String,
    /// The action type. The only type currently supported is 'email'
    #[serde(rename = "type")]
    pub _type: String,
    /// The date when the action was updated
    #[serde(rename = "updated_timestamp")]
    pub updated_timestamp: String,
    /// The UUID of the user who created the action
    #[serde(rename = "user_uuid")]
    pub user_uuid: String,
}

impl DomainActionV1 {
    pub fn new(cid: String, created_timestamp: String, frequency: String, id: String, recipients: Vec<String>, rule_id: String, status: String, _type: String, updated_timestamp: String, user_uuid: String) -> DomainActionV1 {
        DomainActionV1 {
            cid,
            created_timestamp,
            frequency,
            id,
            recipients,
            rule_id,
            status,
            _type,
            updated_timestamp,
            user_uuid,
        }
    }
}

