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
pub struct DomainRule {
    #[serde(rename = "created_date")]
    pub created_date: i64,
    #[serde(rename = "description")]
    pub description: String,
    #[serde(rename = "id")]
    pub id: i32,
    #[serde(rename = "last_modified_date")]
    pub last_modified_date: i64,
    #[serde(rename = "name")]
    pub name: String,
    #[serde(rename = "rich_text_description")]
    pub rich_text_description: String,
    #[serde(rename = "short_description")]
    pub short_description: String,
    #[serde(rename = "tags")]
    pub tags: Vec<String>,
    #[serde(rename = "type")]
    pub _type: String,
}

impl DomainRule {
    pub fn new(created_date: i64, description: String, id: i32, last_modified_date: i64, name: String, rich_text_description: String, short_description: String, tags: Vec<String>, _type: String) -> DomainRule {
        DomainRule {
            created_date,
            description,
            id,
            last_modified_date,
            name,
            rich_text_description,
            short_description,
            tags,
            _type,
        }
    }
}

