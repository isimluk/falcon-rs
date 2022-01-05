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
pub struct DomainAwsConfiguration {
    /// The 12 digit AWS account which is hosting the centralized S3 bucket containing cloudtrail logs for all accounts.
    #[serde(rename = "cloudtrail_bucket_owner_id", skip_serializing_if = "Option::is_none")]
    pub cloudtrail_bucket_owner_id: Option<String>,
    /// Timestamp of when the settings were first provisioned within CrowdStrike's system.'
    #[serde(rename = "created_timestamp", skip_serializing_if = "Option::is_none")]
    pub created_timestamp: Option<String>,
    /// Timestamp of when the settings were last modified.
    #[serde(rename = "last_modified_timestamp", skip_serializing_if = "Option::is_none")]
    pub last_modified_timestamp: Option<String>,
    /// By setting this value, all subsequent accounts that are provisioned will default to using this value as the external ID.
    #[serde(rename = "static_external_id", skip_serializing_if = "Option::is_none")]
    pub static_external_id: Option<String>,
}

impl DomainAwsConfiguration {
    pub fn new() -> DomainAwsConfiguration {
        DomainAwsConfiguration {
            cloudtrail_bucket_owner_id: None,
            created_timestamp: None,
            last_modified_timestamp: None,
            static_external_id: None,
        }
    }
}
