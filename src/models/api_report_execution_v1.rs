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
pub struct ApiReportExecutionV1 {
    #[serde(rename = "can_write")]
    pub can_write: bool,
    #[serde(rename = "created_on")]
    pub created_on: String,
    #[serde(rename = "customer_id")]
    pub customer_id: String,
    #[serde(rename = "expiration_on")]
    pub expiration_on: String,
    #[serde(rename = "id")]
    pub id: String,
    #[serde(rename = "job_reference")]
    pub job_reference: String,
    #[serde(rename = "last_updated_on")]
    pub last_updated_on: String,
    #[serde(rename = "report_file_reference")]
    pub report_file_reference: String,
    #[serde(rename = "result_metadata", skip_serializing_if = "Option::is_none")]
    pub result_metadata: Option<Box<crate::models::DomainResultMetadata>>,
    #[serde(rename = "scheduled_report_id")]
    pub scheduled_report_id: String,
    #[serde(rename = "shared_with")]
    pub shared_with: Vec<String>,
    #[serde(rename = "status")]
    pub status: String,
    #[serde(rename = "status_msg")]
    pub status_msg: String,
    #[serde(rename = "tracking", skip_serializing_if = "Option::is_none")]
    pub tracking: Option<String>,
    #[serde(rename = "trigger_reference")]
    pub trigger_reference: String,
    #[serde(rename = "type")]
    pub _type: String,
    #[serde(rename = "user_id")]
    pub user_id: String,
    #[serde(rename = "user_uuid")]
    pub user_uuid: String,
}

impl ApiReportExecutionV1 {
    pub fn new(can_write: bool, created_on: String, customer_id: String, expiration_on: String, id: String, job_reference: String, last_updated_on: String, report_file_reference: String, scheduled_report_id: String, shared_with: Vec<String>, status: String, status_msg: String, trigger_reference: String, _type: String, user_id: String, user_uuid: String) -> ApiReportExecutionV1 {
        ApiReportExecutionV1 {
            can_write,
            created_on,
            customer_id,
            expiration_on,
            id,
            job_reference,
            last_updated_on,
            report_file_reference,
            result_metadata: None,
            scheduled_report_id,
            shared_with,
            status,
            status_msg,
            tracking: None,
            trigger_reference,
            _type,
            user_id,
            user_uuid,
        }
    }
}

