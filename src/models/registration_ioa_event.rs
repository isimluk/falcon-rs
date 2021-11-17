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
pub struct RegistrationIoaEvent {
    #[serde(rename = "additional_event_data", skip_serializing_if = "Option::is_none")]
    pub additional_event_data: Option<String>,
    #[serde(rename = "aggregate", skip_serializing_if = "Option::is_none")]
    pub aggregate: Option<Box<crate::models::DomainIoaEventAggregate>>,
    #[serde(rename = "api_version", skip_serializing_if = "Option::is_none")]
    pub api_version: Option<String>,
    #[serde(rename = "cid")]
    pub cid: String,
    #[serde(rename = "cloud_account_id", skip_serializing_if = "Option::is_none")]
    pub cloud_account_id: Option<Box<crate::models::DomainCloudAccountId>>,
    #[serde(rename = "cloud_provider")]
    pub cloud_provider: String,
    #[serde(rename = "cloud_region", skip_serializing_if = "Option::is_none")]
    pub cloud_region: Option<String>,
    #[serde(rename = "enrichments", skip_serializing_if = "Option::is_none")]
    pub enrichments: Option<Box<crate::models::DomainIoaEnrichments>>,
    #[serde(rename = "error_code", skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,
    #[serde(rename = "error_message", skip_serializing_if = "Option::is_none")]
    pub error_message: Option<String>,
    #[serde(rename = "event_category", skip_serializing_if = "Option::is_none")]
    pub event_category: Option<String>,
    #[serde(rename = "event_created", skip_serializing_if = "Option::is_none")]
    pub event_created: Option<String>,
    #[serde(rename = "event_id", skip_serializing_if = "Option::is_none")]
    pub event_id: Option<String>,
    #[serde(rename = "event_name", skip_serializing_if = "Option::is_none")]
    pub event_name: Option<String>,
    #[serde(rename = "event_source", skip_serializing_if = "Option::is_none")]
    pub event_source: Option<String>,
    #[serde(rename = "event_type", skip_serializing_if = "Option::is_none")]
    pub event_type: Option<String>,
    #[serde(rename = "group_id", skip_serializing_if = "Option::is_none")]
    pub group_id: Option<String>,
    #[serde(rename = "management_event", skip_serializing_if = "Option::is_none")]
    pub management_event: Option<bool>,
    #[serde(rename = "policy_id")]
    pub policy_id: i32,
    #[serde(rename = "policy_statement")]
    pub policy_statement: String,
    #[serde(rename = "read_only", skip_serializing_if = "Option::is_none")]
    pub read_only: Option<bool>,
    #[serde(rename = "recipient_account_id", skip_serializing_if = "Option::is_none")]
    pub recipient_account_id: Option<String>,
    #[serde(rename = "request_id", skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    #[serde(rename = "request_parameters", skip_serializing_if = "Option::is_none")]
    pub request_parameters: Option<String>,
    #[serde(rename = "resources", skip_serializing_if = "Option::is_none")]
    pub resources: Option<String>,
    #[serde(rename = "response_elements", skip_serializing_if = "Option::is_none")]
    pub response_elements: Option<String>,
    #[serde(rename = "service")]
    pub service: String,
    #[serde(rename = "service_event_details", skip_serializing_if = "Option::is_none")]
    pub service_event_details: Option<String>,
    #[serde(rename = "severity")]
    pub severity: String,
    #[serde(rename = "shared_event_id", skip_serializing_if = "Option::is_none")]
    pub shared_event_id: Option<String>,
    #[serde(rename = "source_ip_address", skip_serializing_if = "Option::is_none")]
    pub source_ip_address: Option<String>,
    #[serde(rename = "state")]
    pub state: String,
    #[serde(rename = "user_agent", skip_serializing_if = "Option::is_none")]
    pub user_agent: Option<String>,
    #[serde(rename = "user_id", skip_serializing_if = "Option::is_none")]
    pub user_id: Option<String>,
    #[serde(rename = "user_identity", skip_serializing_if = "Option::is_none")]
    pub user_identity: Option<String>,
    #[serde(rename = "vertex_id")]
    pub vertex_id: String,
    #[serde(rename = "vertex_type")]
    pub vertex_type: String,
    #[serde(rename = "vpc_endpoint_id", skip_serializing_if = "Option::is_none")]
    pub vpc_endpoint_id: Option<String>,
}

impl RegistrationIoaEvent {
    pub fn new(cid: String, cloud_provider: String, policy_id: i32, policy_statement: String, service: String, severity: String, state: String, vertex_id: String, vertex_type: String) -> RegistrationIoaEvent {
        RegistrationIoaEvent {
            additional_event_data: None,
            aggregate: None,
            api_version: None,
            cid,
            cloud_account_id: None,
            cloud_provider,
            cloud_region: None,
            enrichments: None,
            error_code: None,
            error_message: None,
            event_category: None,
            event_created: None,
            event_id: None,
            event_name: None,
            event_source: None,
            event_type: None,
            group_id: None,
            management_event: None,
            policy_id,
            policy_statement,
            read_only: None,
            recipient_account_id: None,
            request_id: None,
            request_parameters: None,
            resources: None,
            response_elements: None,
            service,
            service_event_details: None,
            severity,
            shared_event_id: None,
            source_ip_address: None,
            state,
            user_agent: None,
            user_id: None,
            user_identity: None,
            vertex_id,
            vertex_type,
            vpc_endpoint_id: None,
        }
    }
}
