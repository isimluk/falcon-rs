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
pub struct DomainCidPolicyAssignments {
    #[serde(rename = "cid", skip_serializing_if = "Option::is_none")]
    pub cid: Option<String>,
    #[serde(rename = "cis_benchmark", skip_serializing_if = "Option::is_none")]
    pub cis_benchmark: Option<Vec<crate::models::DomainCidPolicyAssignmentsCisBenchmark>>,
    #[serde(rename = "cloud_service", skip_serializing_if = "Option::is_none")]
    pub cloud_service: Option<String>,
    #[serde(rename = "cloud_service_subtype", skip_serializing_if = "Option::is_none")]
    pub cloud_service_subtype: Option<String>,
    #[serde(rename = "default_severity", skip_serializing_if = "Option::is_none")]
    pub default_severity: Option<String>,
    #[serde(rename = "name", skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(rename = "nist_benchmark", skip_serializing_if = "Option::is_none")]
    pub nist_benchmark: Option<Vec<crate::models::DomainCidPolicyAssignmentsNistBenchmark>>,
    #[serde(rename = "pci_benchmark", skip_serializing_if = "Option::is_none")]
    pub pci_benchmark: Option<Vec<crate::models::DomainCidPolicyAssignmentsPciBenchmark>>,
    #[serde(rename = "policy_id", skip_serializing_if = "Option::is_none")]
    pub policy_id: Option<i32>,
    #[serde(rename = "policy_settings", skip_serializing_if = "Option::is_none")]
    pub policy_settings: Option<Vec<crate::models::DomainPolicySettingByAccountAndRegion>>,
    #[serde(rename = "policy_timestamp", skip_serializing_if = "Option::is_none")]
    pub policy_timestamp: Option<String>,
    #[serde(rename = "policy_type", skip_serializing_if = "Option::is_none")]
    pub policy_type: Option<String>,
}

impl DomainCidPolicyAssignments {
    pub fn new() -> DomainCidPolicyAssignments {
        DomainCidPolicyAssignments {
            cid: None,
            cis_benchmark: None,
            cloud_service: None,
            cloud_service_subtype: None,
            default_severity: None,
            name: None,
            nist_benchmark: None,
            pci_benchmark: None,
            policy_id: None,
            policy_settings: None,
            policy_timestamp: None,
            policy_type: None,
        }
    }
}

