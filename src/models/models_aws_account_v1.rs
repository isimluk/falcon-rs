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
pub struct ModelsAwsAccountV1 {
    #[serde(rename = "access_health", skip_serializing_if = "Option::is_none")]
    pub access_health: Option<Box<crate::models::ModelsAwsAccountAccessHealth>>,
    /// Alias/Name associated with the account. This is only updated once the account is in a registered state.
    #[serde(rename = "alias", skip_serializing_if = "Option::is_none")]
    pub alias: Option<String>,
    #[serde(rename = "cid", skip_serializing_if = "Option::is_none")]
    pub cid: Option<String>,
    /// Unique identifier for the cloudformation stack id used for provisioning.
    #[serde(rename = "cloudformation_stack_id", skip_serializing_if = "Option::is_none")]
    pub cloudformation_stack_id: Option<String>,
    /// URL of the CloudFormation template to execute. This is returned when mode is to set 'cloudformation' when provisioning.
    #[serde(rename = "cloudformation_url", skip_serializing_if = "Option::is_none")]
    pub cloudformation_url: Option<String>,
    /// The 12 digit AWS account which is hosting the S3 bucket containing cloudtrail logs for this account. If this field is set, it takes precedence of the settings level field.
    #[serde(rename = "cloudtrail_bucket_owner_id", skip_serializing_if = "Option::is_none")]
    pub cloudtrail_bucket_owner_id: Option<String>,
    /// Region where the S3 bucket containing cloudtrail logs resides. This is only set if using cloudformation to provision and create the trail.
    #[serde(rename = "cloudtrail_bucket_region", skip_serializing_if = "Option::is_none")]
    pub cloudtrail_bucket_region: Option<String>,
    /// Timestamp of when the account was first provisioned within CrowdStrike's system.'
    #[serde(rename = "created_timestamp", skip_serializing_if = "Option::is_none")]
    pub created_timestamp: Option<String>,
    /// ID assigned for use with cross account IAM role access.
    #[serde(rename = "external_id", skip_serializing_if = "Option::is_none")]
    pub external_id: Option<String>,
    /// The full arn of the IAM role created in this account to control access.
    #[serde(rename = "iam_role_arn", skip_serializing_if = "Option::is_none")]
    pub iam_role_arn: Option<String>,
    /// 12 digit AWS provided unique identifier for the account.
    #[serde(rename = "id", skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// Timestamp of when the account was last modified.
    #[serde(rename = "last_modified_timestamp", skip_serializing_if = "Option::is_none")]
    pub last_modified_timestamp: Option<String>,
    /// Timestamp of when the account was scanned.
    #[serde(rename = "last_scanned_timestamp", skip_serializing_if = "Option::is_none")]
    pub last_scanned_timestamp: Option<String>,
    /// Current version of permissions associated with IAM role and granted access.
    #[serde(rename = "policy_version", skip_serializing_if = "Option::is_none")]
    pub policy_version: Option<String>,
    /// Provisioning state of the account. Values can be; initiated, registered, unregistered.
    #[serde(rename = "provisioning_state", skip_serializing_if = "Option::is_none")]
    pub provisioning_state: Option<String>,
    /// Rate limiting setting to control the maximum number of requests that can be made within the rate_limit_time duration.
    #[serde(rename = "rate_limit_reqs", skip_serializing_if = "Option::is_none")]
    pub rate_limit_reqs: Option<i32>,
    /// Rate limiting setting to control the number of seconds for which rate_limit_reqs applies.
    #[serde(rename = "rate_limit_time", skip_serializing_if = "Option::is_none")]
    pub rate_limit_time: Option<i64>,
    /// Current version of cloudformation template used to manage access.
    #[serde(rename = "template_version", skip_serializing_if = "Option::is_none")]
    pub template_version: Option<String>,
}

impl ModelsAwsAccountV1 {
    pub fn new() -> ModelsAwsAccountV1 {
        ModelsAwsAccountV1 {
            access_health: None,
            alias: None,
            cid: None,
            cloudformation_stack_id: None,
            cloudformation_url: None,
            cloudtrail_bucket_owner_id: None,
            cloudtrail_bucket_region: None,
            created_timestamp: None,
            external_id: None,
            iam_role_arn: None,
            id: None,
            last_modified_timestamp: None,
            last_scanned_timestamp: None,
            policy_version: None,
            provisioning_state: None,
            rate_limit_reqs: None,
            rate_limit_time: None,
            template_version: None,
        }
    }
}
