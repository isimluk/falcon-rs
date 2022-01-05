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
pub struct DomainECrimeKillChain {
    #[serde(rename = "attribution", skip_serializing_if = "Option::is_none")]
    pub attribution: Option<String>,
    #[serde(rename = "crimes", skip_serializing_if = "Option::is_none")]
    pub crimes: Option<String>,
    #[serde(rename = "customers", skip_serializing_if = "Option::is_none")]
    pub customers: Option<String>,
    #[serde(rename = "marketing", skip_serializing_if = "Option::is_none")]
    pub marketing: Option<String>,
    #[serde(rename = "monetization", skip_serializing_if = "Option::is_none")]
    pub monetization: Option<String>,
    #[serde(rename = "rich_text_attribution", skip_serializing_if = "Option::is_none")]
    pub rich_text_attribution: Option<String>,
    #[serde(rename = "rich_text_crimes", skip_serializing_if = "Option::is_none")]
    pub rich_text_crimes: Option<String>,
    #[serde(rename = "rich_text_customers", skip_serializing_if = "Option::is_none")]
    pub rich_text_customers: Option<String>,
    #[serde(rename = "rich_text_marketing", skip_serializing_if = "Option::is_none")]
    pub rich_text_marketing: Option<String>,
    #[serde(rename = "rich_text_monetization", skip_serializing_if = "Option::is_none")]
    pub rich_text_monetization: Option<String>,
    #[serde(rename = "rich_text_services_offered", skip_serializing_if = "Option::is_none")]
    pub rich_text_services_offered: Option<String>,
    #[serde(rename = "rich_text_services_used", skip_serializing_if = "Option::is_none")]
    pub rich_text_services_used: Option<String>,
    #[serde(rename = "rich_text_technical_tradecraft", skip_serializing_if = "Option::is_none")]
    pub rich_text_technical_tradecraft: Option<String>,
    #[serde(rename = "rich_text_victims", skip_serializing_if = "Option::is_none")]
    pub rich_text_victims: Option<String>,
    #[serde(rename = "services_offered", skip_serializing_if = "Option::is_none")]
    pub services_offered: Option<String>,
    #[serde(rename = "services_used", skip_serializing_if = "Option::is_none")]
    pub services_used: Option<String>,
    #[serde(rename = "technical_tradecraft", skip_serializing_if = "Option::is_none")]
    pub technical_tradecraft: Option<String>,
    #[serde(rename = "victims", skip_serializing_if = "Option::is_none")]
    pub victims: Option<String>,
}

impl DomainECrimeKillChain {
    pub fn new() -> DomainECrimeKillChain {
        DomainECrimeKillChain {
            attribution: None,
            crimes: None,
            customers: None,
            marketing: None,
            monetization: None,
            rich_text_attribution: None,
            rich_text_crimes: None,
            rich_text_customers: None,
            rich_text_marketing: None,
            rich_text_monetization: None,
            rich_text_services_offered: None,
            rich_text_services_used: None,
            rich_text_technical_tradecraft: None,
            rich_text_victims: None,
            services_offered: None,
            services_used: None,
            technical_tradecraft: None,
            victims: None,
        }
    }
}
