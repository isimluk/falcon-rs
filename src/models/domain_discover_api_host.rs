/*
 * CrowdStrike API Specification
 *
 * Use this API specification as a reference for the API endpoints you can use to interact with your Falcon environment. These endpoints support authentication via OAuth2 and interact with detections and network containment. For detailed usage guides and more information about API endpoints that don't yet support OAuth2, see our [documentation inside the Falcon console](https://falcon.crowdstrike.com/support/documentation). To use the APIs described below, combine the base URL with the path shown for each API endpoint. For commercial cloud customers, your base URL is `https://api.crowdstrike.com`. Each API endpoint requires authorization via an OAuth2 token. Your first API request should retrieve an OAuth2 token using the `oauth2/token` endpoint, such as `https://api.crowdstrike.com/oauth2/token`. For subsequent requests, include the OAuth2 token in an HTTP authorization header. Tokens expire after 30 minutes, after which you should make a new token request to continue making API requests.
 *
 * The version of the OpenAPI document: rolling
 *
 * Generated by: https://openapi-generator.tech
 */

/// DomainDiscoverApiHost : Represents information about a managed, an unmanaged or an unsupported asset.

#[derive(Clone, Debug, PartialEq, Default, Serialize, Deserialize)]
pub struct DomainDiscoverApiHost {
    /// The version of the Falcon sensor that's installed on the asset.
    #[serde(rename = "agent_version", skip_serializing_if = "Option::is_none")]
    pub agent_version: Option<String>,
    /// The agent ID of the Falcon sensor installed on the asset.
    #[serde(rename = "aid", skip_serializing_if = "Option::is_none")]
    pub aid: Option<String>,
    /// The name of the asset's BIOS manufacturer.
    #[serde(rename = "bios_manufacturer", skip_serializing_if = "Option::is_none")]
    pub bios_manufacturer: Option<String>,
    /// The asset's BIOS version.
    #[serde(rename = "bios_version", skip_serializing_if = "Option::is_none")]
    pub bios_version: Option<String>,
    /// The asset's customer ID.
    #[serde(rename = "cid")]
    pub cid: String,
    /// The name of the city where the asset is located.
    #[serde(rename = "city", skip_serializing_if = "Option::is_none")]
    pub city: Option<String>,
    /// The level of confidence that the asset is a corporate asset (25 = low confidence, 50 = medium confidence, 75 = high confidence).
    #[serde(rename = "confidence", skip_serializing_if = "Option::is_none")]
    pub confidence: Option<i32>,
    /// The name of the country where the asset is located.
    #[serde(rename = "country", skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
    /// The last seen local IPv4 address of the asset.
    #[serde(rename = "current_local_ip", skip_serializing_if = "Option::is_none")]
    pub current_local_ip: Option<String>,
    /// The agent IDs of the Falcon sensors installed on the sources that discovered the asset.
    #[serde(rename = "discoverer_aids", skip_serializing_if = "Option::is_none")]
    pub discoverer_aids: Option<Vec<String>>,
    /// The number of sources that discovered the asset.
    #[serde(rename = "discoverer_count", skip_serializing_if = "Option::is_none")]
    pub discoverer_count: Option<i32>,
    /// The platform names of the sources that discovered the asset.
    #[serde(rename = "discoverer_platform_names", skip_serializing_if = "Option::is_none")]
    pub discoverer_platform_names: Option<Vec<String>>,
    /// The product type descriptions of the sources that discovered the asset.
    #[serde(rename = "discoverer_product_type_descs", skip_serializing_if = "Option::is_none")]
    pub discoverer_product_type_descs: Option<Vec<String>>,
    /// The tags of the sources that discovered the asset.
    #[serde(rename = "discoverer_tags", skip_serializing_if = "Option::is_none")]
    pub discoverer_tags: Option<Vec<String>>,
    /// The type of asset (managed, unmanaged, unsupported).
    #[serde(rename = "entity_type", skip_serializing_if = "Option::is_none")]
    pub entity_type: Option<String>,
    /// The external IPv4 address of the asset.
    #[serde(rename = "external_ip", skip_serializing_if = "Option::is_none")]
    pub external_ip: Option<String>,
    /// The agent ID of the Falcon sensor on the source that first discovered the asset.
    #[serde(rename = "first_discoverer_aid", skip_serializing_if = "Option::is_none")]
    pub first_discoverer_aid: Option<String>,
    /// The first time the asset was seen in your environment.
    #[serde(rename = "first_seen_timestamp", skip_serializing_if = "Option::is_none")]
    pub first_seen_timestamp: Option<String>,
    /// The host management groups the asset is part of.
    #[serde(rename = "groups", skip_serializing_if = "Option::is_none")]
    pub groups: Option<Vec<String>>,
    /// The asset's hostname .
    #[serde(rename = "hostname", skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    /// The unique ID of the asset.
    #[serde(rename = "id")]
    pub id: String,
    /// Whether the asset is exposed to the internet (Yes or Unknown)
    #[serde(rename = "internet_exposure", skip_serializing_if = "Option::is_none")]
    pub internet_exposure: Option<String>,
    /// For Linux and Mac hosts: the major version, minor version, and patch version of the kernel for the asset. For Windows hosts: the build number of the asset.
    #[serde(rename = "kernel_version", skip_serializing_if = "Option::is_none")]
    pub kernel_version: Option<String>,
    /// The agent ID of the Falcon sensor installed on the source that most recently discovered the asset.
    #[serde(rename = "last_discoverer_aid", skip_serializing_if = "Option::is_none")]
    pub last_discoverer_aid: Option<String>,
    /// The most recent time the asset was seen in your environment.
    #[serde(rename = "last_seen_timestamp", skip_serializing_if = "Option::is_none")]
    pub last_seen_timestamp: Option<String>,
    /// The number of historical local IPv4 addresses the asset has had.
    #[serde(rename = "local_ips_count", skip_serializing_if = "Option::is_none")]
    pub local_ips_count: Option<i32>,
    /// The domain name the asset is currently joined to (applies only to Windows hosts).
    #[serde(rename = "machine_domain", skip_serializing_if = "Option::is_none")]
    pub machine_domain: Option<String>,
    /// The asset's network interfaces.
    #[serde(rename = "network_interfaces", skip_serializing_if = "Option::is_none")]
    pub network_interfaces: Option<Vec<crate::models::DomainDiscoverApiNetworkInterface>>,
    /// The OS version of the asset.
    #[serde(rename = "os_version", skip_serializing_if = "Option::is_none")]
    pub os_version: Option<String>,
    /// The organizational unit of the asset (applies only to Windows hosts).
    #[serde(rename = "ou", skip_serializing_if = "Option::is_none")]
    pub ou: Option<String>,
    /// The platform name of the asset (Windows, Mac, Linux).
    #[serde(rename = "platform_name", skip_serializing_if = "Option::is_none")]
    pub platform_name: Option<String>,
    /// The product type of the asset represented as a number (1 = Workstation, 2 = Domain Controller, 3 = Server).
    #[serde(rename = "product_type", skip_serializing_if = "Option::is_none")]
    pub product_type: Option<String>,
    /// The product type of the asset (Workstation, Domain Controller, Server).
    #[serde(rename = "product_type_desc", skip_serializing_if = "Option::is_none")]
    pub product_type_desc: Option<String>,
    /// The site name of the domain the asset is joined to (applies only to Windows hosts).
    #[serde(rename = "site_name", skip_serializing_if = "Option::is_none")]
    pub site_name: Option<String>,
    /// The asset's system manufacturer.
    #[serde(rename = "system_manufacturer", skip_serializing_if = "Option::is_none")]
    pub system_manufacturer: Option<String>,
    /// The asset's system product name.
    #[serde(rename = "system_product_name", skip_serializing_if = "Option::is_none")]
    pub system_product_name: Option<String>,
    /// The asset's system serial number.
    #[serde(rename = "system_serial_number", skip_serializing_if = "Option::is_none")]
    pub system_serial_number: Option<String>,
    /// The sensor and cloud tags of the asset.
    #[serde(rename = "tags", skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<String>>,
}

impl DomainDiscoverApiHost {
    /// Represents information about a managed, an unmanaged or an unsupported asset.
    pub fn new(cid: String, id: String) -> DomainDiscoverApiHost {
        DomainDiscoverApiHost {
            agent_version: None,
            aid: None,
            bios_manufacturer: None,
            bios_version: None,
            cid,
            city: None,
            confidence: None,
            country: None,
            current_local_ip: None,
            discoverer_aids: None,
            discoverer_count: None,
            discoverer_platform_names: None,
            discoverer_product_type_descs: None,
            discoverer_tags: None,
            entity_type: None,
            external_ip: None,
            first_discoverer_aid: None,
            first_seen_timestamp: None,
            groups: None,
            hostname: None,
            id,
            internet_exposure: None,
            kernel_version: None,
            last_discoverer_aid: None,
            last_seen_timestamp: None,
            local_ips_count: None,
            machine_domain: None,
            network_interfaces: None,
            os_version: None,
            ou: None,
            platform_name: None,
            product_type: None,
            product_type_desc: None,
            site_name: None,
            system_manufacturer: None,
            system_product_name: None,
            system_serial_number: None,
            tags: None,
        }
    }
}
