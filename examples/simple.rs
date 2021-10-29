use rusty_falcon::apis::{Error};
use rusty_falcon::apis::configuration::{Configuration};
use rusty_falcon::apis::oauth2_api::{oauth2_access_token, Oauth2AccessTokenError};
use rusty_falcon::apis::incidents_api::{crowd_score};

use std::env;

#[tokio::main]
async fn main() {
    let falcon_client_id = env::var("FALCON_CLIENT_ID")
        .expect("Missing FALCON_CLIENT_ID environment variable. Please provide your OAuth2 API Client ID for authentication with CrowdStrike Falcon platform. Establishing and retrieving OAuth2 API credentials can be performed at https://falcon.crowdstrike.com/support/api-clients-and-keys.");
    let falcon_client_secret = env::var("FALCON_CLIENT_SECRET")
        .expect("Missing FALCON_CLIENT_SECRET environment variable. Please provide your OAuth2 API Client Secret for authentication with CrowdStrike Falcon platform. Establishing and retrieving OAuth2 API credentials can be performed at https://falcon.crowdstrike.com/support/api-clients-and-keys.");

    let configuration = new_client(FalconCloud::Us1, &falcon_client_id, &falcon_client_secret)
        .await
        .expect("Could not authenticate with CrowdStrike API");

    let crowd_score_response = crowd_score(&configuration, None, None, None, None)
        .await
        .expect("Could not fetch CrowdScore");

    if ! crowd_score_response.errors.is_empty() {
        eprintln!("Errors occured while calculating CrowdScore: {:?}", crowd_score_response.errors);
    }

    if crowd_score_response.resources.is_empty() {
        eprintln!("No CrowdScore returned")
    }

    let score = crowd_score_response.resources.last().unwrap();
    println!("As of {} your CrowdScore is {}.", score.timestamp, score.score)
}

enum FalconCloud {
    Us1,
    Us2,
    Eu1,
    UsGov1,
}

impl FalconCloud {
    fn host(self) -> &'static str {
        match self {
            FalconCloud::Us1 => "api.crowdstrike.com",
            FalconCloud::Us2 => "api.us-2.crowdstrike.com",
            FalconCloud::Eu1 => "api.eu-1.crowdstrike.com",
            FalconCloud::UsGov1 => "api.laggar.gcw.crowdstrike.com"
        }
    }
    fn base_path(self) -> String {
        let mut path = String::from("https://");
        path.push_str(self.host());
        return path;
    }
}

async fn new_client(cloud: FalconCloud, falcon_client_id: &str, falcon_client_secret: &str) -> Result<Configuration, Error<Oauth2AccessTokenError>> {
    let mut configuration = Configuration {
        base_path: cloud.base_path(),
        ..Default::default()
    };

    let response = oauth2_access_token(&configuration, &falcon_client_id, &falcon_client_secret, None).await?;

    configuration.oauth_access_token = Some(response.access_token);
    return Ok(configuration);
}
