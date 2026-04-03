//! Google API authentication via AWS Workload Identity Federation (WIF).
//!
//! Flow:
//! 1. Fetch AWS credentials from EC2 instance metadata (via vsock proxy)
//! 2. Generate a signed GetCallerIdentity request (AWS Sigv4)
//! 3. Exchange the AWS token for a Google access token via STS
//! 4. Use the Google access token to call Google APIs (Play Integrity)
//!
//! No API keys or service account keys needed. Authentication is based on
//! the EC2 instance's IAM role, federated to a Google service account.

use reqwest::Client;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tracing::info;

// -- WIF Configuration (hardcoded — these are identifiers, not secrets) --

const GCP_PROJECT_NUMBER: &str = "648480773688";
const WIF_POOL_ID: &str = "aws-nitro-pool";
const WIF_PROVIDER_ID: &str = "aws-nitro-provider";
const SERVICE_ACCOUNT_EMAIL: &str = "play-integrity-verifier@ruonid.iam.gserviceaccount.com";
const GOOGLE_STS_URL: &str = "https://sts.googleapis.com/v1/token";
const GOOGLE_IAM_URL: &str = "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts";

// -- AWS Instance Metadata --

#[derive(Deserialize)]
struct AwsCredentials {
    #[serde(rename = "AccessKeyId")]
    access_key_id: String,
    #[serde(rename = "SecretAccessKey")]
    secret_access_key: String,
    #[serde(rename = "Token")]
    session_token: String,
}

/// Fetch AWS credentials from the EC2 instance metadata service.
/// In Nitro, this goes through the vsock proxy to the parent.
async fn fetch_aws_credentials(client: &Client) -> Result<AwsCredentials, String> {
    // IMDSv2: get token first
    let token = client
        .put("http://169.254.169.254/latest/api/token")
        .header("X-aws-ec2-metadata-token-ttl-seconds", "300")
        .send()
        .await
        .map_err(|e| format!("metadata token request failed: {e}"))?
        .text()
        .await
        .map_err(|e| format!("metadata token read failed: {e}"))?;

    // Get IAM role name
    let role = client
        .get("http://169.254.169.254/latest/meta-data/iam/security-credentials/")
        .header("X-aws-ec2-metadata-token", &token)
        .send()
        .await
        .map_err(|e| format!("metadata role request failed: {e}"))?
        .text()
        .await
        .map_err(|e| format!("metadata role read failed: {e}"))?;

    let role = role.trim();

    // Get credentials
    let creds: AwsCredentials = client
        .get(format!(
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/{role}"
        ))
        .header("X-aws-ec2-metadata-token", &token)
        .send()
        .await
        .map_err(|e| format!("metadata creds request failed: {e}"))?
        .json()
        .await
        .map_err(|e| format!("metadata creds parse failed: {e}"))?;

    Ok(creds)
}

// -- AWS Sigv4 Signing --

/// Generate a signed AWS GetCallerIdentity request for use as a WIF subject token.
/// Returns the serialized token (JSON with URL, headers, and method).
fn generate_aws_subject_token(creds: &AwsCredentials) -> Result<String, String> {
    let region = "us-east-1"; // STS global endpoint uses us-east-1
    let service = "sts";
    let host = "sts.amazonaws.com";
    let method = "POST";
    let uri = "/";
    let body = "Action=GetCallerIdentity&Version=2011-06-15";

    let now = chrono_now();
    let date_stamp = &now[..8]; // YYYYMMDD
    let amz_date = &now; // YYYYMMDDTHHMMSSZ

    let body_hash = hex::encode(Sha256::digest(body.as_bytes()));

    let canonical_headers = format!(
        "host:{host}\nx-amz-date:{amz_date}\nx-amz-security-token:{}\n",
        creds.session_token
    );
    let signed_headers = "host;x-amz-date;x-amz-security-token";

    let canonical_request =
        format!("{method}\n{uri}\n\n{canonical_headers}\n{signed_headers}\n{body_hash}");

    let credential_scope = format!("{date_stamp}/{region}/{service}/aws4_request");
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{amz_date}\n{credential_scope}\n{}",
        hex::encode(Sha256::digest(canonical_request.as_bytes()))
    );

    // Signing key derivation
    let k_date = hmac_sha256(
        format!("AWS4{}", creds.secret_access_key).as_bytes(),
        date_stamp.as_bytes(),
    );
    let k_region = hmac_sha256(&k_date, region.as_bytes());
    let k_service = hmac_sha256(&k_region, service.as_bytes());
    let k_signing = hmac_sha256(&k_service, b"aws4_request");

    let signature = hex::encode(hmac_sha256(&k_signing, string_to_sign.as_bytes()));

    let authorization = format!(
        "AWS4-HMAC-SHA256 Credential={}/{credential_scope}, SignedHeaders={signed_headers}, Signature={signature}",
        creds.access_key_id
    );

    // Build the subject token as a JSON object (Google STS expects this format)
    let token = serde_json::json!({
        "url": format!("https://{host}{uri}"),
        "method": method,
        "headers": [
            {"key": "Authorization", "value": authorization},
            {"key": "host", "value": host},
            {"key": "x-amz-date", "value": amz_date},
            {"key": "x-amz-security-token", "value": creds.session_token},
            {"key": "x-goog-cloud-target-resource", "value": format!(
                "//iam.googleapis.com/projects/{GCP_PROJECT_NUMBER}/locations/global/workloadIdentityPools/{WIF_POOL_ID}/providers/{WIF_PROVIDER_ID}"
            )}
        ],
        "body": body
    });

    serde_json::to_string(&token).map_err(|e| format!("token serialize failed: {e}"))
}

// -- Google STS Token Exchange --

#[derive(Deserialize)]
struct StsTokenResponse {
    access_token: String,
    #[allow(dead_code)]
    expires_in: Option<u64>,
}

/// Exchange an AWS subject token for a Google STS access token.
async fn exchange_for_google_token(
    client: &Client,
    aws_subject_token: &str,
) -> Result<String, String> {
    let audience = format!(
        "//iam.googleapis.com/projects/{GCP_PROJECT_NUMBER}/locations/global/workloadIdentityPools/{WIF_POOL_ID}/providers/{WIF_PROVIDER_ID}"
    );

    let body = serde_json::json!({
        "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
        "audience": audience,
        "scope": "https://www.googleapis.com/auth/cloud-platform",
        "requested_token_type": "urn:ietf:params:oauth:token-type:access_token",
        "subject_token_type": "urn:ietf:params:aws:token-type:aws4_request",
        "subject_token": aws_subject_token,
    });

    let resp = client
        .post(GOOGLE_STS_URL)
        .json(&body)
        .send()
        .await
        .map_err(|e| format!("Google STS request failed: {e}"))?;

    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(format!("Google STS returned {status}: {body}"));
    }

    let sts_resp: StsTokenResponse = resp
        .json()
        .await
        .map_err(|e| format!("Google STS response parse failed: {e}"))?;

    // Exchange the STS token for a service account access token
    let sa_url = format!(
        "{GOOGLE_IAM_URL}/{}:generateAccessToken",
        SERVICE_ACCOUNT_EMAIL
    );

    let sa_body = serde_json::json!({
        "scope": ["https://www.googleapis.com/auth/playintegrity"],
    });

    let sa_resp = client
        .post(&sa_url)
        .bearer_auth(&sts_resp.access_token)
        .json(&sa_body)
        .send()
        .await
        .map_err(|e| format!("Google IAM generateAccessToken failed: {e}"))?;

    let sa_status = sa_resp.status();
    if !sa_status.is_success() {
        let body = sa_resp.text().await.unwrap_or_default();
        return Err(format!(
            "Google IAM generateAccessToken returned {sa_status}: {body}"
        ));
    }

    #[derive(Deserialize)]
    struct GenerateAccessTokenResponse {
        #[serde(rename = "accessToken")]
        access_token: String,
    }

    let sa_token: GenerateAccessTokenResponse = sa_resp
        .json()
        .await
        .map_err(|e| format!("Google IAM response parse failed: {e}"))?;

    Ok(sa_token.access_token)
}

/// Get a Google access token for calling the Play Integrity API.
///
/// Uses AWS Workload Identity Federation: fetches AWS credentials from
/// instance metadata, signs a GetCallerIdentity request, exchanges it
/// for a Google access token via STS, then impersonates the service account.
pub async fn get_google_access_token(client: &Client) -> Result<String, String> {
    info!("fetching Google access token via WIF");

    let aws_creds = fetch_aws_credentials(client).await?;
    let subject_token = generate_aws_subject_token(&aws_creds)?;
    let google_token = exchange_for_google_token(client, &subject_token).await?;

    info!("Google access token obtained");
    Ok(google_token)
}

// -- Helpers --

fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    use hmac::{Hmac, Mac};
    type HmacSha256 = Hmac<Sha256>;
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC key length");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

/// Generate an ISO 8601 timestamp for AWS Sigv4 signing.
fn chrono_now() -> String {
    // Manual UTC timestamp without chrono dependency
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // Convert epoch seconds to YYYYMMDDTHHMMSSZ
    let days = secs / 86400;
    let time_of_day = secs % 86400;
    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;
    let seconds = time_of_day % 60;

    // Days since 1970-01-01
    let mut y = 1970i64;
    let mut remaining_days = days as i64;

    loop {
        let days_in_year = if is_leap(y) { 366 } else { 365 };
        if remaining_days < days_in_year {
            break;
        }
        remaining_days -= days_in_year;
        y += 1;
    }

    let month_days = if is_leap(y) {
        [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };

    let mut m = 0usize;
    for &md in &month_days {
        if remaining_days < md {
            break;
        }
        remaining_days -= md;
        m += 1;
    }

    format!(
        "{:04}{:02}{:02}T{:02}{:02}{:02}Z",
        y,
        m + 1,
        remaining_days + 1,
        hours,
        minutes,
        seconds
    )
}

fn is_leap(y: i64) -> bool {
    (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
}
