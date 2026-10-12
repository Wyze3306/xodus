use std::collections::HashMap;

use base64::prelude::*;
use xal::cvlib::CorrelationVector;
//use xal::extensions::CorrelationVectorReqwestBuilder;

use crate::licensing::utils;
use crate::models::devicecredential::License;
use crate::models::licensing::{
    DeviceContext, LicenseContent, LicenseContentRequest, LicenseContentResponse,
    LicenseTokenRequest, LicenseTokenResponse, LicenseUserIdentity,
};

#[derive(Debug, thiserror::Error)]
pub enum LicenseContentError {
    #[error("request error: {0}")]
    Request(#[from] reqwest::Error),

    /// The account has no entitlement for the requested content (not owned, or
    /// not covered by the account's current subscription tier).
    #[error("not entitled to this content: {description}")]
    NotEntitled { description: String },

    /// The service answered with something this cannot read a license out of.
    /// The content key is in there and nowhere else, so there is nothing to
    /// fall back on -- but a downloader saying so is worth a great deal more
    /// than one panicking in a library.
    #[error("the license could not be read: {0}")]
    Unreadable(String),

    /// The service refused the request, e.g. 401 InvalidMsaTicketFormat.
    #[error("the licensing service refused the request (HTTP {status}): {reason}")]
    Refused { status: u16, reason: String },
}

/// The most specific reason a licensing error body gives, or the body itself.
///
/// The service answers `{"code": .., "message": .., "innererror": {"code": ..,
/// "message": ..}}`, and the inner error is the one that says what was wrong.
fn refusal_reason(body: &str) -> String {
    let Ok(json) = serde_json::from_str::<serde_json::Value>(body) else {
        return body.chars().take(300).collect();
    };
    let error = json
        .get("innererror")
        .filter(|inner| inner.get("code").is_some())
        .unwrap_or(&json);
    match (
        error.get("code").and_then(|v| v.as_str()),
        error.get("message").and_then(|v| v.as_str()),
    ) {
        (Some(code), Some(message)) => format!("{code}: {message}"),
        (Some(code), None) => code.to_string(),
        (None, Some(message)) => message.to_string(),
        (None, None) => body.chars().take(300).collect(),
    }
}

// we might need a bump in xal-rs concerning reqwest,
// that might block us from using the correlationvector extension
pub async fn get_license_content(
    client: &reqwest::Client,
    device_ms_token: String,
    user_ms_token: String,
    ticket_reference: String,
    content_id: String,
    market: String,
) -> Result<(LicenseContent, License), LicenseContentError> {
    let cv = CorrelationVector::new();
    let response = client
        .post("https://licensing.mp.microsoft.com/v7.0/licenses/content")
        .header("from", "XboxLicenseManager")
        .header("Authorization", device_ms_token)
        .header("user-agent", "XboxLm-PC/Microsoft.GamingServices_32.107.4002.0_x64__8wekyb3d8bbwe")
        .header("MS-CV", cv.to_string())
        .json(&LicenseContentRequest {
            content_id,
            market,
            client_challenge: "PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0idXRmLTgiID8+PENsaWVudENoYWxsZW5nZSB4bWxuczp4c2k9Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvWE1MU2NoZW1hLWluc3RhbmNlIiB4bWxuczp4c2Q9Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvWE1MU2NoZW1hIiB4bWxucz0iaHR0cDovL3NjaGVtYXMubWljcm9zb2Z0LmNvbS9vbmVzdG9yZS9zZWN1cml0eS9ta21zL0xpY1JlcS92MSIgVmVyc2lvbj0iMiI+PExpY2Vuc2VQcm90b2NvbFZlcnNpb24+NTwvTGljZW5zZVByb3RvY29sVmVyc2lvbj48U2lnbmluZ0tleVZlcnNpb24+MTwvU2lnbmluZ0tleVZlcnNpb24+PENsaWVudFZlcnNpb24+MjwvQ2xpZW50VmVyc2lvbj48L0NsaWVudENoYWxsZW5nZT4=".into(),
            concurrency_mode: "Rude".into(),
            license_version: 4,
            need_key: true,
            key_only: true,
            device_context: DeviceContext::default(),
            users: HashMap::from_iter(
                [(utils::generate_suid(),
                vec![LicenseUserIdentity {
                    identity_type: "Msa".to_string(),
                    identity_value: user_ms_token,
                    local_ticket_reference: ticket_reference,
                }])],
            ),
        })
        .send()
        .await?;

    // A refusal is a JSON error, not a license: reading it as one used to
    // surface as "error decoding response body", which named neither the
    // status nor the reason the service gave.
    let status = response.status();
    if !status.is_success() {
        let body = response.text().await.unwrap_or_default();
        return Err(LicenseContentError::Refused {
            status: status.as_u16(),
            reason: refusal_reason(&body),
        });
    }
    let content_res = response.json::<LicenseContentResponse>().await?;
    let content = match content_res {
        LicenseContentResponse::Success { license } => license,
        LicenseContentResponse::SatisfactionFailure {
            satisfaction_failure,
        } => {
            return Err(LicenseContentError::NotEntitled {
                description: satisfaction_failure.description,
            });
        }
    };
    let license = read_license(&content)?;
    Ok((content, license))
}

pub async fn get_license_token(
    client: &reqwest::Client,
    device_ms_token: String,
    user_ms_token: String,
    ticket_reference: String,
    parent_product_id: String,
    products: Vec<String>,
    custom_developer_string: String,
) -> Result<String, Box<dyn std::error::Error>> {
    let response = client
        .post("https://licensing.mp.microsoft.com/v8.0/licenseToken")
        .header("from", "XboxLicenseManager")
        .header("Authorization", device_ms_token)
        .header(
            "user-agent",
            "XboxLm-PC/Microsoft.GamingServices_32.107.4002.0_x64__8wekyb3d8bbwe",
        )
        .json(&LicenseTokenRequest {
            parent_product_id,
            enforce_sellable_by: true,
            related_product_ids: products,
            custom_developer_string,
            beneficiaries: vec![LicenseUserIdentity {
                identity_type: "Msa".to_string(),
                identity_value: user_ms_token,
                local_ticket_reference: ticket_reference,
            }],
        })
        .send()
        .await?;

    let token_resp: LicenseTokenResponse = response.json().await?;

    Ok(token_resp.license_token)
}

/// The license the response carries the content key in.
///
/// Base64, then UTF-8, then a license document: three ways for an answer to
/// be something other than what was expected, and all three used to be
/// unwrapped in the middle of a download.
fn read_license(content: &LicenseContent) -> Result<License, LicenseContentError> {
    let key = content
        .keys
        .first()
        .ok_or_else(|| LicenseContentError::Unreadable("the response carried none".into()))?;
    let decoded = BASE64_STANDARD
        .decode(&key.value)
        .map_err(|err| LicenseContentError::Unreadable(format!("not base64: {err}")))?;
    let xml = String::from_utf8(decoded)
        .map_err(|err| LicenseContentError::Unreadable(format!("not text: {err}")))?;
    quick_xml::de::from_str::<License>(&xml)
        .map_err(|err| LicenseContentError::Unreadable(err.to_string()))
}

#[cfg(test)]
mod tests {
    use crate::models::licensing::LicenseKeys;

    use super::*;

    fn response(keys: Vec<&str>) -> LicenseContent {
        LicenseContent {
            keys: keys
                .into_iter()
                .map(|value| LicenseKeys {
                    value: value.to_string(),
                })
                .collect(),
            leases: vec![],
        }
    }

    #[test]
    fn reads_the_license_out_of_the_first_key() {
        let xml = r#"<License>
                       <SPLicenseBlock>AAAA</SPLicenseBlock>
                       <LicenseInfo Type="Trial" LicenseUsage="Online"/>
                       <Binding Binding_Type="Content"/>
                     </License>"#;

        let license = read_license(&response(vec![&BASE64_STANDARD.encode(xml)]))
            .expect("failed to read the license");

        assert_eq!(license.splicense_block, "AAAA");
    }

    #[test]
    fn names_the_inner_reason_of_a_refusal() {
        let body = r#"{"code":"Unauthorized","innererror":{"faultcode":4003,"code":"InvalidMsaTicketFormat","message":"There was a problem parsing the request since the request had an invalid format for the MSA ticket."},"message":"The client is not authorized to perform the requested operation.","source":"LicensingFD"}"#;

        assert_eq!(
            refusal_reason(body),
            "InvalidMsaTicketFormat: There was a problem parsing the request since the request had an invalid format for the MSA ticket."
        );
    }

    #[test]
    fn falls_back_to_the_outer_error_and_to_the_raw_body() {
        assert_eq!(
            refusal_reason(r#"{"code":"Forbidden","message":"No."}"#),
            "Forbidden: No."
        );
        assert_eq!(refusal_reason("<html>busy</html>"), "<html>busy</html>");
    }

    #[test]
    fn reports_a_response_with_no_license() {
        let err = read_license(&response(vec![])).expect_err("expected no license");

        assert!(
            err.to_string().contains("could not be read"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn reports_a_key_that_is_not_a_license() {
        let err = read_license(&response(vec![&BASE64_STANDARD.encode("<Nope/>")]))
            .expect_err("expected an unreadable license");

        assert!(
            err.to_string().contains("could not be read"),
            "unexpected error: {err}"
        );
    }
}
