use base64::prelude::*;
use zerocopy::transmute;

use crate::licensing::splicense::ClepHmacState;
use crate::models::devicecredential::{DeviceAddRequest, DeviceAddResponse};
use crate::models::live::ExchangeUserTokenOutcome;
use crate::models::secrets::{LegacyToken, Token};
use crate::models::soap;

mod rst;
mod utils;

pub use rst::RSTError;

pub const XML_HEADER: &str = r#"<?xml version="1.0" encoding="UTF-8"?>"#;

pub async fn login_device_credential(
    client: &reqwest::Client,
    data: DeviceAddRequest,
) -> reqwest::Result<DeviceAddResponse> {
    let data = quick_xml::se::to_string(&data).unwrap();

    let response = client
        .post("https://login.live.com/ppsecure/deviceaddcredential.srf")
        .header("User-Agent", "MSAWindows/55 (OS 10.0.26100.0.0 ge_release; IDK 10.0.26100.5074 ge_release; Cfg 16.000.29325.00; Test 0)")
        .header("Content-Type", "application/soap+xml")
        .header("Host", "login.live.com")
        .body(data)
        .send()
        .await?;
    let text = response.text().await?;
    let resp: DeviceAddResponse = quick_xml::de::from_str(&text).expect("Failed to de xml");
    Ok(resp)
}

pub async fn authenticate_device(
    client: &reqwest::Client,
    username: String,
    private_key: rsa::RsaPrivateKey,
) -> Result<soap::Envelope, rst::RSTError> {
    let request = rst::RSTRequestBuilder::new()
        .username(soap::UsernameToken::devicetoken(username))
        .signature(rst::RSTSignature::Rsa(Box::new(private_key)))
        .scope_policy("http://Passport.NET/tb", None)
        .build()?;

    request.request(client).await
}

pub async fn exchange_device_token(
    client: &reqwest::Client,
    token: LegacyToken,
    hosting_app: String,
    scope: String,
    policy: Option<soap::PolicyReference>,
) -> Result<soap::RequestSecurityTokenResponse, rst::RSTError> {
    let secret = BASE64_STANDARD.decode(token.binary_secret.as_ref().unwrap())?;
    let secret: [u8; 4096] = secret.try_into().unwrap();
    let secret: ClepHmacState = transmute!(secret);
    let hmac_secret = secret.get_hmac_state();

    let request = rst::RSTRequestBuilder::new()
        .sso_flags("SsoRestr")
        .hosting_app(&hosting_app)
        .device_token(token)
        .signature(rst::RSTSignature::Hmac {
            clep_secret: &*hmac_secret,
            tpm_secret: &[],
        })
        .scope_policy(&scope, policy)
        .build()?;

    let envelope = request.request(client).await?;

    single_security_token(envelope)
}

/// The one token a device token exchange asks for, or why there is none.
///
/// A Fault is what login.live.com sends for a device token it no longer
/// accepts, and it used to reach `unimplemented!` here -- a panic in the
/// middle of a license request, for something signing the device in again
/// fixes.
fn single_security_token(
    envelope: soap::Envelope,
) -> Result<soap::RequestSecurityTokenResponse, rst::RSTError> {
    match envelope.body.body {
        soap::BodyContent::RequestSecurityTokenResponse(res) => Ok(*res),
        soap::BodyContent::RequestSecurityTokenResponseCollection(mut collection) => {
            if collection.security_tokens.is_empty() {
                return Err(rst::RSTError::UnexpectedResponse("empty token collection"));
            }
            Ok(collection.security_tokens.remove(0))
        }
        soap::BodyContent::Fault(_) => Err(rst::RSTError::Fault(
            envelope.header.pp.and_then(|pp| pp.req_status),
        )),
        soap::BodyContent::EncryptedData(_) => {
            Err(rst::RSTError::UnexpectedResponse("encrypted body"))
        }
        soap::BodyContent::RequestSecurityToken(_)
        | soap::BodyContent::RequestMultipleSecurityTokens(_) => {
            Err(rst::RSTError::UnexpectedResponse("token request"))
        }
    }
}

// Each parameter maps directly to a distinct SOAP request field; grouping them
// into a params struct would just move the sprawl rather than reduce it.
#[allow(clippy::too_many_arguments)]
pub async fn exchange_user_token(
    client: &reqwest::Client,
    user_token: LegacyToken,
    username: String,
    device_token: LegacyToken,
    inline_token: Option<String>,
    inline_ux: Option<String>,
    hosting_app: String,
    scope_policies: &[(String, Option<soap::PolicyReference>)],
) -> Result<ExchangeUserTokenOutcome, rst::RSTError> {
    let secret = BASE64_STANDARD.decode(device_token.binary_secret.as_ref().unwrap())?;
    let secret: [u8; 4096] = secret.try_into().unwrap();
    let secret: ClepHmacState = transmute!(secret);
    let hmac_secret = secret.get_hmac_state();

    let mut builder = rst::RSTRequestBuilder::new()
        .username(soap::UsernameToken::user_hint(username))
        .device_token(device_token)
        .user_token(Token::Legacy(user_token))
        .hosting_app(&hosting_app)
        .sso_flags("SsoRestr")
        .license_signature_key_version(None)
        .signature(rst::RSTSignature::Hmac {
            clep_secret: &*hmac_secret,
            tpm_secret: &[],
        });

    if let Some(ux) = inline_ux.as_deref() {
        builder = builder.inline_ux(ux);
    }
    if let Some(ft) = inline_token.as_deref() {
        builder = builder.inline_ft(ft);
    }
    for (scope, policy) in scope_policies {
        builder = builder.scope_policy(scope, policy.clone());
    }

    let request = builder.build()?;
    let envelope = request.request(client).await?;

    Ok(match envelope.body.body {
        soap::BodyContent::Fault(_) => ExchangeUserTokenOutcome::Fault(envelope.header.pp),
        body => ExchangeUserTokenOutcome::Issued(body),
    })
}

#[cfg(test)]
mod faults {
    use super::{rst::RSTError, single_security_token};
    use crate::models::soap;

    fn envelope(body: soap::BodyContent, pp: Option<soap::PP>) -> soap::Envelope {
        let mut header = soap::Header::new();
        header.pp = pp;
        soap::Envelope::new(header, soap::Body { body })
    }

    #[test]
    fn a_fault_is_an_error_not_a_panic() {
        // Any status: it is only carried into the message.
        let pp = soap::PP {
            xmlns_psf: None,
            server_version: None,
            req_status: Some("0x80048821".to_string()),
            inline_auth_url: None,
            inline_end_auth_url: None,
            auth_state_internal: None,
            user_session_key: None,
        };
        let err =
            single_security_token(envelope(soap::BodyContent::Fault(soap::Fault {}), Some(pp)))
                .unwrap_err();

        assert!(
            matches!(&err, RSTError::Fault(Some(status)) if status == "0x80048821"),
            "{err:?}"
        );
        assert!(err.to_string().contains("SOAP Fault"), "{err}");
    }

    #[test]
    fn a_fault_without_a_status_is_still_a_fault() {
        let err = single_security_token(envelope(soap::BodyContent::Fault(soap::Fault {}), None))
            .unwrap_err();

        assert!(matches!(err, RSTError::Fault(None)), "{err:?}");
    }
}

#[cfg(test)]
mod test {
    use crate::api::live::exchange_device_token;
    use crate::models::secrets::Token;
    use crate::models::soap;
    use crate::tokens::TokenManager;
    use crate::tokens::device::ensure_device_credentials;

    #[tokio::test]
    async fn test_get_xbox_live_dev_token() {
        let client = reqwest::Client::new();

        let mgr = TokenManager::with_memory();
        ensure_device_credentials(&client, &mgr).await;

        let token: Token = mgr.get_device_sts_token().unwrap();
        let Token::Legacy(token) = token else {
            todo!("no a LegacyToken");
        };
        let resp = exchange_device_token(
            &client,
            token,
            "{28C08266-F973-4AE6-FFE4-409B249F138F}".to_string(),
            "scope=service::user.auth.xboxlive.com::MBI_SSL&api-version=2.0".to_owned(),
            Some(soap::PolicyReference::token_broker()),
        )
        .await
        .unwrap();

        let ms_device_token: Token = resp.into();
        let Token::Compact(ms_device_token) = ms_device_token else {
            todo!("Unsupported token");
        };

        println!("{}", ms_device_token);
    }
}
