use crate::hardware;
use crate::licensing::splicense::SPLicense;
use crate::licensing::utils::{generate_string, parse_bcrypt_rsa_private};
use crate::models::devicecredential::{Authentication, ClientInfo, DeviceAddRequest, DeviceInfo};
use crate::models::secrets::Device;
use crate::models::soap::BodyContent;
use crate::tokens::manager::TokenManager;
use crate::tokens::store::TokenStoreError;

/// Provisions a device (if none is stored yet) or re-authenticates an existing one
/// (if its STS token is missing/expired), persisting the result through `tokens`.
pub async fn ensure_device_credentials(client: &reqwest::Client, tokens: &TokenManager) {
    match tokens.get_device_license() {
        Err(_) => provision_device(client, tokens).await,
        Ok(license) => match tokens.get_device_sts_token() {
            Ok(_) => {}
            Err(TokenStoreError::Expired(expires)) => {
                tracing::info!("this device's STS token expired at {expires}; signing it in again");
                // Every device token was issued to the same lapsed session.
                drop_device_tokens(tokens);
                reauthenticate_device(client, tokens, license).await
            }
            Err(_) => reauthenticate_device(client, tokens, license).await,
        },
    }
}

/// Signs this device in again, for a session login.live.com refused although
/// it had not expired by its stored lifetime.
///
/// Drops the device tokens and nothing else -- the device (`dev_license`) and
/// the account stay -- which is the same thing as deleting `device-tokens`
/// from the keyring by hand, then runs `ensure_device_credentials`. A caller
/// should retry a refused request once after this, not in a loop: a refusal
/// a fresh device session does not cure is not a device-session problem.
pub async fn reauthenticate_device_session(client: &reqwest::Client, tokens: &TokenManager) {
    drop_device_tokens(tokens);
    ensure_device_credentials(client, tokens).await;
}

fn drop_device_tokens(tokens: &TokenManager) {
    if let Err(err) = tokens.remove_device_tokens() {
        tracing::debug!("could not remove the device tokens: {err}");
    }
}

async fn provision_device(client: &reqwest::Client, tokens: &TokenManager) {
    let username = format!("02{}", generate_string(14));
    let password = generate_string(20);
    let provision = DeviceAddRequest {
        client_info: ClientInfo::default(),
        authentication: Authentication::new(username.clone(), password.clone()),
        device_info: Some(DeviceInfo {
            id: "DeviceInfo".to_string(),
            components: hardware::probe_provision_components(),
            tpm_info: None,
        }),
    };

    let dev = crate::api::live::login_device_credential(client, provision)
        .await
        .expect("Failed to get device creds");

    let device = Device {
        username: username.clone(),
        password: password.clone(),
        puid: dev.puid,
        hwid: dev.hw_device_id,
        device_id: dev.license.binding.device_id.unwrap_or_default(),
        splicense: dev.license.splicense_block,
    };

    tokens
        .save_device_license(&device)
        .expect("Failed to save device license");

    reauthenticate_device(client, tokens, device).await;
}

async fn reauthenticate_device(client: &reqwest::Client, tokens: &TokenManager, license: Device) {
    let sp_license =
        SPLicense::parse_base64(&license.splicense).expect("Failed to parse SPLicense");
    let clep_sign_state = sp_license.clep_sign_state.expect("Missing clep sign state");
    let key = clep_sign_state.get_rsa_key();
    let private_key = parse_bcrypt_rsa_private(&key).unwrap();
    let resp = crate::api::live::authenticate_device(client, license.username, private_key)
        .await
        .expect("Failed to auth device");

    if let BodyContent::RequestSecurityTokenResponse(resp) = resp.body.body {
        save_device_sts_token(tokens, resp);
    }
}

fn save_device_sts_token(
    tokens: &TokenManager,
    resp: Box<crate::models::soap::RequestSecurityTokenResponse>,
) {
    let key_name = resp
        .requested_security_token
        .encrypted_data
        .as_ref()
        .unwrap()
        .key_info
        .key_name
        .as_ref()
        .unwrap()
        .clone();
    let token = (*resp).into();
    tokens
        .save_device_token(key_name, token)
        .expect("Failed to save device token");
}
