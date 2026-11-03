use xodus::api::live::RSTError;
use xodus::licensing::splicense::{DeviceKey, SPLicense};
use xodus::models::live::ExchangeUserTokenOutcome;
use xodus::models::secrets::{LegacyToken, Token};
use xodus::models::soap;
use xodus::tokens::TokenManager;
use xodus::tokens::store::TokenStoreError;

/// What a license request says when the keyring lacks one of the entries it
/// needs, instead of unwrapping it.
///
/// A keyring can hold device tokens and some user tokens without everything a
/// license request reads -- the account's `user-DA` entry, or its Passport
/// STS token -- and each lookup used to `unwrap()`, so the caller got
/// `called Result::unwrap() on an Err value: NotFound` in the middle of a
/// download, with nothing to say that signing in again is the way out.
/// "not logged in" is the phrase for that.
fn missing(what: &str, err: TokenStoreError) -> String {
    match err {
        TokenStoreError::Expired(_) => {
            format!("not logged in: {what} in the keyring has expired ({err}); sign in again")
        }
        err => format!("not logged in: {what} is missing from the keyring ({err}); sign in again"),
    }
}

fn device_sts_token(tokens: &TokenManager) -> std::result::Result<LegacyToken, String> {
    let dev_token = tokens
        .get_device_sts_token()
        .map_err(|err| missing("this device's Microsoft session", err))?;
    let Token::Legacy(dev_token) = dev_token else {
        return Err("Invalid STS token".to_string());
    };
    Ok(dev_token)
}

async fn exchange_device_token(
    client: &reqwest::Client,
    dev_token: LegacyToken,
) -> std::result::Result<soap::RequestSecurityTokenResponse, RSTError> {
    xodus::api::live::exchange_device_token(
        client,
        dev_token,
        "{d6d5a677-0872-4ab0-9442-bb792fce85c5}".to_string(),
        "www.microsoft.com".to_owned(),
        Some(soap::PolicyReference::mbi_ssl()),
    )
    .await
}

pub async fn get_license(
    client: &reqwest::Client,
    tokens: &TokenManager,
    content_id: String,
    market: String,
) -> std::result::Result<(DeviceKey, SPLicense), String> {
    let dev_token = device_sts_token(tokens)?;
    let user = tokens
        .get_user()
        .map_err(|err| missing("the signed-in Microsoft account", err))?;
    let user_token = tokens
        .get_user_sts_token()
        .map_err(|err| missing("the Microsoft account's session token", err))?;
    let Token::Legacy(legacy) = user_token else {
        return Err("Unspported user token".to_string());
    };

    // A device session login.live.com refuses is one a fresh sign-in of the
    // same device cures, which is what deleting `device-tokens` by hand did
    // (issue #367). Once: a second refusal is reported, not retried.
    let (dev_token, ms_device_token) = match exchange_device_token(client, dev_token.clone()).await
    {
        Ok(token) => (dev_token, token),
        Err(RSTError::Fault(status)) => {
            tracing::warn!(
                "login.live.com refused this device's session (reqstatus: {}); signing the device in again",
                status.as_deref().unwrap_or("none")
            );
            xodus::tokens::device::reauthenticate_device_session(client, tokens).await;
            let dev_token = device_sts_token(tokens)?;
            let token = exchange_device_token(client, dev_token.clone())
                .await
                .map_err(|err| {
                    format!("this device's Microsoft session was refused again after signing it in afresh: {err}")
                })?;
            (dev_token, token)
        }
        Err(err) => {
            return Err(format!(
                "could not exchange this device's Microsoft session: {err}"
            ));
        }
    };

    let user_token = xodus::api::live::exchange_user_token(
        client,
        legacy,
        user.username,
        dev_token,
        None,
        Some("Silent".to_string()),
        "{d6d5a677-0872-4ab0-9442-bb792fce85c5}".to_string(),
        &[(
            "www.microsoft.com".to_owned(),
            Some(soap::PolicyReference::mbi_ssl()),
        )],
    )
    .await
    .expect("Failed to get ms user token");

    let ms_device_token: Token = ms_device_token.into();
    let Token::Compact(ms_device_token) = ms_device_token else {
        return Err("Unsupported token".to_string());
    };

    let user_token: Token = match user_token {
        ExchangeUserTokenOutcome::Fault(_) => {
            return Err("Failed to get exchange MS token".to_string());
        }
        ExchangeUserTokenOutcome::Issued(
            soap::BodyContent::RequestSecurityTokenResponseCollection(mut collection),
        ) => {
            let token = collection.security_tokens.remove(0);
            token.into()
        }
        ExchangeUserTokenOutcome::Issued(soap::BodyContent::RequestSecurityTokenResponse(
            token,
        )) => (*token).into(),
        _ => unreachable!("Only responses are handled"),
    };
    let Token::Compact(user_token) = user_token else {
        return Err("Unsupported token".to_string());
    };

    let (_content, game_license) = xodus::licensing::content::get_license_content(
        client,
        ms_device_token,
        user_token,
        user.puid,
        content_id,
        market,
    )
    .await
    .map_err(|err| err.to_string())?;

    let game_splicense = SPLicense::parse_base64(&game_license.splicense_block)
        .expect("could not parse base64 game SPLicense");

    let dev_license = tokens
        .get_device_license()
        .map_err(|err| missing("this device's Microsoft license", err))?;
    let device_license = SPLicense::parse_base64(&dev_license.splicense)
        .expect("could not parse base64 device SPLicense");
    let key = device_license
        .encrypted_device_key
        .unwrap()
        .derive_device_key();
    Ok((key, game_splicense))
}

#[cfg(test)]
mod tests {
    use xodus::models::secrets::{LegacyToken, User};
    use xodus::tokens::PASSPORT_STS;

    use super::*;

    fn legacy() -> Token {
        Token::Legacy(LegacyToken {
            key_name: None,
            token: "token".to_string(),
            binary_secret: None,
            tpm_key: None,
            lifetime: soap::Timestamp {
                id: None,
                created: "2026-09-29T00:00:00Z".to_string(),
                // Expired tokens are not handed out, and these tests are
                // about entries that are missing.
                expires: "2099-09-30T00:00:00Z".to_string(),
            },
        })
    }

    async fn license_error(tokens: &TokenManager) -> String {
        let license = get_license(
            &reqwest::Client::new(),
            tokens,
            "7792d9ce-355a-493c-afbd-768f4a77c3b0".to_string(),
            "neutral".to_string(),
        )
        .await;
        match license {
            Ok(_) => panic!("a keyring missing an entry cannot license anything"),
            Err(err) => err,
        }
    }

    #[tokio::test]
    async fn a_device_without_a_session_asks_for_a_sign_in() {
        let err = license_error(&TokenManager::with_memory()).await;

        assert!(err.starts_with("not logged in:"), "unexpected error: {err}");
        assert!(err.contains("device's Microsoft session"), "{err}");
    }

    #[tokio::test]
    async fn a_keyring_without_the_account_asks_for_a_sign_in() {
        let tokens = TokenManager::with_memory();
        tokens
            .save_device_token(PASSPORT_STS.to_string(), legacy())
            .unwrap();

        let err = license_error(&tokens).await;

        assert!(err.starts_with("not logged in:"), "unexpected error: {err}");
        assert!(err.contains("signed-in Microsoft account"), "{err}");
    }

    #[tokio::test]
    async fn an_account_without_its_session_token_asks_for_a_sign_in() {
        let tokens = TokenManager::with_memory();
        tokens
            .save_device_token(PASSPORT_STS.to_string(), legacy())
            .unwrap();
        tokens
            .save_user(&User {
                puid: "1".to_string(),
                username: "player@example.com".to_string(),
            })
            .unwrap();
        // A user token for another service is not the Passport one.
        tokens
            .save_user_token("http://auth.xboxlive.com".to_string(), legacy())
            .unwrap();

        let err = license_error(&tokens).await;

        assert!(err.starts_with("not logged in:"), "unexpected error: {err}");
        assert!(err.contains("session token"), "{err}");
    }

    #[tokio::test]
    async fn an_expired_account_session_asks_for_a_sign_in() {
        let tokens = TokenManager::with_memory();
        tokens
            .save_device_token(PASSPORT_STS.to_string(), legacy())
            .unwrap();
        tokens
            .save_user(&User {
                puid: "1".to_string(),
                username: "player@example.com".to_string(),
            })
            .unwrap();
        let Token::Legacy(mut expired) = legacy() else {
            unreachable!()
        };
        expired.lifetime.expires = "2026-09-30T00:00:00Z".to_string();
        tokens
            .save_user_token(PASSPORT_STS.to_string(), Token::Legacy(expired))
            .unwrap();

        let err = license_error(&tokens).await;

        assert!(err.starts_with("not logged in:"), "unexpected error: {err}");
        assert!(err.contains("has expired"), "{err}");
    }
}
