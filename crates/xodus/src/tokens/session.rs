//! The signed-in account's Passport session, and renewing it before it runs
//! out.
//!
//! Sign-in stores it once, under `user-tokens`, and every license request
//! exchanges it for the ticket the licensing service reads. Live issues it for
//! ninety days and nothing renewed it, so ninety days after a sign-in the
//! keyring held a session Live no longer took, and the only way on was to sign
//! in again -- through the same sign-in page that some systems cannot get past.
//! While Live still takes the session, it issues a new one for it without a
//! sign-in.

use chrono::{DateTime, TimeDelta, Utc};

use crate::api::live::RSTError;
use crate::models::live::ExchangeUserTokenOutcome;
use crate::models::secrets::{LegacyToken, Token};
use crate::models::soap::BodyContent;
use crate::tokens::PASSPORT_STS;
use crate::tokens::manager::TokenManager;
use crate::tokens::store::TokenStoreError;

/// How long before the expiry it states the account's session is renewed.
///
/// A license request is made at every start of the game, so a week renews the
/// session of anyone who plays in its last week, once.
pub const RENEW_BEFORE: TimeDelta = TimeDelta::days(7);

/// The scope Live answers with the account's own session.
const SESSION_SCOPE: &str = "http://Passport.NET/tb";

/// Why the account's session could not be renewed.
#[derive(thiserror::Error, Debug)]
pub enum SessionError {
    #[error("the keyring could not store it ({0})")]
    Store(#[from] TokenStoreError),
    #[error("{0}")]
    Request(#[from] RSTError),
    #[error("login.live.com answered without a new session")]
    NotIssued,
}

/// Whether a session ends within [`RENEW_BEFORE`] of `now`, or already has. A
/// session whose expiry cannot be read is left alone: the exchange that uses it
/// reports a refusal itself.
pub fn is_ending(session: &LegacyToken, now: DateTime<Utc>) -> bool {
    match DateTime::parse_from_rfc3339(&session.lifetime.expires) {
        Ok(expires) => expires.with_timezone(&Utc) - now < RENEW_BEFORE,
        Err(_) => false,
    }
}

/// Asks Live for a new session in place of `session`, the account's, signed
/// with `device`, this device's; stores it and returns it.
///
/// Live answers a request for `http://Passport.NET/tb` with the session
/// itself, keyed `http://Passport.NET/STS` the way sign-in stores it, for
/// another ninety days. Anything else is not a session and is not stored.
pub async fn renew_account_session(
    client: &reqwest::Client,
    tokens: &TokenManager,
    session: LegacyToken,
    username: String,
    device: LegacyToken,
    hosting_app: &str,
) -> Result<LegacyToken, SessionError> {
    let outcome = crate::api::live::exchange_user_token(
        client,
        session,
        username,
        device,
        None,
        Some("Silent".to_string()),
        hosting_app.to_string(),
        &[(SESSION_SCOPE.to_string(), None)],
    )
    .await?;
    let issued = match outcome {
        ExchangeUserTokenOutcome::Issued(BodyContent::RequestSecurityTokenResponse(token)) => {
            *token
        }
        ExchangeUserTokenOutcome::Issued(BodyContent::RequestSecurityTokenResponseCollection(
            mut collection,
        )) if !collection.security_tokens.is_empty() => collection.security_tokens.remove(0),
        _ => return Err(SessionError::NotIssued),
    };
    let Token::Legacy(renewed) = issued.into() else {
        return Err(SessionError::NotIssued);
    };
    if renewed.key_name.as_deref() != Some(PASSPORT_STS) {
        return Err(SessionError::NotIssued);
    }
    tokens.save_user_token(PASSPORT_STS.to_string(), Token::Legacy(renewed.clone()))?;
    Ok(renewed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::soap::Timestamp;

    fn session(expires: &str) -> LegacyToken {
        LegacyToken {
            key_name: None,
            token: "token".to_string(),
            binary_secret: None,
            tpm_key: None,
            lifetime: Timestamp {
                id: None,
                created: "2026-08-14T16:09:06Z".to_string(),
                expires: expires.to_string(),
            },
        }
    }

    fn at(time: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(time)
            .unwrap()
            .with_timezone(&Utc)
    }

    #[test]
    fn a_session_in_its_last_week_is_renewed() {
        let token = session("2026-11-12T16:09:06Z");

        assert!(is_ending(&token, at("2026-11-06T00:00:00Z")));
        assert!(is_ending(&token, at("2026-11-12T15:00:00Z")));
    }

    #[test]
    fn a_session_that_ran_out_is_ending() {
        let token = session("2026-11-12T16:09:06Z");

        assert!(is_ending(&token, at("2026-12-01T00:00:00Z")));
    }

    #[test]
    fn a_session_with_weeks_left_is_kept() {
        let token = session("2026-11-12T16:09:06Z");

        assert!(!is_ending(&token, at("2026-10-13T16:01:39Z")));
    }

    #[test]
    fn an_unreadable_expiry_is_left_to_the_exchange() {
        let token = session("not a date");

        assert!(!is_ending(&token, at("2026-10-13T16:01:39Z")));
    }
}
