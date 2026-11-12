use serde::{Deserialize, Serialize};

use crate::models::soap::{self, Timestamp};

#[derive(Debug, Serialize, Deserialize)]
pub struct Device {
    pub puid: String,
    pub hwid: String,
    pub device_id: String,
    pub splicense: String,
    pub username: String,
    pub password: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct LegacyToken {
    pub key_name: Option<String>,
    pub token: String,
    pub binary_secret: Option<String>,
    #[serde(default)]
    pub tpm_key: Option<String>,
    pub lifetime: Timestamp,
}

impl LegacyToken {
    /// Whether the token's `wsu:Expires` has passed at `now`.
    ///
    /// The keyring keeps a Passport STS token for as long as nothing replaces
    /// it, and login.live.com answers every request signed with an expired one
    /// with a SOAP Fault. A token is treated as expired a few minutes early so
    /// a request does not race its own expiry, or the server's clock.
    /// A lifetime that cannot be read is not called expired: the token is then
    /// used as before, and the server is the judge.
    pub fn is_expired_at(&self, now: chrono::DateTime<chrono::Utc>) -> bool {
        match chrono::DateTime::parse_from_rfc3339(&self.lifetime.expires) {
            Ok(expires) => now + chrono::TimeDelta::minutes(5) >= expires.to_utc(),
            Err(_) => false,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(untagged)]
pub enum Token {
    Legacy(LegacyToken),
    Compact(String),
}

impl From<soap::RequestSecurityTokenResponse> for Token {
    fn from(value: soap::RequestSecurityTokenResponse) -> Self {
        match value.token_type.as_str() {
            "urn:passport:legacy" => {
                let encrypted_data = value.requested_security_token.encrypted_data.unwrap();
                let key_name = encrypted_data.key_info.key_name.clone();
                let token = quick_xml::se::to_string(&encrypted_data).unwrap();
                let binary_secret = value
                    .requested_proof_token
                    .as_ref()
                    .map(|t| t.binary_secret.clone());
                let tpm_key = value
                    .requested_proof_token
                    .and_then(|t| t.encrypted_key.map(|k| k.cipher_data.cipher_value));
                Self::Legacy(LegacyToken {
                    key_name,
                    token,
                    binary_secret,
                    tpm_key,
                    lifetime: value.lifetime,
                })
            }
            "urn:passport:compact" => Self::Compact(
                value
                    .requested_security_token
                    .binary_security_token
                    .unwrap()
                    .value,
            ),
            "urn:passport:delegationcompact" => Self::Compact(delegation_ticket(
                value
                    .requested_security_token
                    .binary_security_token
                    .unwrap()
                    .value,
            )),
            _ => unreachable!(),
        }
    }
}

/// The MSA ticket a delegation-compact token is sent as.
///
/// The opaque tickets Live used to issue here are sent with a `d=` prefix.
/// Since 2026-10-12 the same token type carries a compact JWE instead, and
/// the licensing service rejects `d=<jwe>` with `InvalidMsaTicketFormat`
/// (HTTP 401) while it accepts the token on its own, so it goes out unprefixed.
fn delegation_ticket(value: String) -> String {
    if is_jose_compact(&value) {
        value
    } else {
        format!("d={value}")
    }
}

/// Whether a token is a compact JWS (3 segments) or JWE (5 segments).
///
/// Live sends a JWE here, with an empty encrypted-key segment (`alg: dir`).
/// The header segment is base64url JSON, so it always starts with `eyJ`.
fn is_jose_compact(value: &str) -> bool {
    let parts: Vec<&str> = value.split('.').collect();
    let base64url = |part: &&str| {
        part.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    };
    parts[0].starts_with("eyJ")
        && matches!(parts.len(), 3 | 5)
        && parts.iter().all(base64url)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn legacy_expiring(expires: &str) -> LegacyToken {
        LegacyToken {
            key_name: None,
            token: "token".to_string(),
            binary_secret: None,
            tpm_key: None,
            lifetime: Timestamp {
                id: None,
                created: "2026-09-04T00:00:00Z".to_string(),
                expires: expires.to_string(),
            },
        }
    }

    fn at(time: &str) -> chrono::DateTime<chrono::Utc> {
        chrono::DateTime::parse_from_rfc3339(time).unwrap().to_utc()
    }

    #[test]
    fn a_token_past_its_expiry_is_expired() {
        let token = legacy_expiring("2026-11-03T12:00:00Z");
        assert!(token.is_expired_at(at("2026-11-03T12:00:01Z")));
        assert!(token.is_expired_at(at("2026-12-01T00:00:00Z")));
    }

    #[test]
    fn a_token_about_to_expire_is_expired() {
        let token = legacy_expiring("2026-11-03T12:00:00Z");
        assert!(token.is_expired_at(at("2026-11-03T11:57:00Z")));
    }

    #[test]
    fn a_token_within_its_lifetime_is_not_expired() {
        let token = legacy_expiring("2026-11-03T12:00:00Z");
        assert!(!token.is_expired_at(at("2026-11-03T11:00:00Z")));
        // Fractional seconds and an explicit offset are read the same way.
        let token = legacy_expiring("2026-11-03T12:00:00.1234567+00:00");
        assert!(!token.is_expired_at(at("2026-11-03T11:00:00Z")));
    }

    #[test]
    fn a_lifetime_that_cannot_be_read_is_not_expired() {
        assert!(!legacy_expiring("").is_expired_at(at("2026-11-03T12:00:00Z")));
        assert!(!legacy_expiring("soon").is_expired_at(at("2026-11-03T12:00:00Z")));
    }

    #[test]
    fn prefixes_an_opaque_delegation_ticket() {
        assert_eq!(delegation_ticket("EwAoA+pvBAAU".to_string()), "d=EwAoA+pvBAAU");
    }

    #[test]
    fn sends_a_jwe_delegation_ticket_as_is() {
        // The shape Live issues since 2026-10-12: header..iv.ciphertext.tag
        let jwe = "eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0..aXY.Y2lwaGVy_dGV4dA.dGFn";
        assert_eq!(delegation_ticket(jwe.to_string()), jwe);
    }

    #[test]
    fn sends_a_jws_delegation_ticket_as_is() {
        let jws = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJl";
        assert_eq!(delegation_ticket(jws.to_string()), jws);
    }

    #[test]
    fn does_not_take_an_opaque_ticket_for_a_jose_token() {
        assert_eq!(delegation_ticket("eyJ.abc".to_string()), "d=eyJ.abc");
        assert_eq!(delegation_ticket("eyJa+b.c.d".to_string()), "d=eyJa+b.c.d");
        assert_eq!(delegation_ticket("EwA.b.c".to_string()), "d=EwA.b.c");
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TokenStore {
    #[serde(flatten)]
    pub tokens: std::collections::HashMap<String, Token>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct User {
    pub puid: String,
    pub username: String,
}
