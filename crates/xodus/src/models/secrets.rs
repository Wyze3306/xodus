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
