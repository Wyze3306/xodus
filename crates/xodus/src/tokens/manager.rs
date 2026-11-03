use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use crate::models::secrets::{Device, Token, TokenStore, User};
use crate::models::xbox::XstsResponse;
use crate::tokens::backend::{KeychainBackend, MemoryBackend};
use crate::tokens::store::{ExpiringTokenBackend, TokenBackend, TokenStoreError};

mod keys {
    pub const DEV_LICENSE: &str = "dev_license";
    pub const DEVICE_TOKENS: &str = "device-tokens";
    pub const USER_TOKENS: &str = "user-tokens";
    pub const USER_INFO: &str = "user-DA";
}

pub const PASSPORT_STS: &str = "http://Passport.NET/STS";

/// Semantic facade over the two storage tiers: a persistent, keychain-backed tier
/// for STS/device/user credentials, and an ephemeral tier for short-lived
/// per-relying-party XSTS tokens. Centralizes the read-merge-write pattern that was
/// previously duplicated across `xodus-cli` and `xodus-service`.
#[derive(Clone)]
pub struct TokenManager {
    persistent: Arc<dyn TokenBackend>,
    ephemeral: Arc<dyn ExpiringTokenBackend>,
}

impl TokenManager {
    pub fn new(
        persistent: Arc<dyn TokenBackend>,
        ephemeral: Arc<dyn ExpiringTokenBackend>,
    ) -> Self {
        Self {
            persistent,
            ephemeral,
        }
    }

    /// Keychain for persistent storage, in-memory for ephemeral - the default
    /// wiring for both `xodus-cli` and `xodus-service` today.
    pub fn with_keychain_and_memory() -> Self {
        Self::new(
            Arc::new(KeychainBackend),
            Arc::new(MemoryBackend::default()),
        )
    }

    /// Keychain for persistent storage, in-memory for ephemeral - the default
    /// wiring for both `xodus-cli` and `xodus-service` today.
    pub fn with_memory() -> Self {
        Self::new(
            Arc::new(MemoryBackend::default()),
            Arc::new(MemoryBackend::default()),
        )
    }

    pub fn remove_persistent(&self) -> Result<(), TokenStoreError> {
        self.persistent.remove(keys::DEVICE_TOKENS)?;
        self.persistent.remove(keys::USER_TOKENS)?;
        self.persistent.remove(keys::USER_INFO)
    }

    // ---- Device identity / license -----------------------------------------

    pub fn get_device_license(&self) -> Result<Device, TokenStoreError> {
        let bytes = self
            .persistent
            .get(keys::DEV_LICENSE)?
            .ok_or(TokenStoreError::NotFound)?;
        Ok(serde_json::from_slice(&bytes)?)
    }

    pub fn save_device_license(&self, device: &Device) -> Result<(), TokenStoreError> {
        self.persistent
            .set(keys::DEV_LICENSE, &serde_json::to_vec(device)?)
    }

    pub fn remove_device_license(&self) -> Result<(), TokenStoreError> {
        self.persistent.remove(keys::DEV_LICENSE)
    }

    // ---- Device STS tokens (keyed by SOAP "applies_to" address) -----------

    pub fn get_device_token_for(&self, address: &str) -> Result<Option<Token>, TokenStoreError> {
        Self::read_token_store(&*self.persistent, keys::DEVICE_TOKENS, address)
    }

    pub fn save_device_token(&self, address: String, token: Token) -> Result<(), TokenStoreError> {
        Self::write_token_store(&*self.persistent, keys::DEVICE_TOKENS, address, token)
    }

    /// This device's Passport STS token, unless it has expired.
    ///
    /// It is issued for 60 days and nothing used to look at that, so once it
    /// lapsed every request it signed was answered with a SOAP Fault, for as
    /// long as the keyring kept it. `TokenStoreError::Expired` is what makes
    /// `ensure_device_credentials` sign the device in again.
    pub fn get_device_sts_token(&self) -> Result<Token, TokenStoreError> {
        Self::unexpired(
            self.get_device_token_for(PASSPORT_STS)?
                .ok_or(TokenStoreError::NotFound)?,
        )
    }

    /// Drops every device STS token, keeping the device itself (`dev_license`),
    /// so the next `ensure_device_credentials` signs the same device in again.
    pub fn remove_device_tokens(&self) -> Result<(), TokenStoreError> {
        self.persistent.remove(keys::DEVICE_TOKENS)
    }

    // ---- User STS tokens (keyed by SOAP "applies_to" address) --------------

    pub fn get_user_token_for(&self, address: &str) -> Result<Option<Token>, TokenStoreError> {
        Self::read_token_store(&*self.persistent, keys::USER_TOKENS, address)
    }

    pub fn save_user_token(&self, address: String, token: Token) -> Result<(), TokenStoreError> {
        Self::write_token_store(&*self.persistent, keys::USER_TOKENS, address, token)
    }

    /// The account's Passport STS token, unless it has expired. Only a new
    /// sign-in replaces it, so an expired one is reported as such rather than
    /// sent to be refused.
    pub fn get_user_sts_token(&self) -> Result<Token, TokenStoreError> {
        Self::unexpired(
            self.get_user_token_for(PASSPORT_STS)?
                .ok_or(TokenStoreError::NotFound)?,
        )
    }

    fn unexpired(token: Token) -> Result<Token, TokenStoreError> {
        match &token {
            Token::Legacy(legacy) if legacy.is_expired_at(chrono::Utc::now()) => {
                Err(TokenStoreError::Expired(legacy.lifetime.expires.clone()))
            }
            _ => Ok(token),
        }
    }

    // ---- User info -----------------------------------------------------------

    pub fn get_user(&self) -> Result<User, TokenStoreError> {
        let bytes = self
            .persistent
            .get(keys::USER_INFO)?
            .ok_or(TokenStoreError::NotFound)?;
        Ok(serde_json::from_slice(&bytes)?)
    }

    pub fn save_user(&self, user: &User) -> Result<(), TokenStoreError> {
        self.persistent
            .set(keys::USER_INFO, &serde_json::to_vec(user)?)
    }

    // ---- Ephemeral XSTS-by-relying-party cache --------------------------------

    pub fn get_cached_xsts(&self, relying_party: &str) -> Option<XstsResponse> {
        let bytes = self.ephemeral.get(relying_party).ok()??;
        serde_json::from_slice(&bytes).ok()
    }

    pub fn cache_xsts(&self, relying_party: &str, token: &XstsResponse) {
        self.cache_xsts_response(relying_party, token);
    }

    fn cache_xsts_response(&self, key: &str, token: &XstsResponse) {
        let Ok(bytes) = serde_json::to_vec(token) else {
            return;
        };
        let remaining = (token.not_after - chrono::Utc::now())
            .to_std()
            .unwrap_or(std::time::Duration::ZERO);
        let _ = self
            .ephemeral
            .set_with_expiry(key, &bytes, Instant::now() + remaining);
    }

    // ---- shared TokenStore read/modify/write helper ---------------------------

    fn read_token_store(
        backend: &dyn TokenBackend,
        key: &str,
        address: &str,
    ) -> Result<Option<Token>, TokenStoreError> {
        let Some(bytes) = backend.get(key)? else {
            return Ok(None);
        };
        let store: TokenStore = serde_json::from_slice(&bytes)?;
        Ok(store.tokens.get(address).cloned())
    }

    fn write_token_store(
        backend: &dyn TokenBackend,
        key: &str,
        address: String,
        token: Token,
    ) -> Result<(), TokenStoreError> {
        let mut tokens: HashMap<String, Token> = match backend.get(key)? {
            Some(bytes) if !bytes.is_empty() => {
                serde_json::from_slice::<TokenStore>(&bytes)?.tokens
            }
            _ => HashMap::new(),
        };
        tokens.insert(address, token);
        backend.set(key, &serde_json::to_vec(&TokenStore { tokens })?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::secrets::LegacyToken;
    use crate::models::soap::Timestamp;

    fn legacy(expires: chrono::DateTime<chrono::Utc>) -> Token {
        Token::Legacy(LegacyToken {
            key_name: None,
            token: "token".to_string(),
            binary_secret: None,
            tpm_key: None,
            lifetime: Timestamp {
                id: None,
                created: (expires - chrono::TimeDelta::days(60)).to_rfc3339(),
                expires: expires.to_rfc3339(),
            },
        })
    }

    fn expired() -> Token {
        legacy(chrono::Utc::now() - chrono::TimeDelta::days(1))
    }

    fn current() -> Token {
        legacy(chrono::Utc::now() + chrono::TimeDelta::days(30))
    }

    #[test]
    fn an_expired_device_token_is_not_handed_out() {
        let tokens = TokenManager::with_memory();
        tokens
            .save_device_token(PASSPORT_STS.to_string(), expired())
            .unwrap();

        assert!(matches!(
            tokens.get_device_sts_token(),
            Err(TokenStoreError::Expired(_))
        ));
    }

    #[test]
    fn a_current_device_token_is_handed_out() {
        let tokens = TokenManager::with_memory();
        tokens
            .save_device_token(PASSPORT_STS.to_string(), current())
            .unwrap();

        assert!(tokens.get_device_sts_token().is_ok());
    }

    #[test]
    fn an_expired_user_token_is_not_handed_out() {
        let tokens = TokenManager::with_memory();
        tokens
            .save_user_token(PASSPORT_STS.to_string(), expired())
            .unwrap();

        assert!(matches!(
            tokens.get_user_sts_token(),
            Err(TokenStoreError::Expired(_))
        ));
    }

    #[test]
    fn removing_the_device_tokens_keeps_the_device_and_the_account() {
        let tokens = TokenManager::with_memory();
        tokens
            .save_device_license(&Device {
                puid: "1".to_string(),
                hwid: "hw".to_string(),
                device_id: "dev".to_string(),
                splicense: String::new(),
                username: "02device".to_string(),
                password: "secret".to_string(),
            })
            .unwrap();
        tokens
            .save_device_token(PASSPORT_STS.to_string(), expired())
            .unwrap();
        tokens
            .save_user_token(PASSPORT_STS.to_string(), current())
            .unwrap();
        tokens
            .save_user(&User {
                puid: "2".to_string(),
                username: "player@example.com".to_string(),
            })
            .unwrap();

        tokens.remove_device_tokens().unwrap();

        assert!(matches!(
            tokens.get_device_sts_token(),
            Err(TokenStoreError::NotFound)
        ));
        assert!(tokens.get_device_license().is_ok());
        assert!(tokens.get_user_sts_token().is_ok());
        assert!(tokens.get_user().is_ok());
    }
}
