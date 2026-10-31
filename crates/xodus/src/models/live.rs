use serde::{Deserialize, Serialize};

use crate::models::soap;

/// The tokens login.live.com leaves in `ServerData` once a sign-in is done.
///
/// Only the fields the token exchange cannot do without are required. The
/// session key is never read, and the inline flow token is what a sign-in
/// that has already been through its inline-auth leg may no longer carry:
/// requiring either turned such a `ServerData` into a payload nobody
/// recognised, and the page sat on "Please wait" for ever.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DAProperty {
    #[serde(rename = "sDAToken")]
    pub da_token: String,
    #[serde(rename = "sDASessionKey", default)]
    pub da_session_key: String,
    #[serde(rename = "sDAStartTime")]
    pub da_start_time: String,
    #[serde(rename = "sDAExpires")]
    pub da_expires: String,
    #[serde(rename = "sSTSInlineFlowToken", default)]
    pub sts_inline_flow_token: Option<String>,
    #[serde(rename = "sSigninName")]
    pub username: String,
    #[serde(rename = "K", deserialize_with = "string_or_number")]
    pub puid: String,
}

impl DAProperty {
    /// The fields `ServerData` has to carry for this to be a finished sign-in.
    pub const REQUIRED: [&'static str; 5] =
        ["sDAToken", "sDAStartTime", "sDAExpires", "sSigninName", "K"];

    /// Whether `value` is a `ServerData` that carries sign-in tokens at all.
    pub fn is_token_bag(value: &serde_json::Value) -> bool {
        value.get("sDAToken").is_some()
    }

    /// The required fields `value` lacks, by name only: the values are
    /// credentials and are never worth printing.
    pub fn missing(value: &serde_json::Value) -> Vec<&'static str> {
        Self::REQUIRED
            .into_iter()
            .filter(|name| value.get(name).is_none_or(serde_json::Value::is_null))
            .collect()
    }
}

fn string_or_number<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    match serde_json::Value::deserialize(deserializer)? {
        serde_json::Value::String(text) => Ok(text),
        serde_json::Value::Number(number) => Ok(number.to_string()),
        other => Err(serde::de::Error::custom(format!(
            "expected a string or a number, got {other}"
        ))),
    }
}

#[derive(Deserialize, Debug)]
pub struct HostBridgeMessage {
    #[serde(rename = "type")]
    pub message_type: Option<String>,
    pub value: Option<HostBridgeValue>,
}

#[derive(Deserialize, Debug)]
pub struct HostBridgeValue {
    pub name: Option<String>,
    pub context: Option<String>,
}

impl HostBridgeMessage {
    /// The host method the page is waiting on, when it is one this host does
    /// not answer. The page shows "Please wait" until its callback comes back,
    /// so an invoke that is dropped without a word is a sign-in that hangs with
    /// nothing in the log to say why.
    pub fn unanswered_invoke(&self) -> Option<&str> {
        let value = self.value.as_ref()?;
        if self.message_type.as_deref() != Some("invoke") || self.get_context_invoke().is_some() {
            return None;
        }
        Some(value.name.as_deref().unwrap_or("<unnamed>"))
    }

    pub fn get_context_invoke(&self) -> Option<&str> {
        let value = self.value.as_ref()?;
        if self.message_type.as_deref() == Some("invoke")
            && value.name.as_deref() == Some("CloudExperienceHost.getContext")
        {
            value.context.as_deref()
        } else {
            None
        }
    }
}

#[derive(Debug)]
pub enum ExchangeUserTokenOutcome {
    Issued(soap::BodyContent),
    Fault(Option<soap::PP>),
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn server_data() -> serde_json::Value {
        json!({
            "sDAToken": "t", "sDASessionKey": "s", "sDAStartTime": "a",
            "sDAExpires": "b", "sSTSInlineFlowToken": "f", "sSigninName": "u",
            "K": "1", "urlPost": "https://login.live.com/ppsecure/post.srf",
        })
    }

    #[test]
    fn server_data_with_every_field_is_a_finished_sign_in() {
        let data: DAProperty = serde_json::from_value(server_data()).unwrap();
        assert_eq!(data.sts_inline_flow_token.as_deref(), Some("f"));
        assert_eq!(data.puid, "1");
    }

    /// The leg after an inline-auth fault: no flow token and no session key.
    /// Required, they made this payload unrecognisable and the sign-in hung.
    #[test]
    fn server_data_without_the_inline_flow_token_still_finishes() {
        let mut value = server_data();
        let bag = value.as_object_mut().unwrap();
        bag.remove("sSTSInlineFlowToken");
        bag.remove("sDASessionKey");
        let data: DAProperty = serde_json::from_value(value).unwrap();
        assert_eq!(data.sts_inline_flow_token, None);
        assert_eq!(data.da_session_key, "");
    }

    #[test]
    fn a_numeric_puid_is_read_as_its_digits() {
        let mut value = server_data();
        value["K"] = json!(1234567890123u64);
        let data: DAProperty = serde_json::from_value(value).unwrap();
        assert_eq!(data.puid, "1234567890123");
    }

    #[test]
    fn missing_names_the_fields_and_not_their_values() {
        let mut value = server_data();
        value.as_object_mut().unwrap().remove("sDAExpires");
        value["K"] = serde_json::Value::Null;
        assert!(DAProperty::is_token_bag(&value));
        assert_eq!(DAProperty::missing(&value), ["sDAExpires", "K"]);
        assert!(!DAProperty::is_token_bag(&json!({"urlPost": "x"})));
    }

    #[test]
    fn only_invokes_other_than_get_context_are_reported() {
        let parse = |v: serde_json::Value| serde_json::from_value::<HostBridgeMessage>(v).unwrap();
        let context = parse(json!({"type": "invoke", "value": {
            "name": "CloudExperienceHost.getContext", "context": "c"}}));
        assert_eq!(context.unanswered_invoke(), None);
        let event = parse(json!({"type": "event", "value": {
            "name": "CloudExperienceHost.visible", "data": true}}));
        assert_eq!(event.unanswered_invoke(), None);
        let other = parse(json!({"type": "invoke", "value": {
            "name": "CloudExperienceHost.done", "context": "d"}}));
        assert_eq!(other.unanswered_invoke(), Some("CloudExperienceHost.done"));
    }
}
