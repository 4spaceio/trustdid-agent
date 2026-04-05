//! DIDComm v2.1 message types.
//!
//! Implements the core DIDComm message structure with builder pattern,
//! attachments, and convenience constructors for common protocols.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Protocol type URIs for DIDComm v2 standard protocols.
pub mod protocol {
    /// Trust Ping 2.0 protocol.
    pub const TRUST_PING: &str = "https://didcomm.org/trust-ping/2.0/ping";
    pub const TRUST_PING_RESPONSE: &str = "https://didcomm.org/trust-ping/2.0/ping-response";

    /// TrustDID agent authentication protocol.
    pub const AGENT_AUTH_REQUEST: &str = "https://trustdid.org/agent-auth/1.0/request";
    pub const AGENT_AUTH_RESPONSE: &str = "https://trustdid.org/agent-auth/1.0/response";

    /// Basic message protocol.
    pub const BASIC_MESSAGE: &str = "https://didcomm.org/basicmessage/2.0/message";
}

/// A DIDComm v2.1 compliant message.
///
/// This is the core message structure used for all agent-to-agent communication
/// in the TrustDID system. Messages are self-describing through their `type_` field
/// and can carry arbitrary structured data in the `body` and `attachments`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DIDCommMessage {
    /// Unique message identifier (UUID).
    pub id: String,

    /// Message type URI (e.g., "https://didcomm.org/trust-ping/2.0/ping").
    #[serde(rename = "type")]
    pub type_: String,

    /// Sender DID. Optional for anonymous messages.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,

    /// Recipient DIDs.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub to: Vec<String>,

    /// Message creation time as epoch seconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_time: Option<u64>,

    /// Message expiration time as epoch seconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_time: Option<u64>,

    /// Message body (protocol-specific JSON payload).
    pub body: serde_json::Value,

    /// Attached data (files, credentials, etc.).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub attachments: Vec<Attachment>,

    /// Thread identifier for correlating messages in a conversation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thid: Option<String>,

    /// Parent thread identifier for linking sub-protocols.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pthid: Option<String>,
}

impl DIDCommMessage {
    /// Create a new builder for constructing a DIDComm message.
    pub fn builder(type_uri: impl Into<String>) -> DIDCommMessageBuilder {
        DIDCommMessageBuilder::new(type_uri)
    }

    /// Convenience constructor for a Trust Ping message.
    pub fn trust_ping(from: impl Into<String>, to: impl Into<String>) -> Self {
        let from_str = from.into();
        let id = Uuid::new_v4().to_string();
        Self {
            id,
            type_: protocol::TRUST_PING.to_string(),
            from: Some(from_str),
            to: vec![to.into()],
            created_time: Some(now_epoch()),
            expires_time: None,
            body: serde_json::json!({ "response_requested": true }),
            attachments: Vec::new(),
            thid: None,
            pthid: None,
        }
    }

    /// Convenience constructor for a Trust Ping response.
    pub fn trust_ping_response(
        from: impl Into<String>,
        to: impl Into<String>,
        thid: impl Into<String>,
    ) -> Self {
        let id = Uuid::new_v4().to_string();
        Self {
            id,
            type_: protocol::TRUST_PING_RESPONSE.to_string(),
            from: Some(from.into()),
            to: vec![to.into()],
            created_time: Some(now_epoch()),
            expires_time: None,
            body: serde_json::json!({}),
            attachments: Vec::new(),
            thid: Some(thid.into()),
            pthid: None,
        }
    }

    /// Returns the thread ID for this message, falling back to the message ID.
    pub fn thread_id(&self) -> &str {
        self.thid.as_deref().unwrap_or(&self.id)
    }

    /// Check if this message has expired based on current time.
    pub fn is_expired(&self) -> bool {
        if let Some(exp) = self.expires_time {
            now_epoch() > exp
        } else {
            false
        }
    }
}

/// Builder for constructing DIDComm messages with a fluent API.
#[derive(Debug)]
pub struct DIDCommMessageBuilder {
    type_: String,
    from: Option<String>,
    to: Vec<String>,
    body: serde_json::Value,
    attachments: Vec<Attachment>,
    thid: Option<String>,
    pthid: Option<String>,
    created_time: Option<u64>,
    expires_time: Option<u64>,
    id: Option<String>,
}

impl DIDCommMessageBuilder {
    /// Create a new builder with the given message type URI.
    pub fn new(type_uri: impl Into<String>) -> Self {
        Self {
            type_: type_uri.into(),
            from: None,
            to: Vec::new(),
            body: serde_json::Value::Object(serde_json::Map::new()),
            attachments: Vec::new(),
            thid: None,
            pthid: None,
            created_time: None,
            expires_time: None,
            id: None,
        }
    }

    /// Set a custom message ID (defaults to a new UUID).
    pub fn id(mut self, id: impl Into<String>) -> Self {
        self.id = Some(id.into());
        self
    }

    /// Set the sender DID.
    pub fn from(mut self, from: impl Into<String>) -> Self {
        self.from = Some(from.into());
        self
    }

    /// Add a recipient DID.
    pub fn to(mut self, to: impl Into<String>) -> Self {
        self.to.push(to.into());
        self
    }

    /// Add multiple recipient DIDs.
    pub fn to_many(mut self, recipients: Vec<String>) -> Self {
        self.to.extend(recipients);
        self
    }

    /// Set the message body.
    pub fn body(mut self, body: serde_json::Value) -> Self {
        self.body = body;
        self
    }

    /// Add an attachment.
    pub fn attachment(mut self, attachment: Attachment) -> Self {
        self.attachments.push(attachment);
        self
    }

    /// Set the thread ID.
    pub fn thid(mut self, thid: impl Into<String>) -> Self {
        self.thid = Some(thid.into());
        self
    }

    /// Set the parent thread ID.
    pub fn pthid(mut self, pthid: impl Into<String>) -> Self {
        self.pthid = Some(pthid.into());
        self
    }

    /// Set the creation time (epoch seconds).
    pub fn created_time(mut self, time: u64) -> Self {
        self.created_time = Some(time);
        self
    }

    /// Set the expiration time (epoch seconds).
    pub fn expires_time(mut self, time: u64) -> Self {
        self.expires_time = Some(time);
        self
    }

    /// Build the DIDComm message.
    pub fn build(self) -> DIDCommMessage {
        DIDCommMessage {
            id: self.id.unwrap_or_else(|| Uuid::new_v4().to_string()),
            type_: self.type_,
            from: self.from,
            to: self.to,
            created_time: self.created_time.or(Some(now_epoch())),
            expires_time: self.expires_time,
            body: self.body,
            attachments: self.attachments,
            thid: self.thid,
            pthid: self.pthid,
        }
    }
}

/// An attachment to a DIDComm message.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Attachment {
    /// Attachment identifier.
    pub id: String,

    /// MIME type of the attachment content.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub media_type: Option<String>,

    /// Attachment data.
    pub data: AttachmentData,
}

impl Attachment {
    /// Create a new base64-encoded attachment.
    pub fn base64(id: impl Into<String>, media_type: impl Into<String>, data: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            media_type: Some(media_type.into()),
            data: AttachmentData::Base64(data.into()),
        }
    }

    /// Create a new JSON attachment.
    pub fn json(id: impl Into<String>, data: serde_json::Value) -> Self {
        Self {
            id: id.into(),
            media_type: Some("application/json".to_string()),
            data: AttachmentData::Json(data),
        }
    }

    /// Create a new links-based attachment.
    pub fn links(id: impl Into<String>, media_type: impl Into<String>, urls: Vec<String>) -> Self {
        Self {
            id: id.into(),
            media_type: Some(media_type.into()),
            data: AttachmentData::Links(urls),
        }
    }
}

/// Data content of an attachment.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", content = "value")]
pub enum AttachmentData {
    /// Base64-encoded binary data.
    #[serde(rename = "base64")]
    Base64(String),

    /// Inline JSON data.
    #[serde(rename = "json")]
    Json(serde_json::Value),

    /// External links to the data.
    #[serde(rename = "links")]
    Links(Vec<String>),
}

/// Get the current time as epoch seconds.
fn now_epoch() -> u64 {
    chrono::Utc::now().timestamp() as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn test_builder_basic() {
        let msg = DIDCommMessage::builder("https://didcomm.org/basicmessage/2.0/message")
            .id("msg-123")
            .from("did:trustdid:evm:1:sender")
            .to("did:trustdid:evm:1:receiver")
            .body(serde_json::json!({ "content": "Hello!" }))
            .build();

        assert_eq!(msg.id, "msg-123");
        assert_eq!(msg.type_, "https://didcomm.org/basicmessage/2.0/message");
        assert_eq!(msg.from.as_deref(), Some("did:trustdid:evm:1:sender"));
        assert_eq!(msg.to, vec!["did:trustdid:evm:1:receiver"]);
        assert_eq!(msg.body["content"], "Hello!");
        assert!(msg.created_time.is_some());
    }

    #[test]
    fn test_builder_with_thread() {
        let msg = DIDCommMessage::builder(protocol::TRUST_PING_RESPONSE)
            .from("did:trustdid:evm:1:b")
            .to("did:trustdid:evm:1:a")
            .thid("thread-001")
            .pthid("parent-001")
            .body(serde_json::json!({}))
            .build();

        assert_eq!(msg.thid.as_deref(), Some("thread-001"));
        assert_eq!(msg.pthid.as_deref(), Some("parent-001"));
        assert_eq!(msg.thread_id(), "thread-001");
    }

    #[test]
    fn test_thread_id_fallback() {
        let msg = DIDCommMessage::builder(protocol::BASIC_MESSAGE)
            .id("msg-fallback")
            .body(serde_json::json!({}))
            .build();

        // Without thid, thread_id() should return the message id.
        assert_eq!(msg.thread_id(), "msg-fallback");
    }

    #[test]
    fn test_builder_multiple_recipients() {
        let msg = DIDCommMessage::builder(protocol::BASIC_MESSAGE)
            .from("did:trustdid:evm:1:sender")
            .to("did:trustdid:evm:1:r1")
            .to("did:trustdid:evm:1:r2")
            .to_many(vec![
                "did:trustdid:evm:1:r3".to_string(),
                "did:trustdid:evm:1:r4".to_string(),
            ])
            .body(serde_json::json!({}))
            .build();

        assert_eq!(msg.to.len(), 4);
    }

    #[test]
    fn test_builder_with_attachments() {
        let attachment = Attachment::json(
            "att-1",
            serde_json::json!({ "credential": "vc-data" }),
        );

        let msg = DIDCommMessage::builder(protocol::BASIC_MESSAGE)
            .from("did:trustdid:evm:1:sender")
            .to("did:trustdid:evm:1:receiver")
            .body(serde_json::json!({}))
            .attachment(attachment.clone())
            .build();

        assert_eq!(msg.attachments.len(), 1);
        assert_eq!(msg.attachments[0].id, "att-1");
    }

    #[test]
    fn test_trust_ping() {
        let msg = DIDCommMessage::trust_ping(
            "did:trustdid:evm:1:alice",
            "did:trustdid:evm:1:bob",
        );

        assert_eq!(msg.type_, protocol::TRUST_PING);
        assert_eq!(msg.from.as_deref(), Some("did:trustdid:evm:1:alice"));
        assert_eq!(msg.to, vec!["did:trustdid:evm:1:bob"]);
        assert_eq!(msg.body["response_requested"], true);
        assert!(msg.thid.is_none());
    }

    #[test]
    fn test_trust_ping_response() {
        let ping = DIDCommMessage::trust_ping(
            "did:trustdid:evm:1:alice",
            "did:trustdid:evm:1:bob",
        );

        let pong = DIDCommMessage::trust_ping_response(
            "did:trustdid:evm:1:bob",
            "did:trustdid:evm:1:alice",
            &ping.id,
        );

        assert_eq!(pong.type_, protocol::TRUST_PING_RESPONSE);
        assert_eq!(pong.from.as_deref(), Some("did:trustdid:evm:1:bob"));
        assert_eq!(pong.to, vec!["did:trustdid:evm:1:alice"]);
        assert_eq!(pong.thid.as_deref(), Some(ping.id.as_str()));
    }

    #[test]
    fn test_serialization_roundtrip() {
        let msg = DIDCommMessage::builder(protocol::TRUST_PING)
            .id("roundtrip-001")
            .from("did:trustdid:evm:1:alice")
            .to("did:trustdid:evm:1:bob")
            .body(serde_json::json!({ "response_requested": true }))
            .thid("thread-rt")
            .created_time(1700000000)
            .expires_time(1700003600)
            .build();

        let json = serde_json::to_string_pretty(&msg).unwrap();
        let deserialized: DIDCommMessage = serde_json::from_str(&json).unwrap();
        assert_eq!(msg, deserialized);
    }

    #[test]
    fn test_serialization_minimal() {
        // Minimal message: only required fields.
        let msg = DIDCommMessage::builder(protocol::BASIC_MESSAGE)
            .id("min-001")
            .body(serde_json::json!({ "content": "hi" }))
            .build();

        let json = serde_json::to_string(&msg).unwrap();
        // "from" should be absent, "to" should be absent (empty vec).
        assert!(!json.contains("\"from\""));
        assert!(!json.contains("\"to\""));
        assert!(!json.contains("\"thid\""));
        assert!(!json.contains("\"pthid\""));
        assert!(!json.contains("\"attachments\""));

        let deserialized: DIDCommMessage = serde_json::from_str(&json).unwrap();
        assert_eq!(msg.id, deserialized.id);
        assert_eq!(msg.type_, deserialized.type_);
        assert!(deserialized.from.is_none());
        assert!(deserialized.to.is_empty());
    }

    #[test]
    fn test_attachment_base64() {
        let att = Attachment::base64("att-b64", "application/pdf", "AQIDBA==");
        assert_eq!(att.id, "att-b64");
        assert_eq!(att.media_type.as_deref(), Some("application/pdf"));
        match &att.data {
            AttachmentData::Base64(data) => assert_eq!(data, "AQIDBA=="),
            _ => panic!("expected Base64 variant"),
        }
    }

    #[test]
    fn test_attachment_json() {
        let att = Attachment::json("att-json", serde_json::json!({ "key": "value" }));
        match &att.data {
            AttachmentData::Json(v) => assert_eq!(v["key"], "value"),
            _ => panic!("expected Json variant"),
        }
    }

    #[test]
    fn test_attachment_links() {
        let att = Attachment::links(
            "att-links",
            "application/pdf",
            vec!["https://example.com/doc.pdf".to_string()],
        );
        match &att.data {
            AttachmentData::Links(urls) => {
                assert_eq!(urls.len(), 1);
                assert_eq!(urls[0], "https://example.com/doc.pdf");
            }
            _ => panic!("expected Links variant"),
        }
    }

    #[test]
    fn test_attachment_serialization_roundtrip() {
        let att = Attachment::json("att-rt", serde_json::json!({ "vc": "data" }));
        let json = serde_json::to_string(&att).unwrap();
        let deserialized: Attachment = serde_json::from_str(&json).unwrap();
        assert_eq!(att, deserialized);
    }

    #[test]
    fn test_is_expired() {
        let msg = DIDCommMessage::builder(protocol::BASIC_MESSAGE)
            .body(serde_json::json!({}))
            .expires_time(1) // epoch second 1 is definitely in the past
            .build();
        assert!(msg.is_expired());

        let msg_future = DIDCommMessage::builder(protocol::BASIC_MESSAGE)
            .body(serde_json::json!({}))
            .expires_time(u64::MAX)
            .build();
        assert!(!msg_future.is_expired());

        let msg_no_expiry = DIDCommMessage::builder(protocol::BASIC_MESSAGE)
            .body(serde_json::json!({}))
            .build();
        assert!(!msg_no_expiry.is_expired());
    }

    #[test]
    fn test_deserialize_from_json_string() {
        let json_str = r#"{
            "id": "ext-001",
            "type": "https://didcomm.org/basicmessage/2.0/message",
            "from": "did:example:sender",
            "to": ["did:example:receiver"],
            "body": { "content": "external" },
            "created_time": 1700000000
        }"#;

        let msg: DIDCommMessage = serde_json::from_str(json_str).unwrap();
        assert_eq!(msg.id, "ext-001");
        assert_eq!(msg.from.as_deref(), Some("did:example:sender"));
        assert_eq!(msg.to.len(), 1);
        assert!(msg.attachments.is_empty());
        assert!(msg.thid.is_none());
    }
}
