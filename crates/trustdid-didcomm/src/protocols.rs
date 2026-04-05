//! Standard DIDComm protocol handlers.
//!
//! Implements DIDComm protocol handlers for Trust Ping and the custom
//! TrustDID agent authentication protocol.

use crate::message::{protocol, Attachment, AttachmentData, DIDCommMessage};

// ---------------------------------------------------------------------------
// Trust Ping 2.0 protocol
// ---------------------------------------------------------------------------

/// Trust Ping 2.0 protocol handler.
///
/// Trust Ping is a simple protocol for verifying agent connectivity.
/// A ping message elicits a ping-response from the recipient.
pub struct TrustPing;

impl TrustPing {
    /// Create a Trust Ping message from `from` to `to`.
    pub fn send_ping(from: impl Into<String>, to: impl Into<String>) -> DIDCommMessage {
        DIDCommMessage::trust_ping(from, to)
    }

    /// Handle an incoming Trust Ping message.
    ///
    /// If the message requests a response (`response_requested` is true or absent),
    /// returns a ping-response message. Otherwise returns `None`.
    pub fn handle_ping(message: &DIDCommMessage) -> Option<DIDCommMessage> {
        if message.type_ != protocol::TRUST_PING {
            return None;
        }

        // Check if a response is requested (defaults to true per spec).
        let response_requested = message
            .body
            .get("response_requested")
            .and_then(|v| v.as_bool())
            .unwrap_or(true);

        if !response_requested {
            return None;
        }

        // Build the response, swapping sender and recipient.
        let from = message.to.first()?;
        let to = message.from.as_ref()?;

        Some(DIDCommMessage::trust_ping_response(from, to, &message.id))
    }
}

// ---------------------------------------------------------------------------
// Agent Auth 1.0 protocol (TrustDID-specific)
// ---------------------------------------------------------------------------

/// TrustDID Agent Authentication protocol handler.
///
/// This protocol allows agents to authenticate each other by proving they
/// hold delegation credentials and the required capabilities.
///
/// Flow:
/// 1. Requester sends `auth_request` specifying required capabilities.
/// 2. Responder sends `auth_response` with a delegation chain proof.
/// 3. Requester verifies the delegation chain.
pub struct AgentAuth;

impl AgentAuth {
    /// Create an authentication request message.
    ///
    /// The `capabilities_required` list specifies what capabilities the
    /// requesting agent needs the responder to prove.
    pub fn auth_request(
        from: impl Into<String>,
        to: impl Into<String>,
        capabilities_required: &[String],
    ) -> DIDCommMessage {
        DIDCommMessage::builder(protocol::AGENT_AUTH_REQUEST)
            .from(from)
            .to(to)
            .body(serde_json::json!({
                "capabilities_required": capabilities_required,
            }))
            .build()
    }

    /// Create an authentication response message.
    ///
    /// The `delegation_chain_proof` is a JSON value containing the verifiable
    /// delegation chain from the responder back to a trusted root.
    pub fn auth_response(
        from: impl Into<String>,
        to: impl Into<String>,
        thid: impl Into<String>,
        delegation_chain_proof: serde_json::Value,
    ) -> DIDCommMessage {
        let attachment = Attachment {
            id: "delegation-chain".to_string(),
            media_type: Some("application/json".to_string()),
            data: AttachmentData::Json(delegation_chain_proof),
        };

        DIDCommMessage::builder(protocol::AGENT_AUTH_RESPONSE)
            .from(from)
            .to(to)
            .thid(thid)
            .body(serde_json::json!({
                "authenticated": true,
            }))
            .attachment(attachment)
            .build()
    }

    /// Handle an incoming authentication request.
    ///
    /// Returns `Some(DIDCommMessage)` if the message is a valid auth request
    /// and we can construct a response. The caller must supply the delegation
    /// chain proof to include in the response.
    ///
    /// Returns `None` if the message is not an auth request.
    pub fn handle_auth_request(
        message: &DIDCommMessage,
        delegation_chain_proof: serde_json::Value,
    ) -> Option<DIDCommMessage> {
        if message.type_ != protocol::AGENT_AUTH_REQUEST {
            return None;
        }

        let from = message.to.first()?;
        let to = message.from.as_ref()?;

        Some(Self::auth_response(from, to, &message.id, delegation_chain_proof))
    }

    /// Extract the required capabilities from an auth request message.
    pub fn extract_capabilities(message: &DIDCommMessage) -> Option<Vec<String>> {
        if message.type_ != protocol::AGENT_AUTH_REQUEST {
            return None;
        }

        message
            .body
            .get("capabilities_required")
            .and_then(|v| serde_json::from_value::<Vec<String>>(v.clone()).ok())
    }

    /// Extract the delegation chain proof from an auth response message.
    pub fn extract_delegation_proof(message: &DIDCommMessage) -> Option<serde_json::Value> {
        if message.type_ != protocol::AGENT_AUTH_RESPONSE {
            return None;
        }

        message
            .attachments
            .iter()
            .find(|a| a.id == "delegation-chain")
            .and_then(|a| match &a.data {
                AttachmentData::Json(v) => Some(v.clone()),
                _ => None,
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    // -----------------------------------------------------------------------
    // Trust Ping tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_trust_ping_send() {
        let ping = TrustPing::send_ping(
            "did:trustdid:evm:1:alice",
            "did:trustdid:evm:1:bob",
        );

        assert_eq!(ping.type_, protocol::TRUST_PING);
        assert_eq!(ping.from.as_deref(), Some("did:trustdid:evm:1:alice"));
        assert_eq!(ping.to, vec!["did:trustdid:evm:1:bob"]);
        assert_eq!(ping.body["response_requested"], true);
    }

    #[test]
    fn test_trust_ping_handle_returns_pong() {
        let ping = TrustPing::send_ping(
            "did:trustdid:evm:1:alice",
            "did:trustdid:evm:1:bob",
        );

        let pong = TrustPing::handle_ping(&ping).expect("should return pong");

        assert_eq!(pong.type_, protocol::TRUST_PING_RESPONSE);
        assert_eq!(pong.from.as_deref(), Some("did:trustdid:evm:1:bob"));
        assert_eq!(pong.to, vec!["did:trustdid:evm:1:alice"]);
        assert_eq!(pong.thid.as_deref(), Some(ping.id.as_str()));
    }

    #[test]
    fn test_trust_ping_no_response_requested() {
        let mut ping = TrustPing::send_ping(
            "did:trustdid:evm:1:alice",
            "did:trustdid:evm:1:bob",
        );
        ping.body = serde_json::json!({ "response_requested": false });

        let result = TrustPing::handle_ping(&ping);
        assert!(result.is_none());
    }

    #[test]
    fn test_trust_ping_handle_wrong_type() {
        let msg = DIDCommMessage::builder(protocol::BASIC_MESSAGE)
            .from("did:trustdid:evm:1:alice")
            .to("did:trustdid:evm:1:bob")
            .body(serde_json::json!({}))
            .build();

        let result = TrustPing::handle_ping(&msg);
        assert!(result.is_none());
    }

    #[test]
    fn test_trust_ping_handle_no_sender() {
        // Anonymous ping with no `from` -- cannot construct response.
        let msg = DIDCommMessage::builder(protocol::TRUST_PING)
            .to("did:trustdid:evm:1:bob")
            .body(serde_json::json!({ "response_requested": true }))
            .build();

        let result = TrustPing::handle_ping(&msg);
        assert!(result.is_none());
    }

    // -----------------------------------------------------------------------
    // Agent Auth tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_agent_auth_request() {
        let caps = vec!["credential:issue".to_string(), "payment:authorize".to_string()];
        let req = AgentAuth::auth_request(
            "did:trustdid:evm:1:requester",
            "did:trustdid:evm:1:responder",
            &caps,
        );

        assert_eq!(req.type_, protocol::AGENT_AUTH_REQUEST);
        assert_eq!(req.from.as_deref(), Some("did:trustdid:evm:1:requester"));
        assert_eq!(req.to, vec!["did:trustdid:evm:1:responder"]);

        let extracted = AgentAuth::extract_capabilities(&req).unwrap();
        assert_eq!(extracted, caps);
    }

    #[test]
    fn test_agent_auth_response() {
        let proof = serde_json::json!({
            "chain": [
                {
                    "parent": "did:trustdid:evm:1:root",
                    "child": "did:trustdid:evm:1:responder",
                    "capabilities": ["credential:issue"],
                    "proof": "base64-encoded-proof"
                }
            ]
        });

        let resp = AgentAuth::auth_response(
            "did:trustdid:evm:1:responder",
            "did:trustdid:evm:1:requester",
            "thread-001",
            proof.clone(),
        );

        assert_eq!(resp.type_, protocol::AGENT_AUTH_RESPONSE);
        assert_eq!(resp.thid.as_deref(), Some("thread-001"));
        assert_eq!(resp.attachments.len(), 1);
        assert_eq!(resp.attachments[0].id, "delegation-chain");

        let extracted = AgentAuth::extract_delegation_proof(&resp).unwrap();
        assert_eq!(extracted, proof);
    }

    #[test]
    fn test_agent_auth_handle_request() {
        let caps = vec!["credential:issue".to_string()];
        let req = AgentAuth::auth_request(
            "did:trustdid:evm:1:requester",
            "did:trustdid:evm:1:responder",
            &caps,
        );

        let proof = serde_json::json!({ "chain": [] });
        let resp = AgentAuth::handle_auth_request(&req, proof.clone()).expect("should respond");

        assert_eq!(resp.type_, protocol::AGENT_AUTH_RESPONSE);
        assert_eq!(resp.from.as_deref(), Some("did:trustdid:evm:1:responder"));
        assert_eq!(resp.to, vec!["did:trustdid:evm:1:requester"]);
        assert_eq!(resp.thid.as_deref(), Some(req.id.as_str()));

        let extracted = AgentAuth::extract_delegation_proof(&resp).unwrap();
        assert_eq!(extracted, proof);
    }

    #[test]
    fn test_agent_auth_handle_wrong_type() {
        let msg = DIDCommMessage::builder(protocol::BASIC_MESSAGE)
            .from("did:trustdid:evm:1:alice")
            .to("did:trustdid:evm:1:bob")
            .body(serde_json::json!({}))
            .build();

        let result = AgentAuth::handle_auth_request(&msg, serde_json::json!({}));
        assert!(result.is_none());
    }

    #[test]
    fn test_extract_capabilities_wrong_type() {
        let msg = DIDCommMessage::builder(protocol::BASIC_MESSAGE)
            .body(serde_json::json!({}))
            .build();

        assert!(AgentAuth::extract_capabilities(&msg).is_none());
    }

    #[test]
    fn test_extract_delegation_proof_wrong_type() {
        let msg = DIDCommMessage::builder(protocol::BASIC_MESSAGE)
            .body(serde_json::json!({}))
            .build();

        assert!(AgentAuth::extract_delegation_proof(&msg).is_none());
    }

    #[test]
    fn test_full_auth_flow() {
        // 1. Requester creates an auth request.
        let caps = vec!["credential:issue".to_string(), "payment:authorize".to_string()];
        let request = AgentAuth::auth_request(
            "did:trustdid:evm:1:agent-a",
            "did:trustdid:evm:1:agent-b",
            &caps,
        );

        // 2. Responder receives request, extracts capabilities.
        let required = AgentAuth::extract_capabilities(&request).unwrap();
        assert_eq!(required, caps);

        // 3. Responder creates auth response with delegation proof.
        let proof = serde_json::json!({
            "chain": [{
                "parent": "did:trustdid:evm:1:org",
                "child": "did:trustdid:evm:1:agent-b",
                "capabilities": ["credential:issue", "payment:authorize"],
                "signature": "proof-sig"
            }]
        });
        let response = AgentAuth::handle_auth_request(&request, proof.clone()).unwrap();

        // 4. Requester receives response, extracts delegation proof.
        let received_proof = AgentAuth::extract_delegation_proof(&response).unwrap();
        assert_eq!(received_proof, proof);
        assert_eq!(response.thid.as_deref(), Some(request.id.as_str()));
    }

    // -----------------------------------------------------------------------
    // Protocol constants tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_protocol_constants() {
        assert!(protocol::TRUST_PING.starts_with("https://didcomm.org/"));
        assert!(protocol::TRUST_PING_RESPONSE.starts_with("https://didcomm.org/"));
        assert!(protocol::AGENT_AUTH_REQUEST.starts_with("https://trustdid.org/"));
        assert!(protocol::AGENT_AUTH_RESPONSE.starts_with("https://trustdid.org/"));
        assert!(protocol::BASIC_MESSAGE.starts_with("https://didcomm.org/"));
    }
}
