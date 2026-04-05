//! Message routing for DIDComm messages.
//!
//! Provides a `Router` that dispatches incoming DIDComm messages to registered
//! handler functions based on the message type URI.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use crate::message::DIDCommMessage;

/// The result of routing a message.
#[derive(Debug)]
pub enum RoutingResult {
    /// The handler produced a response message to send back.
    Response(DIDCommMessage),
    /// The message should be forwarded to the given DID.
    Forward(String, DIDCommMessage),
    /// No handler was registered for this message type.
    NoHandler,
}

impl RoutingResult {
    /// Returns `true` if the result is a `Response`.
    pub fn is_response(&self) -> bool {
        matches!(self, Self::Response(_))
    }

    /// Returns `true` if the result is a `Forward`.
    pub fn is_forward(&self) -> bool {
        matches!(self, Self::Forward(..))
    }

    /// Returns `true` if no handler was found.
    pub fn is_no_handler(&self) -> bool {
        matches!(self, Self::NoHandler)
    }

    /// Extract the response message, if any.
    pub fn into_response(self) -> Option<DIDCommMessage> {
        match self {
            Self::Response(msg) => Some(msg),
            _ => None,
        }
    }
}

/// Type alias for an async handler function.
///
/// Handlers receive a DIDComm message and return a `RoutingResult`.
pub type HandlerFn = Arc<
    dyn Fn(DIDCommMessage) -> Pin<Box<dyn Future<Output = RoutingResult> + Send>>
        + Send
        + Sync,
>;

/// A synchronous handler function type for convenience.
pub type SyncHandlerFn = Arc<dyn Fn(DIDCommMessage) -> RoutingResult + Send + Sync>;

/// Message router that dispatches DIDComm messages to handlers by type.
///
/// The router maintains a mapping from message type URIs to handler functions.
/// When a message arrives, the router looks up the handler for its type and
/// invokes it.
pub struct Router {
    async_routes: HashMap<String, HandlerFn>,
    sync_routes: HashMap<String, SyncHandlerFn>,
}

impl Router {
    /// Create a new empty router.
    pub fn new() -> Self {
        Self {
            async_routes: HashMap::new(),
            sync_routes: HashMap::new(),
        }
    }

    /// Register an async handler for a message type.
    pub fn add_async_route(
        &mut self,
        message_type: impl Into<String>,
        handler: HandlerFn,
    ) {
        self.async_routes.insert(message_type.into(), handler);
    }

    /// Register a synchronous handler for a message type.
    pub fn add_route(
        &mut self,
        message_type: impl Into<String>,
        handler: SyncHandlerFn,
    ) {
        self.sync_routes.insert(message_type.into(), handler);
    }

    /// Route a message to the appropriate handler.
    ///
    /// Async handlers take precedence over sync handlers if both are registered
    /// for the same type. Returns `RoutingResult::NoHandler` if no handler is found.
    pub async fn route(&self, message: DIDCommMessage) -> RoutingResult {
        // Try async handler first.
        if let Some(handler) = self.async_routes.get(&message.type_) {
            return handler(message).await;
        }

        // Try sync handler.
        if let Some(handler) = self.sync_routes.get(&message.type_) {
            return handler(message);
        }

        RoutingResult::NoHandler
    }

    /// Synchronously route a message (only checks sync handlers).
    pub fn route_sync(&self, message: DIDCommMessage) -> RoutingResult {
        if let Some(handler) = self.sync_routes.get(&message.type_) {
            return handler(message);
        }

        RoutingResult::NoHandler
    }

    /// Check if a handler is registered for the given message type.
    pub fn has_handler(&self, message_type: &str) -> bool {
        self.async_routes.contains_key(message_type) || self.sync_routes.contains_key(message_type)
    }

    /// Return the number of registered routes (async + sync).
    pub fn route_count(&self) -> usize {
        self.async_routes.len() + self.sync_routes.len()
    }

    /// Return all registered message types.
    pub fn registered_types(&self) -> Vec<&str> {
        let mut types: Vec<&str> = self
            .async_routes
            .keys()
            .chain(self.sync_routes.keys())
            .map(|s| s.as_str())
            .collect();
        types.sort();
        types.dedup();
        types
    }
}

impl Default for Router {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for Router {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Router")
            .field("async_routes", &self.async_routes.keys().collect::<Vec<_>>())
            .field("sync_routes", &self.sync_routes.keys().collect::<Vec<_>>())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::protocol;
    use pretty_assertions::assert_eq;

    fn make_ping() -> DIDCommMessage {
        DIDCommMessage::trust_ping("did:trustdid:evm:1:alice", "did:trustdid:evm:1:bob")
    }

    fn make_basic(content: &str) -> DIDCommMessage {
        DIDCommMessage::builder(protocol::BASIC_MESSAGE)
            .from("did:trustdid:evm:1:alice")
            .to("did:trustdid:evm:1:bob")
            .body(serde_json::json!({ "content": content }))
            .build()
    }

    #[test]
    fn test_sync_route() {
        let mut router = Router::new();

        let handler: SyncHandlerFn = Arc::new(|msg: DIDCommMessage| {
            let pong = DIDCommMessage::trust_ping_response(
                "did:trustdid:evm:1:bob",
                "did:trustdid:evm:1:alice",
                &msg.id,
            );
            RoutingResult::Response(pong)
        });

        router.add_route(protocol::TRUST_PING, handler);

        let ping = make_ping();
        let ping_id = ping.id.clone();
        let result = router.route_sync(ping);

        match result {
            RoutingResult::Response(pong) => {
                assert_eq!(pong.type_, protocol::TRUST_PING_RESPONSE);
                assert_eq!(pong.thid.as_deref(), Some(ping_id.as_str()));
            }
            _ => panic!("expected Response"),
        }
    }

    #[test]
    fn test_no_handler() {
        let router = Router::new();
        let msg = make_basic("hello");

        let result = router.route_sync(msg);
        assert!(result.is_no_handler());
    }

    #[test]
    fn test_forward_result() {
        let mut router = Router::new();

        let handler: SyncHandlerFn = Arc::new(|msg: DIDCommMessage| {
            RoutingResult::Forward("did:trustdid:evm:1:mediator".to_string(), msg)
        });

        router.add_route(protocol::BASIC_MESSAGE, handler);

        let msg = make_basic("forward me");
        let result = router.route_sync(msg);

        match result {
            RoutingResult::Forward(target, fwd_msg) => {
                assert_eq!(target, "did:trustdid:evm:1:mediator");
                assert_eq!(fwd_msg.body["content"], "forward me");
            }
            _ => panic!("expected Forward"),
        }
    }

    #[tokio::test]
    async fn test_async_route() {
        let mut router = Router::new();

        let handler: HandlerFn = Arc::new(|msg: DIDCommMessage| {
            Box::pin(async move {
                let pong = DIDCommMessage::trust_ping_response(
                    "did:trustdid:evm:1:bob",
                    "did:trustdid:evm:1:alice",
                    &msg.id,
                );
                RoutingResult::Response(pong)
            })
        });

        router.add_async_route(protocol::TRUST_PING, handler);

        let ping = make_ping();
        let ping_id = ping.id.clone();
        let result = router.route(ping).await;

        match result {
            RoutingResult::Response(pong) => {
                assert_eq!(pong.type_, protocol::TRUST_PING_RESPONSE);
                assert_eq!(pong.thid.as_deref(), Some(ping_id.as_str()));
            }
            _ => panic!("expected Response"),
        }
    }

    #[tokio::test]
    async fn test_async_route_no_handler() {
        let router = Router::new();
        let msg = make_basic("hello");
        let result = router.route(msg).await;
        assert!(result.is_no_handler());
    }

    #[tokio::test]
    async fn test_async_route_falls_through_to_sync() {
        let mut router = Router::new();

        let handler: SyncHandlerFn = Arc::new(|msg: DIDCommMessage| {
            let response = DIDCommMessage::builder(protocol::BASIC_MESSAGE)
                .from("did:trustdid:evm:1:bob")
                .to("did:trustdid:evm:1:alice")
                .thid(msg.thread_id())
                .body(serde_json::json!({ "content": "echo" }))
                .build();
            RoutingResult::Response(response)
        });

        router.add_route(protocol::BASIC_MESSAGE, handler);

        let msg = make_basic("hello");
        let result = router.route(msg).await;
        assert!(result.is_response());
    }

    #[test]
    fn test_has_handler() {
        let mut router = Router::new();
        assert!(!router.has_handler(protocol::TRUST_PING));

        let handler: SyncHandlerFn = Arc::new(|_msg| RoutingResult::NoHandler);
        router.add_route(protocol::TRUST_PING, handler);

        assert!(router.has_handler(protocol::TRUST_PING));
        assert!(!router.has_handler(protocol::BASIC_MESSAGE));
    }

    #[test]
    fn test_route_count() {
        let mut router = Router::new();
        assert_eq!(router.route_count(), 0);

        let sync_handler: SyncHandlerFn = Arc::new(|_msg| RoutingResult::NoHandler);
        router.add_route(protocol::TRUST_PING, sync_handler);
        assert_eq!(router.route_count(), 1);

        let async_handler: HandlerFn = Arc::new(|_msg| {
            Box::pin(async { RoutingResult::NoHandler })
        });
        router.add_async_route(protocol::BASIC_MESSAGE, async_handler);
        assert_eq!(router.route_count(), 2);
    }

    #[test]
    fn test_registered_types() {
        let mut router = Router::new();

        let handler: SyncHandlerFn = Arc::new(|_msg| RoutingResult::NoHandler);
        router.add_route(protocol::TRUST_PING, handler.clone());
        router.add_route(protocol::BASIC_MESSAGE, handler);

        let types = router.registered_types();
        assert_eq!(types.len(), 2);
        assert!(types.contains(&protocol::TRUST_PING));
        assert!(types.contains(&protocol::BASIC_MESSAGE));
    }

    #[test]
    fn test_routing_result_helpers() {
        let msg = make_basic("test");

        let response = RoutingResult::Response(msg.clone());
        assert!(response.is_response());
        assert!(!response.is_forward());
        assert!(!response.is_no_handler());

        let forward = RoutingResult::Forward("did:example:target".to_string(), msg.clone());
        assert!(!forward.is_response());
        assert!(forward.is_forward());

        let no_handler = RoutingResult::NoHandler;
        assert!(no_handler.is_no_handler());
    }

    #[test]
    fn test_into_response() {
        let msg = make_basic("test");
        let result = RoutingResult::Response(msg);
        assert!(result.into_response().is_some());

        let no_handler = RoutingResult::NoHandler;
        assert!(no_handler.into_response().is_none());
    }

    #[test]
    fn test_multiple_routes() {
        let mut router = Router::new();

        let ping_handler: SyncHandlerFn = Arc::new(|msg: DIDCommMessage| {
            let pong = DIDCommMessage::trust_ping_response(
                "did:trustdid:evm:1:bob",
                "did:trustdid:evm:1:alice",
                &msg.id,
            );
            RoutingResult::Response(pong)
        });

        let basic_handler: SyncHandlerFn = Arc::new(|msg: DIDCommMessage| {
            let echo = DIDCommMessage::builder(protocol::BASIC_MESSAGE)
                .from("did:trustdid:evm:1:bob")
                .to("did:trustdid:evm:1:alice")
                .thid(msg.thread_id())
                .body(serde_json::json!({ "content": "echo" }))
                .build();
            RoutingResult::Response(echo)
        });

        router.add_route(protocol::TRUST_PING, ping_handler);
        router.add_route(protocol::BASIC_MESSAGE, basic_handler);

        // Route a ping.
        let ping = make_ping();
        let result = router.route_sync(ping);
        match &result {
            RoutingResult::Response(pong) => {
                assert_eq!(pong.type_, protocol::TRUST_PING_RESPONSE);
            }
            _ => panic!("expected ping Response"),
        }

        // Route a basic message.
        let basic = make_basic("hello");
        let result = router.route_sync(basic);
        match &result {
            RoutingResult::Response(echo) => {
                assert_eq!(echo.type_, protocol::BASIC_MESSAGE);
                assert_eq!(echo.body["content"], "echo");
            }
            _ => panic!("expected basic Response"),
        }

        // Unknown type returns NoHandler.
        let unknown = DIDCommMessage::builder("https://example.com/unknown/1.0/msg")
            .from("did:trustdid:evm:1:alice")
            .to("did:trustdid:evm:1:bob")
            .body(serde_json::json!({}))
            .build();
        let result = router.route_sync(unknown);
        assert!(result.is_no_handler());
    }

    #[test]
    fn test_router_debug() {
        let router = Router::new();
        let debug = format!("{:?}", router);
        assert!(debug.contains("Router"));
    }
}
