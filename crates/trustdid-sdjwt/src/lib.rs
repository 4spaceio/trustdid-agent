//! SD-JWT (RFC 9901) selective disclosure for TrustDID.
//!
//! This crate implements the SD-JWT specification, allowing issuers to create
//! JWTs with selectively disclosable claims, holders to choose which claims
//! to reveal, and verifiers to reconstruct the disclosed claim set.
//!
//! # Architecture
//!
//! The SD-JWT flow involves three parties:
//!
//! 1. **Issuer** (`SdJwtIssuer`): Creates an SD-JWT from a set of claims,
//!    replacing specified claims with SHA-256 digests in the `_sd` array.
//! 2. **Holder** (`SdJwtHolder`): Receives the full SD-JWT and selectively
//!    presents only desired disclosures to a verifier.
//! 3. **Verifier** (`SdJwtVerifier`): Validates the presented SD-JWT by
//!    matching disclosure digests against the `_sd` array and reconstructing
//!    the disclosed claims.
//!
//! # Example
//!
//! ```rust
//! use trustdid_sdjwt::{SdJwtIssuer, SdJwtHolder, SdJwtVerifier};
//!
//! let issuer = SdJwtIssuer::new("did:example:issuer");
//! let claims = serde_json::json!({
//!     "sub": "did:example:holder",
//!     "given_name": "Alice",
//!     "email": "alice@example.com"
//! });
//!
//! // Issue an SD-JWT with given_name and email as selectively disclosable.
//! let sd_jwt = issuer.issue(
//!     claims,
//!     &["given_name".to_string(), "email".to_string()],
//! ).unwrap();
//!
//! // Holder presents only given_name.
//! let holder = SdJwtHolder::new();
//! let presented = holder.present(&sd_jwt, &["given_name".to_string()]).unwrap();
//!
//! // Verifier reconstructs the disclosed claims.
//! let verifier = SdJwtVerifier::new();
//! let verified = verifier.verify(&presented).unwrap();
//!
//! assert_eq!(verified.claims["given_name"], "Alice");
//! assert!(!verified.claims.contains_key("email"));
//! ```

pub mod disclosure;
pub mod holder;
pub mod issuer;
pub mod types;
pub mod verifier;

pub use disclosure::Disclosure;
pub use holder::SdJwtHolder;
pub use issuer::SdJwtIssuer;
pub use types::{SdJwt, SdJwtError, VerifiedClaims};
pub use verifier::SdJwtVerifier;
