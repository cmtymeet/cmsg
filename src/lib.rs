//! Experimental client-side MLS text messaging. No server holds content keys.
//!
//! This crate is a cryptographic/transport component, not admission enforcement.
//! Applications must verify cvld eligibility and cfrm capabilities before invoking
//! it. No public API claims those independent proofs have been checked.
mod admission;
mod member;
mod transport;

pub use admission::{AdmissionGrant, AdmissionTrust, verify_admission};
pub use member::{Invitation, Member, Received};
pub use transport::{OnionEndpoint, OnionTransport};

/// Maximum application text length in UTF-8 bytes, not characters.
pub const MAX_TEXT_BYTES: usize = 16 * 1024;
/// Bound untrusted serialized MLS objects before parsing.
pub const MAX_WIRE_BYTES: usize = 1024 * 1024;

/// Deliberately coarse errors: never include keys, plaintext or peer identifiers.
#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    InvalidText,
    Admission,
    InvalidMessage,
    InvalidState,
    InvalidStore,
    InvalidRoute,
    Transport,
    Randomness,
}

/// Interpret text literally. This function performs no markup parsing or I/O.
pub fn validate_text(text: &[u8]) -> Result<&str, Error> {
    if text.is_empty() || text.len() > MAX_TEXT_BYTES {
        return Err(Error::InvalidText);
    }
    std::str::from_utf8(text).map_err(|_| Error::InvalidText)
}
