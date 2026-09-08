//! Deterministic authorization time and same-key credential renewal boundary.
use crate::{AdmissionGrant, Error, Member};
use std::sync::Arc;

/// Trusted client time source. Never accept protocol-supplied time as this clock.
/// The source is process state, not part of an encrypted snapshot.
pub trait Clock: Send + Sync {
    fn now(&self) -> Result<u64, Error>;
}

impl Member {
    pub fn new_with_clock(_clock: Arc<dyn Clock>) -> Result<Self, Error> {
        // Fail-first specification; the normal constructor is unchanged.
        Err(Error::InvalidState)
    }

    pub fn restore_with_clock(
        _sealed: &[u8],
        _wrapping_key: &[u8; 32],
        _context: &[u8],
        _clock: Arc<dyn Clock>,
    ) -> Result<Self, Error> {
        Err(Error::InvalidState)
    }

    /// Renew an existing group's certificate without changing identity or signer.
    /// The callback must durably persist the candidate before its commit is returned.
    /// A failure keeps the original local certificate and ratchet state.
    pub fn renew_admission(
        &mut self,
        _grant: AdmissionGrant,
        _persist: impl FnOnce(&Member) -> Result<(), Error>,
    ) -> Result<Vec<u8>, Error> {
        Err(Error::Admission)
    }

    /// Catch up only on authenticated MLS control, even after local expiry.
    /// This method never exposes application text or adds it to local history.
    pub fn receive_control(&mut self, _wire: &[u8]) -> Result<(), Error> {
        Err(Error::Admission)
    }
}
