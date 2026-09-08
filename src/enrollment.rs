//! Certified-key authorization for cfrm's immutable Semaphore enrollment.
//! Semaphore identity derivation, curve validation and the second possession proof stay in cfrm.
use crate::{Error, Member};
use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SemaphoreEnrollmentChallenge {
    pub community_id: String,
    pub member_id: String,
    pub chat_public_key: String,
    pub commitment: String,
    pub challenge_id: String,
    pub issued_at: u64,
    pub expires_at: u64,
}

impl Member {
    /// Sign the fixed cfrm enrollment statement using the currently admitted chat key.
    /// The trusted client must independently obtain `expected_wallet_commitment` from
    /// its persistent wallet identity, never copy it from the server challenge unnoticed.
    /// This signature does not prove Semaphore-key possession or register a binding.
    pub fn sign_semaphore_enrollment(
        &self,
        _challenge: &SemaphoreEnrollmentChallenge,
        _expected_wallet_commitment: &str,
    ) -> Result<String, Error> {
        // Pending implementation: the hosted behavioral contract must fail first.
        Err(Error::Admission)
    }
}
