//! Isolated first-contact release experiment; no network or operator ledger.
use serde::{Deserialize, Serialize};

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Context {
    pub community_id: String,
    pub policy_digest: String,
    pub cohort_id: String,
    pub not_before: u64,
    pub expires_at: u64,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Peer {
    pub member_id: String,
    pub chat_public_key: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SenderCommit {
    pub context: Context,
    pub sender: Peer,
    pub authorization_nonce: String,
    pub blinded_request_hash: String,
    pub signature: String,
}

impl SenderCommit {
    /// Fixed statement encoding, never a signature or private-key export.
    pub fn signing_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!([
            "cfrm.directional.commit.v1",
            self.context.community_id,
            self.context.policy_digest,
            self.context.cohort_id,
            self.sender.member_id,
            self.sender.chat_public_key,
            self.authorization_nonce,
            self.blinded_request_hash,
            self.context.not_before,
            self.context.expires_at,
        ]))
        .expect("fixed serializable statement")
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RecipientRedemption {
    pub context: Context,
    pub recipient: Peer,
    pub release_nonce: String,
    pub signature: String,
}

impl RecipientRedemption {
    pub fn signing_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!([
            "cfrm.directional.redemption.v1",
            self.context.community_id,
            self.context.policy_digest,
            self.context.cohort_id,
            self.recipient.member_id,
            self.recipient.chat_public_key,
            self.release_nonce,
            self.context.not_before,
            self.context.expires_at,
        ]))
        .expect("fixed serializable statement")
    }
}

/// Trusted common operator keys with deliberately separate signing purposes.
pub struct OperatorTrust {
    pub sender_commit_key: [u8; 32],
    pub recipient_redemption_key: [u8; 32],
}

/// Private peer-to-peer metadata. This is not an authenticated preflight API.
#[derive(Clone)]
pub struct Preflight {
    pub context: Context,
    pub sender: Peer,
    pub recipient: Peer,
    pub release_nonce: String,
}

#[derive(Clone, PartialEq, Eq)]
pub struct ReleasedMaterial {
    pub welcome: Vec<u8>,
    pub first_ciphertext: Vec<u8>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    InvalidInput,
    InvalidAttestation,
    InvalidStore,
    Declined,
    Expired,
}

/// Owns the exact withheld MLS input. No public accessor exposes that input.
pub struct PendingRelease;

impl PendingRelease {
    pub fn prepare(
        _context: Context,
        _sender: Peer,
        _recipient: Peer,
        _material: ReleasedMaterial,
        _now: u64,
    ) -> Result<Self, Error> {
        Err(Error::InvalidInput)
    }

    pub fn preflight(&self) -> Preflight {
        unimplemented!("fail-first preflight")
    }

    /// Bind one blind request after the recipient sees the private release nonce.
    pub fn bind_request(&mut self, _request_hash: &str) -> Result<SenderCommit, Error> {
        Err(Error::InvalidInput)
    }

    pub fn release(
        &mut self,
        _sender_commit: &SenderCommit,
        _recipient_redemption: &RecipientRedemption,
        _trust: &OperatorTrust,
        _now: u64,
    ) -> Result<ReleasedMaterial, Error> {
        Err(Error::InvalidAttestation)
    }

    pub fn decline(&mut self) {}

    pub fn seal(&self, _key: &[u8; 32]) -> Result<Vec<u8>, Error> {
        Err(Error::InvalidStore)
    }

    pub fn restore(
        _sealed: &[u8],
        _key: &[u8; 32],
        _expected_context: &Context,
    ) -> Result<Self, Error> {
        Err(Error::InvalidStore)
    }
}
