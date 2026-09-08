//! Fixed-purpose account authorizations and private release preflight metadata.
//!
//! These operations do not issue receipts, debit counters, prove delivery or
//! implement recipient consent. A preflight and its signature are private peer
//! data; neither belongs in an operator authorization or telemetry payload.
use crate::{AdmissionGrant, Error, Member};
use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReleaseContext {
    pub community_id: String,
    pub policy_digest: String,
    pub cohort_id: String,
    pub not_before: u64,
    pub expires_at: u64,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReleaseAuthorizationTiming {
    pub nonce: String,
    pub expires_at: u64,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReleaseReceipt {
    pub message: String,
    pub signature: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DirectionalSendAuthorization {
    pub version: u32,
    pub purpose: String,
    pub community_id: String,
    pub policy_digest: String,
    pub cohort_id: String,
    pub sender_id: String,
    pub request_hash: String,
    pub nonce: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub signature: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DirectionalReceiveAuthorization {
    pub version: u32,
    pub purpose: String,
    pub community_id: String,
    pub policy_digest: String,
    pub cohort_id: String,
    pub member_id: String,
    pub receipt_hash: String,
    pub nonce: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub signature: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReleasePeer {
    pub member_id: String,
    pub chat_public_key: String,
}

/// Signed peer/challenge metadata, not a certification of withheld MLS contents.
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReleasePreflight {
    pub version: u32,
    pub context: ReleaseContext,
    pub sender: ReleasePeer,
    pub recipient: ReleasePeer,
    pub release_nonce: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub signature: String,
}

impl Member {
    /// Authorize only our current certified account, hashing the actual blinded
    /// request locally. The caller must retain an independently generated nonce.
    pub fn authorize_release_send(
        &self,
        _context: &ReleaseContext,
        _blinded_request: &[u8],
        _timing: &ReleaseAuthorizationTiming,
    ) -> Result<DirectionalSendAuthorization, Error> {
        Err(Error::Admission)
    }

    /// Authorize a canonical 160-byte release receipt for our own identity and
    /// expected private challenge. The cfrm service must verify its blind RSA
    /// signature/domain; these client checks do not establish receipt validity.
    pub fn authorize_release_receive(
        &self,
        _context: &ReleaseContext,
        _receipt: &ReleaseReceipt,
        _expected_release_nonce: &str,
        _timing: &ReleaseAuthorizationTiming,
    ) -> Result<DirectionalReceiveAuthorization, Error> {
        Err(Error::Admission)
    }

    /// Authenticate private metadata using current cvld credentials for both
    /// peers. This is not a recipient consent or content validity decision.
    pub fn sign_release_preflight(
        &self,
        _context: &ReleaseContext,
        _recipient_admission: &AdmissionGrant,
        _release_nonce: &str,
        _expires_at: u64,
    ) -> Result<ReleasePreflight, Error> {
        Err(Error::Admission)
    }

    /// Verify private preflight addressed to our current certified ID and key.
    pub fn verify_release_preflight(
        &self,
        _preflight: &ReleasePreflight,
        _sender_admission: &AdmissionGrant,
    ) -> Result<(), Error> {
        Err(Error::Admission)
    }
}
