use crate::Error;
use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AdmissionGrant {
    pub version: u32,
    pub issuer_key_id: String,
    pub community_id: String,
    pub member_id: String,
    pub chat_public_key: String,
    pub policy_digest: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub signature: String,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct AdmissionTrust {
    pub community_id: String,
    pub policy_digest: String,
    pub issuer_public_key: [u8;32],
}
pub fn verify_admission(_grant: &AdmissionGrant, _trust: &AdmissionTrust, _chat_key: &[u8], _now: u64) -> Result<String, Error> {
    Err(Error::Admission)
}
