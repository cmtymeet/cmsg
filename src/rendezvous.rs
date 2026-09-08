use crate::{Error, Member};
use serde::{Deserialize, Serialize};

/// The cfrm rendezvous challenge is an exact, domain-separated signing request.
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RendezvousEndpoint {
    pub host: String,
    pub port: u16,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RendezvousChallenge {
    pub community_id: String,
    pub member_id: String,
    pub chat_public_key: String,
    pub endpoint: RendezvousEndpoint,
    pub challenge_id: String,
    pub issued_at: u64,
    pub expires_at: u64,
}
impl Member {
    pub fn sign_rendezvous(
        &self,
        _challenge: &RendezvousChallenge,
        _now: u64,
    ) -> Result<String, Error> {
        Err(Error::Admission)
    }
}
