//! Participant-local group identity display and epoch-scoped targeting.
use crate::{Error, Member};
use std::fmt;
use zeroize::Zeroize;

/// Authenticated identity and current chat key, visible to this group's members.
pub struct Participant {
    pub member_id: String,
    pub chat_public_key: Vec<u8>,
    pub handle: ParticipantHandle,
}

/// Opaque local targeting handle. It expires on every MLS epoch change.
/// Never export this group's identifiers through operator telemetry.
#[derive(Clone)]
pub struct ParticipantHandle {
    pub(crate) group_id: Vec<u8>,
    pub(crate) epoch: u64,
    pub(crate) leaf: u32,
    pub(crate) member_id: String,
    pub(crate) chat_public_key: Vec<u8>,
}
impl fmt::Debug for Participant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Participant([redacted])")
    }
}
impl fmt::Debug for ParticipantHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ParticipantHandle([redacted])")
    }
}
impl Drop for Participant {
    fn drop(&mut self) {
        self.member_id.zeroize();
        self.chat_public_key.zeroize();
    }
}
impl Drop for ParticipantHandle {
    fn drop(&mut self) {
        self.group_id.zeroize();
        self.member_id.zeroize();
        self.chat_public_key.zeroize();
    }
}
impl Member {
    /// Display authenticated roster identities, including expired stored members.
    /// This alpha rejects duplicate member IDs; multi-device membership is separate.
    pub fn participants(&self) -> Result<Vec<Participant>, Error> {
        Err(Error::InvalidState)
    }

    /// Target the member shown by a current handle; reject stale or foreign handles.
    pub fn remove_participant(&mut self, _handle: &ParticipantHandle) -> Result<Vec<u8>, Error> {
        Err(Error::InvalidState)
    }
}
