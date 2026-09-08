//! Recipient-controlled first-contact acceptance, above the raw MLS primitive.
use crate::{Error, Member};

#[derive(Debug, PartialEq, Eq)]
pub enum Acceptance {
    Joined,
    Rejected,
    Pending,
    NeedsPermit,
    Busy,
}
#[derive(Debug, PartialEq, Eq)]
pub enum Redemption {
    Accepted,
    Rejected,
    Indeterminate,
}
pub struct Inbox;
impl Inbox {
    pub fn new(_recipient: &Member) -> Result<Self, Error> {
        Err(Error::InvalidState)
    }
    pub fn is_known(&self, _member_id: &str) -> bool {
        false
    }
    pub fn accept(
        &mut self,
        _recipient: &mut Member,
        _welcome: &[u8],
        _recipient_redemption: Option<&[u8]>,
        _wrapping_key: &[u8; 32],
        _context: &[u8],
        _persist: impl FnMut(&[u8]) -> Result<(), Error>,
        _redeem: impl FnMut(&[u8]) -> Redemption,
    ) -> Result<Acceptance, Error> {
        Err(Error::InvalidState)
    }
    pub fn restore(
        _sealed: &[u8],
        _key: &[u8; 32],
        _context: &[u8],
    ) -> Result<(Self, Member), Error> {
        Err(Error::InvalidStore)
    }
}
