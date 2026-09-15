//! Recipient-controlled first-contact acceptance, above the raw MLS primitive.
use crate::{Clock, ContactResolution, ContactResolutionKind, Error, Member, Received, MAX_WIRE_BYTES};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use zeroize::{Zeroize, Zeroizing};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ContactSync {
    community_id: String,
    owner_id: String,
    issued_at: u64,
    device_public_key: Vec<u8>,
    credential: Vec<u8>,
    known: BTreeSet<String>,
    closed: BTreeSet<String>,
    introductions: BTreeMap<String, Introduction>,
    signature: Vec<u8>,
}

impl ContactSync {
    fn signing_bytes(&self) -> Result<Vec<u8>, Error> {
        serde_json::to_vec(&serde_json::json!([
            "cmsg.contact-sync.v1", self.community_id, self.owner_id,
            self.issued_at, self.device_public_key, self.credential, self.known,
            self.closed, self.introductions,
        ])).map_err(|_| Error::InvalidMessage)
    }
}

impl Drop for ContactSync {
    fn drop(&mut self) {
        self.community_id.zeroize();
        self.owner_id.zeroize();
        self.credential.zeroize();
        for mut value in std::mem::take(&mut self.known) {
            value.zeroize();
        }
        for mut value in std::mem::take(&mut self.closed) {
            value.zeroize();
        }
        for (mut peer, _) in std::mem::take(&mut self.introductions) {
            peer.zeroize();
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Acceptance {
    Joined,
    Rejected,
    Pending,
    NeedsPermit,
    Busy,
    Blocked,
}
/// Results from the trusted, anonymously connected cfrm redemption adapter.
#[derive(Debug, PartialEq, Eq)]
pub enum Redemption {
    Accepted,
    Rejected,
    Indeterminate,
}

pub struct Inbox {
    state: InboxState,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct InboxState {
    community_id: String,
    recipient_id: String,
    root_authorized: bool,
    known: BTreeSet<String>,
    #[serde(default)]
    blocked: BTreeSet<String>,
    /// Permanent identity-level tombstones. This set can only grow.
    closed: BTreeSet<String>,
    introductions: BTreeMap<String, Introduction>,
    pending: Option<Pending>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Introduction {
    id: [u8; 32],
    decision: Option<ContactResolutionKind>,
    outbound_receipt: Option<Vec<u8>>,
}

impl Drop for Introduction {
    fn drop(&mut self) {
        self.id.zeroize();
        if let Some(bytes) = &mut self.outbound_receipt {
            bytes.zeroize();
        }
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Pending {
    welcome: Vec<u8>,
    inviter: String,
    welcome_hash: [u8; 32],
    recipient_redemption: Vec<u8>,
}
impl Drop for Pending {
    fn drop(&mut self) {
        self.recipient_redemption.zeroize();
        self.welcome.zeroize();
        self.inviter.zeroize();
    }
}
impl Drop for InboxState {
    fn drop(&mut self) {
        self.community_id.zeroize();
        self.recipient_id.zeroize();
        for mut value in std::mem::take(&mut self.known) {
            value.zeroize();
        }
        for mut value in std::mem::take(&mut self.blocked) {
            value.zeroize();
        }
        for mut value in std::mem::take(&mut self.closed) {
            value.zeroize();
        }
        for (mut peer, _) in std::mem::take(&mut self.introductions) {
            peer.zeroize();
        }
    }
}
impl Inbox {
    pub fn new(recipient: &Member) -> Result<Self, Error> {
        Ok(Self {
            state: InboxState {
                community_id: recipient
                    .trust
                    .as_ref()
                    .ok_or(Error::Admission)?
                    .community_id
                    .clone(),
                recipient_id: recipient.member_id()?,
                root_authorized: recipient.device_authorization()?.is_some(),
                known: BTreeSet::new(),
                blocked: BTreeSet::new(),
                closed: BTreeSet::new(),
                introductions: BTreeMap::new(),
                pending: None,
            },
        })
    }
    fn duplicate(&self) -> Self {
        Self {
            state: self.state.clone(),
        }
    }

    pub fn is_known(&self, member_id: &str) -> bool {
        self.state.known.contains(member_id)
    }
    /// Private local recovery data; never include this in operator telemetry.
    pub fn pending_welcome(&self) -> Option<&[u8]> {
        self.state.pending.as_ref().map(|p| p.welcome.as_slice())
    }

    /// Accept an invitation only after the recipient enforces first-contact rules.
    ///
    /// `recipient_redemption` MUST come from the trusted recipient-side cfrm
    /// prepareRedemption adapter. Never take a retry claim supplied by the sender.
    /// Only the permit is sent by the inviter; the recipient adds fresh private
    /// randomness. The redemption callback receives those opaque bytes alone.
    ///
    /// `persist` must return Ok only after an atomic, durable local write of the
    /// supplied encrypted checkpoint. The first write precedes external spending;
    /// the last precedes exposing joined state. This callback contract cannot prove
    /// storage freshness or prevent an application from restoring an older file.
    ///
    /// Keep retries bounded in the application. Pending means retain/retry the
    /// exact checkpoint, not mint a new claim or treat a timeout as rejection.
    #[allow(clippy::too_many_arguments)]
    pub fn accept(
        &mut self,
        recipient: &mut Member,
        welcome: &[u8],
        recipient_redemption: Option<&[u8]>,
        wrapping_key: &[u8; 32],
        context: &[u8],
        mut persist: impl FnMut(&[u8]) -> Result<(), Error>,
        mut redeem: impl FnMut(&[u8]) -> Redemption,
    ) -> Result<Acceptance, Error> {
        self.check_binding(recipient)?;
        if welcome.len() > MAX_WIRE_BYTES {
            return Err(Error::InvalidMessage);
        }
        // Verify the entire invitation and the actual Welcome signer before any
        // persistence or debit. Merely possessing a public certificate is not enough.
        let prepared = recipient.prepare_join(welcome)?;
        let inviter = prepared.inviter.clone();
        let excluded = self.excluded();
        if prepared.contains_any(
            &excluded,
            recipient.trust.as_ref().ok_or(Error::Admission)?,
            recipient.authorization_time()?,
        )? {
            return Ok(Acceptance::Blocked);
        }
        let hash: [u8; 32] = Sha256::digest(welcome).into();
        if let Some(pending) = &self.state.pending {
            if pending.welcome_hash != hash
                || recipient_redemption.is_some_and(|bytes| bytes != pending.recipient_redemption)
            {
                return Ok(Acceptance::Busy);
            }
        }
        let known = inviter == self.state.recipient_id || self.state.known.contains(&inviter);
        if !known && self.state.pending.is_none() {
            let Some(attempt) = recipient_redemption else {
                return Ok(Acceptance::NeedsPermit);
            };
            if attempt.is_empty() || attempt.len() > 8192 {
                return Err(Error::InvalidMessage);
            }
            self.state.pending = Some(Pending {
                welcome: welcome.to_vec(),
                inviter: inviter.clone(),
                welcome_hash: hash,
                recipient_redemption: attempt.to_vec(),
            });
        }
        if !known {
            // Re-persist on retry too: an interrupted previous local write must
            // never authorize a first external spend without durable intent.
            persist(&self.seal(recipient, wrapping_key, context)?)?;
            match redeem(
                &self
                    .state
                    .pending
                    .as_ref()
                    .ok_or(Error::InvalidState)?
                    .recipient_redemption,
            ) {
                Redemption::Indeterminate => return Ok(Acceptance::Pending),
                Redemption::Rejected => {
                    let mut cleared = self.duplicate();
                    cleared.state.pending = None;
                    match persist(&cleared.seal(recipient, wrapping_key, context)?) {
                        Ok(()) => {
                            *self = cleared;
                            return Ok(Acceptance::Rejected);
                        }
                        Err(_) => return Ok(Acceptance::Pending),
                    }
                }
                Redemption::Accepted => (),
            }
        }
        let mut committed = self.duplicate();
        if inviter != self.state.recipient_id {
            committed.state.known.insert(inviter);
        }
        committed.state.pending = None;
        // The candidate ratchet and contact book form one encrypted checkpoint.
        // commit_join rolls back in-memory MLS state if the final write fails.
        if recipient
            .commit_join(prepared, |joined| {
                persist(&committed.seal(joined, wrapping_key, context)?)
            })
            .is_err()
        {
            return if known {
                Err(Error::InvalidStore)
            } else {
                Ok(Acceptance::Pending)
            };
        }
        *self = committed;
        Ok(Acceptance::Joined)
    }
    /// Locally discard an unresolved invitation after durably clearing it. A spent
    /// permit is forfeited; cancellation never refunds allowance or calls cfrm.
    pub fn cancel_pending(
        &mut self,
        recipient: &Member,
        key: &[u8; 32],
        context: &[u8],
        mut persist: impl FnMut(&[u8]) -> Result<(), Error>,
    ) -> Result<(), Error> {
        self.check_binding(recipient)?;
        let mut cleared = self.duplicate();
        cleared.state.pending = None;
        persist(&cleared.seal(recipient, key, context)?)?;
        *self = cleared;
        Ok(())
    }
    /// Private stable-ID invitation blocking, including previously known contacts.
    /// Use Inbox::send/receive for existing conversations too. Raw Member methods
    /// intentionally remain low-level MLS primitives with no contact policy.
    #[allow(clippy::too_many_arguments)]
    pub fn set_blocked(
        &mut self,
        member_id: &str,
        blocked: bool,
        recipient: &Member,
        key: &[u8; 32],
        context: &[u8],
        mut persist: impl FnMut(&[u8]) -> Result<(), Error>,
    ) -> Result<(), Error> {
        self.check_binding(recipient)?;
        if !crate::admission::valid_member_id(member_id)
            || member_id == self.state.recipient_id
        {
            return Err(Error::Admission);
        }
        let mut changed = self.duplicate();
        if blocked {
            changed.state.blocked.insert(member_id.to_owned());
            if changed
                .state
                .pending
                .as_ref()
                .is_some_and(|p| p.inviter == member_id)
            {
                changed.state.pending = None;
            }
        } else {
            changed.state.blocked.remove(member_id);
        }
        persist(&changed.seal(recipient, key, context)?)?;
        *self = changed;
        Ok(())
    }
    pub fn is_blocked(&self, member_id: &str) -> bool {
        self.state.blocked.contains(member_id) || self.is_closed(member_id)
    }

    /// Permanently refuse this community member across threads and device keys.
    /// Clearing a temporary block never clears this tombstone. The transaction
    /// does not send a notification or prove anything to an accounting service.
    /// Sync the tombstone with every other device before that device reconnects.
    pub fn close_forever(
        &mut self,
        member_id: &str,
        recipient: &Member,
        key: &[u8; 32],
        context: &[u8],
        mut persist: impl FnMut(&[u8]) -> Result<(), Error>,
    ) -> Result<(), Error> {
        self.check_binding(recipient)?;
        if !crate::admission::valid_member_id(member_id)
            || member_id == self.state.recipient_id
        {
            return Err(Error::Admission);
        }
        let mut changed = self.duplicate();
        changed.state.closed.insert(member_id.to_owned());
        if changed.state.pending.as_ref().is_some_and(|p| p.inviter == member_id) {
            changed.state.pending = None;
        }
        persist(&changed.seal(recipient, key, context)?)?;
        *self = changed;
        Ok(())
    }

    pub fn is_closed(&self, member_id: &str) -> bool {
        self.state.closed.contains(member_id)
    }

    /// Register the shared, unpredictable first-introduction ID after peer
    /// authentication. A second thread cannot replace a member's unresolved
    /// introduction. The policy adapter controls when registration is authorized.
    #[allow(clippy::too_many_arguments)]
    pub fn begin_introduction(
        &mut self,
        peer_id: &str,
        introduction_id: &[u8; 32],
        member: &Member,
        key: &[u8; 32],
        context: &[u8],
        mut persist: impl FnMut(&[u8]) -> Result<(), Error>,
    ) -> Result<(), Error> {
        self.check_binding(member)?;
        if !crate::admission::valid_member_id(peer_id)
            || peer_id == self.state.recipient_id || self.is_blocked(peer_id)
        {
            return Err(Error::Admission);
        }
        if let Some(existing) = self.state.introductions.get(peer_id) {
            return if existing.id == *introduction_id { Ok(()) } else { Err(Error::InvalidState) };
        }
        let mut changed = self.duplicate();
        changed.state.introductions.insert(peer_id.to_owned(), Introduction {
            id: *introduction_id, decision: None, outbound_receipt: None,
        });
        persist(&changed.seal(member, key, context)?)?;
        *self = changed;
        Ok(())
    }

    pub fn needs_resolution(&self, peer_id: &str) -> bool {
        !self.is_closed(peer_id) && self.state.introductions.get(peer_id)
            .is_some_and(|intro| intro.decision.is_none())
    }

    /// Commit a local decision and its exact signed outbound receipt atomically.
    /// Answered is a protocol declaration; the embedding application must pair
    /// it with the actual answer. No receipt establishes sincere participation.
    /// ClosedForever also commits the permanent member-level exclusion.
    #[allow(clippy::too_many_arguments)]
    pub fn resolve_introduction(
        &mut self,
        peer_id: &str,
        kind: ContactResolutionKind,
        member: &Member,
        key: &[u8; 32],
        context: &[u8],
        mut persist: impl FnMut(&[u8]) -> Result<(), Error>,
    ) -> Result<Vec<u8>, Error> {
        self.check_binding(member)?;
        let existing = self.state.introductions.get(peer_id).ok_or(Error::InvalidState)?;
        if kind == ContactResolutionKind::Answered && self.is_closed(peer_id) {
            return Err(Error::Admission);
        }
        if let Some(decision) = existing.decision {
            return if decision == kind {
                existing.outbound_receipt.clone().ok_or(Error::InvalidState)
            } else {
                Err(Error::InvalidState)
            };
        }
        let receipt = member.sign_contact_resolution(peer_id, &existing.id, kind)?;
        let encoded = serde_json::to_vec(&receipt).map_err(|_| Error::InvalidMessage)?;
        let mut changed = self.duplicate();
        let entry = changed.state.introductions.get_mut(peer_id).ok_or(Error::InvalidState)?;
        entry.decision = Some(kind);
        entry.outbound_receipt = Some(encoded.clone());
        if kind == ContactResolutionKind::ClosedForever {
            changed.state.closed.insert(peer_id.to_owned());
            if changed.state.pending.as_ref().is_some_and(|pending| pending.inviter == peer_id) {
                changed.state.pending = None;
            }
        }
        persist(&changed.seal(member, key, context)?)?;
        *self = changed;
        Ok(encoded)
    }

    /// Apply the peer's signed decision once for the locally registered nonce.
    /// Returns false for an exact already-applied decision. Replays cannot create
    /// another local transition; contradictory or unrelated receipts fail closed.
    pub fn apply_resolution(
        &mut self,
        receipt: &ContactResolution,
        member: &Member,
        key: &[u8; 32],
        context: &[u8],
        mut persist: impl FnMut(&[u8]) -> Result<(), Error>,
    ) -> Result<bool, Error> {
        self.check_binding(member)?;
        let peer_id = &receipt.responder_id;
        let existing = self.state.introductions.get(peer_id).ok_or(Error::InvalidState)?;
        member.verify_contact_resolution(receipt, peer_id, &existing.id)?;
        if let Some(decision) = existing.decision {
            return if decision == receipt.kind { Ok(false) } else { Err(Error::InvalidState) };
        }
        if receipt.kind == ContactResolutionKind::Answered && self.is_closed(peer_id) {
            return Err(Error::Admission);
        }
        let mut changed = self.duplicate();
        changed.state.introductions.get_mut(peer_id).ok_or(Error::InvalidState)?.decision = Some(receipt.kind);
        if receipt.kind == ContactResolutionKind::ClosedForever {
            changed.state.closed.insert(peer_id.clone());
            if changed.state.pending.as_ref().is_some_and(|pending| &pending.inviter == peer_id) {
                changed.state.pending = None;
            }
        }
        persist(&changed.seal(member, key, context)?)?;
        *self = changed;
        Ok(true)
    }

    /// Private device-sync payload. It discloses contacts: carry it only inside
    /// an encrypted channel authenticated to another device of this same member.
    /// Member-controlled root authorization is required; an eligibility issuer's
    /// assertion alone cannot authorize a second device to modify this policy.
    pub fn export_contact_sync(&self, member: &Member) -> Result<Vec<u8>, Error> {
        use openmls_traits::signatures::Signer;
        self.check_binding(member)?;
        member.member_id()?;
        if member.device_authorization()?.is_none() {
            return Err(Error::Admission);
        }
        let mut sync = ContactSync {
            community_id: self.state.community_id.clone(),
            owner_id: self.state.recipient_id.clone(),
            issued_at: member.authorization_time()?,
            device_public_key: member.chat_public_key(),
            credential: member.private_identity_credential()?,
            known: self.state.known.clone(),
            closed: self.state.closed.clone(),
            introductions: self.state.introductions.clone(),
            signature: Vec::new(),
        };
        sync.signature = member.signer.sign(&Zeroizing::new(sync.signing_bytes()?))
            .map_err(|_| Error::Admission)?;
        let encoded = serde_json::to_vec(&sync).map_err(|_| Error::InvalidMessage)?;
        if encoded.len() > MAX_WIRE_BYTES {
            return Err(Error::InvalidMessage);
        }
        Ok(encoded)
    }

    /// Merge authenticated contacts and permanent closures by set union. A stale
    /// journal cannot erase a decision. Conflicting introduction nonces fail
    /// closed for explicit endpoint reconciliation. Replayed or stale device
    /// snapshots cannot remove a closure already known locally. This does
    /// not protect a device whose entire local store and all peers are rolled back.
    /// The host must persist before acknowledging synchronization to the peer.
    pub fn merge_contact_sync(
        &mut self,
        payload: &[u8],
        member: &Member,
        key: &[u8; 32],
        context: &[u8],
        mut persist: impl FnMut(&[u8]) -> Result<(), Error>,
    ) -> Result<(), Error> {
        use ed25519_dalek::{Signature, VerifyingKey};
        self.check_binding(member)?;
        if payload.len() > MAX_WIRE_BYTES || member.device_authorization()?.is_none() {
            return Err(Error::Admission);
        }
        let sync: ContactSync = serde_json::from_slice(payload).map_err(|_| Error::InvalidMessage)?;
        let now = member.authorization_time()?;
        if sync.community_id != self.state.community_id
            || sync.owner_id != self.state.recipient_id
            || sync.issued_at == 0 || sync.issued_at > now
            || sync.closed.iter().chain(&sync.known).chain(sync.introductions.keys())
                .any(|id| !crate::admission::valid_member_id(id) || id == &sync.owner_id)
            || member.verify_private_identity_credential(&sync.credential, &sync.device_public_key, now)? != sync.owner_id
        {
            return Err(Error::Admission);
        }
        let public: [u8; 32] = sync.device_public_key.as_slice().try_into().map_err(|_| Error::Admission)?;
        VerifyingKey::from_bytes(&public).map_err(|_| Error::Admission)?.verify_strict(
            &Zeroizing::new(sync.signing_bytes()?),
            &Signature::from_slice(&sync.signature).map_err(|_| Error::Admission)?,
        ).map_err(|_| Error::Admission)?;
        let mut changed = self.duplicate();
        changed.state.known.extend(sync.known.iter().cloned());
        changed.state.closed.extend(sync.closed.iter().cloned());
        for (peer, incoming) in &sync.introductions {
            if let Some(existing) = changed.state.introductions.get_mut(peer) {
                if existing.id != incoming.id {
                    return Err(Error::InvalidState);
                }
                match (existing.decision, incoming.decision) {
                    (None, Some(_)) => *existing = incoming.clone(),
                    (Some(ContactResolutionKind::Answered), Some(ContactResolutionKind::ClosedForever)) => {
                        *existing = incoming.clone();
                    }
                    _ => (),
                }
            } else {
                changed.state.introductions.insert(peer.clone(), incoming.clone());
            }
        }
        if changed.state.pending.as_ref().is_some_and(|p| changed.is_closed(&p.inviter)) {
            changed.state.pending = None;
        }
        changed.validate_state(member)?;
        persist(&changed.seal(member, key, context)?)?;
        *self = changed;
        Ok(())
    }

    fn excluded(&self) -> BTreeSet<String> {
        self.state.blocked.union(&self.state.closed).cloned().collect()
    }

    /// Enforce local contact exclusions before encrypting any new text. A group
    /// containing a closed member must remove that member before further sends.
    pub fn send(&self, member: &mut Member, text: &[u8]) -> Result<Vec<u8>, Error> {
        self.check_outbound(member)?;
        member.send(text)
    }

    pub fn send_bytes(&self, member: &mut Member, bytes: &[u8]) -> Result<Vec<u8>, Error> {
        self.check_outbound(member)?;
        member.send_bytes(bytes)
    }

    fn check_outbound(&self, member: &Member) -> Result<(), Error> {
        self.check_binding(member)?;
        if member.participants()?.iter().any(|p| self.is_blocked(&p.member_id)) {
            return Err(Error::Admission);
        }
        Ok(())
    }

    /// Validate a candidate conversation roster before publishing an invitation
    /// or a locally staged membership update. Hosts stage such mutations in an
    /// isolated checkpoint, check here, then durably commit before transmitting.
    pub fn check_group(&self, member: &Member) -> Result<(), Error> {
        self.check_outbound(member)
    }

    /// Reject excluded authenticated senders before publishing plaintext,
    /// changing receive ratchets, or appending history. A control message cannot
    /// silently reintroduce a closed identity under a different device key.
    pub fn receive(&self, member: &mut Member, wire: &[u8]) -> Result<Received, Error> {
        self.check_binding(member)?;
        member.receive_excluding(wire, &self.excluded())
    }

    fn check_binding(&self, recipient: &Member) -> Result<(), Error> {
        if self.state.recipient_id != recipient.stored_member_id()?
            || self.state.root_authorized != recipient.device_authorization()?.is_some()
            || self.state.community_id
                != recipient
                    .trust
                    .as_ref()
                    .ok_or(Error::Admission)?
                    .community_id
        {
            return Err(Error::Admission);
        }
        Ok(())
    }

    fn validate_state(&self, member: &Member) -> Result<(), Error> {
        self.check_binding(member)?;
        if self.state.known.iter().chain(&self.state.blocked).chain(&self.state.closed)
            .any(|id| !crate::admission::valid_member_id(id) || id == &self.state.recipient_id)
        {
            return Err(Error::InvalidStore);
        }
        for (peer, introduction) in &self.state.introductions {
            if !crate::admission::valid_member_id(peer) || peer == &self.state.recipient_id
                || (introduction.decision == Some(ContactResolutionKind::ClosedForever) && !self.is_closed(peer))
                || (introduction.decision.is_none() && introduction.outbound_receipt.is_some())
            {
                return Err(Error::InvalidStore);
            }
            if let Some(bytes) = &introduction.outbound_receipt {
                if bytes.len() > 16 * 1024 {
                    return Err(Error::InvalidStore);
                }
                let receipt: ContactResolution = serde_json::from_slice(bytes).map_err(|_| Error::InvalidStore)?;
                if receipt.responder_id != self.state.recipient_id || &receipt.peer_id != peer
                    || receipt.introduction_id != introduction.id || Some(receipt.kind) != introduction.decision
                    || receipt.community_id != self.state.community_id
                    || receipt.issued_at == 0 || receipt.issued_at > member.authorization_time()?
                {
                    return Err(Error::InvalidStore);
                }
                receipt.verify_device_signature(member, receipt.issued_at).map_err(|_| Error::InvalidStore)?;
            }
        }
        if let Some(pending) = &self.state.pending {
            if self.is_blocked(&pending.inviter)
                || self.is_known(&pending.inviter)
                || !crate::admission::valid_member_id(&pending.inviter)
                || pending.recipient_redemption.is_empty()
                || pending.recipient_redemption.len() > 8192
                || pending.welcome.is_empty()
                || pending.welcome.len() > MAX_WIRE_BYTES
                || <[u8; 32]>::from(Sha256::digest(&pending.welcome)) != pending.welcome_hash
            {
                return Err(Error::InvalidStore);
            }
            // Authenticate pending bindings at restore without requiring old
            // admission to remain unexpired. accept rechecks current admission
            // before any spending, while expired pending data can be cancelled.
            let prepared = member.prepare_stored_join(&pending.welcome).map_err(|_| Error::InvalidStore)?;
            if prepared.inviter != pending.inviter || prepared.contains_any(
                &self.excluded(), member.trust.as_ref().ok_or(Error::InvalidStore)?,
                member.authorization_time()?,
            )? {
                return Err(Error::InvalidStore);
            }
        }
        Ok(())
    }
    fn seal(&self, member: &Member, key: &[u8; 32], context: &[u8]) -> Result<Vec<u8>, Error> {
        #[derive(Serialize)]
        struct Bundle<'a> {
            inbox: &'a InboxState,
            member: Vec<u8>,
        }
        let bundle = Bundle {
            inbox: &self.state,
            member: member.snapshot(key, context)?,
        };
        let plaintext =
            Zeroizing::new(serde_json::to_vec(&bundle).map_err(|_| Error::InvalidStore)?);
        crate::vault::seal(&plaintext, key, &inbox_context(context)?)
    }

    /// Export one encrypted checkpoint containing both policy and MLS state.
    pub fn snapshot(&self, member: &Member, key: &[u8; 32], context: &[u8]) -> Result<Vec<u8>, Error> {
        self.validate_state(member)?;
        self.seal(member, key, context)
    }

    pub fn restore(sealed: &[u8], key: &[u8; 32], context: &[u8]) -> Result<(Self, Member), Error> {
        Self::restore_with_clock(sealed, key, context, Arc::new(crate::lifecycle::SystemClock))
    }

    pub fn restore_with_clock(
        sealed: &[u8],
        key: &[u8; 32],
        context: &[u8],
        clock: Arc<dyn Clock>,
    ) -> Result<(Self, Member), Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Bundle {
            inbox: InboxState,
            member: Vec<u8>,
        }
        let plaintext = crate::vault::open(sealed, key, &inbox_context(context)?)?;
        let bundle: Bundle = serde_json::from_slice(&plaintext).map_err(|_| Error::InvalidStore)?;
        let member = Member::restore_with_clock(&bundle.member, key, context, clock)?;
        let inbox = Self {
            state: bundle.inbox,
        };
        inbox.validate_state(&member)?;
        Ok((inbox, member))
    }
}
fn inbox_context(context: &[u8]) -> Result<[u8; 32], Error> {
    if context.is_empty() || context.len() > 128 {
        return Err(Error::InvalidStore);
    }
    let mut hash = Sha256::new();
    hash.update(b"cmsg.inbox.v1\0");
    hash.update(context);
    Ok(hash.finalize().into())
}
