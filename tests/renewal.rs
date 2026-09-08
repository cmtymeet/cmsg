mod common;
use cmsg::{AdmissionGrant, Clock, Error, Member, Received};
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};

const KEY: [u8; 32] = [52; 32];
const CONTEXT: &[u8] = b"synthetic-renewal";
struct ManualClock(AtomicU64);
impl ManualClock {
    fn new(now: u64) -> Arc<Self> {
        Arc::new(Self(AtomicU64::new(now)))
    }
    fn set(&self, now: u64) {
        self.0.store(now, Ordering::Relaxed);
    }
}
impl Clock for ManualClock {
    fn now(&self) -> Result<u64, Error> {
        Ok(self.0.load(Ordering::Relaxed))
    }
}
fn grant(member: &Member, id: u8, issued_at: u64, expires_at: u64) -> AdmissionGrant {
    let mut grant = common::grant(&member.chat_public_key(), id);
    grant.issued_at = issued_at;
    grant.expires_at = expires_at;
    common::sign(&mut grant);
    grant
}
fn member(clock: &Arc<ManualClock>, id: u8, expires: u64) -> Member {
    let mut m = Member::new_with_clock(clock.clone()).unwrap();
    m.bind_admission(
        grant(&m, id, 1, expires),
        common::trust(),
        clock.now().unwrap(),
    )
    .unwrap();
    m
}
fn pair(clock: &Arc<ManualClock>, a_expiry: u64, b_expiry: u64) -> (Member, Member) {
    let mut a = member(clock, 210, a_expiry);
    let mut b = member(clock, 211, b_expiry);
    a.create_group().unwrap();
    b.join(&a.add(&b.key_package().unwrap()).unwrap().welcome)
        .unwrap();
    (a, b)
}
fn text_is(received: Received, expected: &str) {
    assert!(matches!(received, Received::Text(t) if t.text == expected));
}

#[test]
fn clock_is_deterministic_and_restored_history_stays_readable_after_expiry() {
    let clock = ManualClock::new(100);
    let (mut a, mut b) = pair(&clock, 200, 1000);
    let wire = a.send(b"before expiry").unwrap();
    text_is(b.receive(&wire).unwrap(), "before expiry");
    let sealed = a.snapshot(&KEY, CONTEXT).unwrap();
    clock.set(200);
    assert!(a.member_id().is_err());
    assert!(a.send(b"expired").is_err());
    let restored = Member::restore_with_clock(&sealed, &KEY, CONTEXT, clock.clone()).unwrap();
    assert!(restored.member_id().is_err());
    assert_eq!(restored.history()[0].text, "before expiry");
}

#[test]
fn inactive_expired_roster_entry_does_not_break_other_members_epoch_agreement() {
    let clock = ManualClock::new(100);
    let mut a = member(&clock, 201, 1000);
    let mut b = member(&clock, 202, 1000);
    let mut inactive = member(&clock, 203, 200);
    a.create_group().unwrap();
    let welcome = a
        .add_many(&[b.key_package().unwrap(), inactive.key_package().unwrap()])
        .unwrap()
        .welcome;
    b.join(&welcome).unwrap();
    inactive.join(&welcome).unwrap();
    clock.set(300);
    assert!(inactive.send(b"expired sender").is_err());
    text_is(
        b.receive(&a.send(b"still eligible").unwrap()).unwrap(),
        "still eligible",
    );
    let mut d = member(&clock, 204, 1000);
    let invitation = a.add(&d.key_package().unwrap()).unwrap();
    assert!(matches!(
        b.receive(&invitation.commit).unwrap(),
        Received::MembershipChanged
    ));
    d.join(&invitation.welcome).unwrap();
    let removal = a.remove(2).unwrap();
    b.receive(&removal).unwrap();
    d.receive(&removal).unwrap();
    let wire = a.send(b"same epoch after removal").unwrap();
    text_is(b.receive(&wire).unwrap(), "same epoch after removal");
    text_is(d.receive(&wire).unwrap(), "same epoch after removal");
}

#[test]
fn same_key_renewal_preserves_identity_before_and_after_old_certificate_expiry() {
    for renewal_time in [150, 300] {
        let clock = ManualClock::new(100);
        let (mut a, mut b) = pair(&clock, 200, 1000);
        let identity = a.member_id().unwrap();
        let public_key = a.chat_public_key();
        clock.set(renewal_time);
        let replacement = grant(&a, 210, renewal_time, 900);
        let mut saved = Vec::new();
        let commit = a
            .renew_admission(replacement, |candidate| {
                assert_eq!(candidate.member_id().unwrap(), identity);
                saved = candidate.snapshot(&KEY, CONTEXT)?;
                Ok(())
            })
            .unwrap();
        assert!(!saved.is_empty());
        assert_eq!(a.chat_public_key(), public_key);
        assert!(matches!(
            b.receive(&commit).unwrap(),
            Received::MembershipChanged
        ));
        assert!(b.receive(&commit).is_err());
        let mut restored =
            Member::restore_with_clock(&saved, &KEY, CONTEXT, clock.clone()).unwrap();
        assert_eq!(restored.member_id().unwrap(), identity);
        let message = b.receive(&restored.send(b"renewed").unwrap()).unwrap();
        assert!(
            matches!(message, Received::Text(t) if t.text == "renewed" && t.member_id == identity)
        );
    }
}

#[test]
fn failed_renewal_persistence_does_not_advance_local_identity_or_epoch() {
    let clock = ManualClock::new(100);
    let (mut a, mut b) = pair(&clock, 200, 1000);
    clock.set(300);
    let replacement = grant(&a, 210, 300, 900);
    assert!(a
        .renew_admission(replacement.clone(), |_| Err(Error::InvalidStore))
        .is_err());
    assert!(a.member_id().is_err());
    assert!(a.send(b"not committed").is_err());
    assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = a.renew_admission(replacement.clone(), |_| {
            panic!("synthetic persistence crash")
        });
    }))
    .is_err());
    assert!(a.member_id().is_err());
    let commit = a.renew_admission(replacement, |_| Ok(())).unwrap();
    b.receive(&commit).unwrap();
    text_is(
        b.receive(&a.send(b"retry succeeds").unwrap()).unwrap(),
        "retry succeeds",
    );
}

#[test]
fn expired_member_can_catch_up_control_without_exposing_text_then_renew() {
    let clock = ManualClock::new(100);
    let (mut a, mut b) = pair(&clock, 1000, 200);
    clock.set(300);
    let mut c = member(&clock, 212, 1000);
    let invitation = a.add(&c.key_package().unwrap()).unwrap();
    c.join(&invitation.welcome).unwrap();
    assert!(b.receive(&invitation.commit).is_err());
    b.receive_control(&invitation.commit).unwrap();
    let wire = a.send(b"not exposed during recovery").unwrap();
    assert!(b.receive_control(&wire).is_err());
    assert!(b.history().is_empty());
    let replacement = grant(&b, 211, 300, 900);
    let renewal = b.renew_admission(replacement, |_| Ok(())).unwrap();
    a.receive(&renewal).unwrap();
    c.receive(&renewal).unwrap();
    let wire = b.send(b"back in current epoch").unwrap();
    text_is(a.receive(&wire).unwrap(), "back in current epoch");
    text_is(c.receive(&wire).unwrap(), "back in current epoch");
}

// A peer using upstream MLS directly can create cryptographically valid control
// messages that violate application admission. These are not mocked ciphertexts.
struct RawOwner {
    provider: openmls_rust_crypto::OpenMlsRustCrypto,
    signer: openmls_basic_credential::SignatureKeyPair,
    group: openmls::prelude::MlsGroup,
}
impl RawOwner {
    fn with_receiver(receiver: &mut Member) -> Self {
        use openmls::prelude::*;
        use openmls_traits::OpenMlsProvider;
        use tls_codec::{Deserialize, Serialize};
        let provider = openmls_rust_crypto::OpenMlsRustCrypto::default();
        let suite = Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519;
        let signer =
            openmls_basic_credential::SignatureKeyPair::new(suite.signature_algorithm()).unwrap();
        let mut cert = common::grant(&signer.to_public_vec(), 220);
        cert.expires_at = 200;
        common::sign(&mut cert);
        let credential = CredentialWithKey {
            credential: BasicCredential::new(serde_json::to_vec(&cert).unwrap()).into(),
            signature_key: signer.to_public_vec().into(),
        };
        let config = MlsGroupCreateConfig::builder()
            .ciphersuite(suite)
            .use_ratchet_tree_extension(true)
            .wire_format_policy(PURE_CIPHERTEXT_WIRE_FORMAT_POLICY)
            .build();
        let mut group = MlsGroup::new(&provider, &signer, &config, credential).unwrap();
        let key_package = KeyPackageIn::tls_deserialize_exact(&receiver.key_package().unwrap())
            .unwrap()
            .validate(provider.crypto(), ProtocolVersion::Mls10)
            .unwrap();
        let (_, welcome, _) = group
            .add_members(&provider, &signer, &[key_package])
            .unwrap();
        group.merge_pending_commit(&provider).unwrap();
        receiver
            .join(&welcome.tls_serialize_detached().unwrap())
            .unwrap();
        Self {
            provider,
            signer,
            group,
        }
    }
    fn replacement(&self) -> AdmissionGrant {
        let mut grant = common::grant(&self.signer.to_public_vec(), 220);
        grant.issued_at = 300;
        grant.expires_at = 900;
        common::sign(&mut grant);
        grant
    }
    fn renewal_candidate(&self, grant: AdmissionGrant, extra: Option<Vec<u8>>) -> Vec<u8> {
        use openmls::prelude::*;
        use openmls_traits::OpenMlsProvider;
        use tls_codec::{Deserialize, Serialize};
        let provider = openmls_rust_crypto::OpenMlsRustCrypto::default();
        *provider.storage().values.write().unwrap() =
            self.provider.storage().values.read().unwrap().clone();
        let mut group = MlsGroup::load(provider.storage(), self.group.group_id())
            .unwrap()
            .unwrap();
        let credential = CredentialWithKey {
            credential: BasicCredential::new(serde_json::to_vec(&grant).unwrap()).into(),
            signature_key: self.signer.to_public_vec().into(),
        };
        let parameters = LeafNodeParameters::builder()
            .with_credential_with_key(credential)
            .build();
        let mut builder = group
            .commit_builder()
            .consume_proposal_store(false)
            .leaf_node_parameters(parameters);
        if let Some(bytes) = extra {
            let package = KeyPackageIn::tls_deserialize_exact(&bytes)
                .unwrap()
                .validate(provider.crypto(), ProtocolVersion::Mls10)
                .unwrap();
            builder = builder.propose_adds([package]);
        }
        builder
            .load_psks(provider.storage())
            .unwrap()
            .build(provider.rand(), provider.crypto(), &self.signer, |_| true)
            .unwrap()
            .stage_commit(&provider)
            .unwrap()
            .into_commit()
            .tls_serialize_detached()
            .unwrap()
    }
    fn expired_text(&mut self) -> Vec<u8> {
        use tls_codec::Serialize;
        self.group
            .create_message(
                &self.provider,
                &self.signer,
                b"expired peer bypassed its local checks",
            )
            .unwrap()
            .tls_serialize_detached()
            .unwrap()
    }
}

#[test]
fn expired_sender_cannot_smuggle_text_identity_changes_or_additions_through_recovery() {
    for attack in [
        "member",
        "community",
        "policy",
        "key",
        "expired",
        "future",
        "signature",
        "addition",
    ] {
        let clock = ManualClock::new(100);
        let mut receiver = member(&clock, 221, 1000);
        let mut owner = RawOwner::with_receiver(&mut receiver);
        clock.set(300);
        assert!(receiver.receive(&owner.expired_text()).is_err());
        let mut forged = owner.replacement();
        match attack {
            "member" => forged.member_id = data_encoding::BASE64URL_NOPAD.encode(&[222; 32]),
            "community" => forged.community_id = "other-community".into(),
            "policy" => forged.policy_digest = data_encoding::BASE64URL_NOPAD.encode(&[225; 32]),
            "key" => forged.chat_public_key = data_encoding::BASE64URL_NOPAD.encode(&[223; 32]),
            "expired" => {
                forged.issued_at = 1;
                forged.expires_at = 250;
            }
            "future" => forged.issued_at = 301,
            _ => (),
        }
        common::sign(&mut forged);
        if attack == "signature" {
            forged.signature = data_encoding::BASE64URL_NOPAD.encode(&[0; 64]);
        }
        let extra =
            (attack == "addition").then(|| member(&clock, 224, 1000).key_package().unwrap());
        let invalid = owner.renewal_candidate(forged, extra);
        assert!(receiver.receive(&invalid).is_err(), "rejected {attack}");
        let valid = owner.renewal_candidate(owner.replacement(), None);
        assert!(matches!(
            receiver.receive(&valid).unwrap(),
            Received::MembershipChanged
        ));
        assert!(receiver.history().is_empty());
    }
}

#[test]
fn even_current_sender_cannot_replace_its_stable_identity_during_self_update() {
    let clock = ManualClock::new(100);
    let mut receiver = member(&clock, 221, 1000);
    let owner = RawOwner::with_receiver(&mut receiver);
    clock.set(150);
    let mut valid = owner.replacement();
    valid.issued_at = 150;
    common::sign(&mut valid);
    let mut forged = valid.clone();
    forged.member_id = data_encoding::BASE64URL_NOPAD.encode(&[226; 32]);
    common::sign(&mut forged);
    assert!(receiver
        .receive(&owner.renewal_candidate(forged, None))
        .is_err());
    assert!(matches!(
        receiver
            .receive(&owner.renewal_candidate(valid, None))
            .unwrap(),
        Received::MembershipChanged
    ));
}
