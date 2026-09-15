mod common;
use cmsg::{Clock, ContactResolution, Error, FirstContactPolicy, FirstContactRole as Role, Inbox, Member, MemberIdentity, Received};
use std::sync::{Arc, atomic::{AtomicU64, Ordering}};

const KEY: [u8; 32] = [71; 32];
const CONTEXT: &[u8] = b"synthetic-directional-contact";
const INITIAL: [u8; 32] = [72; 32];
const FRESH: [u8; 32] = [73; 32];

struct Time(AtomicU64);
impl Clock for Time { fn now(&self) -> Result<u64, Error> { Ok(self.0.load(Ordering::Relaxed)) } }
fn device(root: &MemberIdentity, time: &Arc<Time>) -> Member {
    let mut member = Member::new_with_clock(time.clone()).unwrap();
    let key = member.chat_public_key();
    let mut grant = common::grant(&key, 1);
    grant.member_id = root.member_id().to_owned();
    common::sign(&mut grant);
    member.bind_device_admission(grant, common::trust(), root.authorize_device(&key, 1, 10_000).unwrap(), 100).unwrap();
    member
}
fn policy() -> FirstContactPolicy { FirstContactPolicy { response_deadline: 5000, max_intro_bytes: 128 } }
fn chain(inbox: &Inbox, member: &Member, peer: &str) -> Vec<cmsg::ContactDirective> {
    let state: serde_json::Value = serde_json::from_slice(&inbox.export_contact_sync(member).unwrap()).unwrap();
    serde_json::from_value(state["directional"][peer]["local"].clone()).unwrap()
}
fn malicious_control(member: &mut Member, chain: &[cmsg::ContactDirective]) -> Vec<u8> {
    let mut bytes = b"cmsg.contact-directive.v1\0".to_vec();
    bytes.extend_from_slice(&serde_json::to_vec(&serde_json::json!({"chain":chain,"receipt":null})).unwrap());
    member.send_bytes(&bytes).unwrap()
}
struct Pair {
    a: Member, b: Member, ai: Inbox, bi: Inbox,
    ar: MemberIdentity, br: MemberIdentity, time: Arc<Time>,
}
fn pending() -> Pair {
    let time = Arc::new(Time(AtomicU64::new(100)));
    let ar = MemberIdentity::new("synthetic-community").unwrap();
    let br = MemberIdentity::new("synthetic-community").unwrap();
    let mut a = device(&ar, &time);
    let mut b = device(&br, &time);
    a.create_group().unwrap();
    b.join(&a.add(&b.key_package().unwrap()).unwrap().welcome).unwrap();
    let mut ai = Inbox::new(&a).unwrap();
    let mut bi = Inbox::new(&b).unwrap();
    ai.begin_first_contact(br.member_id(), &INITIAL, Role::Initiator, policy(), &a, &KEY, CONTEXT, |_| Ok(())).unwrap();
    bi.begin_first_contact(ar.member_id(), &INITIAL, Role::Recipient, policy(), &b, &KEY, CONTEXT, |_| Ok(())).unwrap();
    let intro = ai.send_contact(&mut a, b"initial introduction", &KEY, CONTEXT, |_, _| Ok(())).unwrap();
    bi.receive_contact(&mut b, &intro, &KEY, CONTEXT, |_| Ok(())).unwrap();
    Pair { a, b, ai, bi, ar, br, time }
}

fn established() -> Pair {
    let mut p = pending();
    let answer = p.bi.send_contact(&mut p.b, b"initial answer", &KEY, CONTEXT, |_, _| Ok(())).unwrap();
    p.ai.receive_contact(&mut p.a, &answer, &KEY, CONTEXT, |_| Ok(())).unwrap();
    p
}

#[test]
fn only_block_owner_restarts_with_a_fresh_gate_and_old_data_and_receipts_stay_closed() {
    let mut p = established();
    let delayed = p.ai.send_contact(&mut p.a, b"old queued data", &KEY, CONTEXT, |_, _| Ok(())).unwrap();
    let close = p.bi.close_contact(&mut p.b, &KEY, CONTEXT, |_, _| Ok(())).unwrap();
    let old_receipt: ContactResolution = serde_json::from_slice(p.bi.outbound_resolution_receipt(p.ar.member_id()).unwrap()).unwrap();
    assert!(matches!(p.ai.receive_contact(&mut p.a, &close, &KEY, CONTEXT, |_| Ok(())).unwrap(), Received::ContactClosed));
    assert!(p.ai.initiate_contact(&mut p.a, &FRESH, policy(), &KEY, CONTEXT, |_, _| panic!("blocked peer cannot initiate")).is_err());
    assert!(p.bi.initiate_contact(&mut p.b, &FRESH, policy(), &KEY, CONTEXT, |_, _| Err(Error::InvalidStore)).is_err());
    assert!(p.bi.is_closed(p.ar.member_id()));
    let stale = p.bi.export_contact_sync(&p.b).unwrap();
    let mut saved = Vec::new();
    let initiative = p.bi.initiate_contact(&mut p.b, &FRESH, policy(), &KEY, CONTEXT,
        |state, _| { saved = state.to_vec(); Ok(()) }).unwrap();
    assert!(!p.bi.is_closed(p.ar.member_id()));
    assert!(matches!(p.ai.receive_contact(&mut p.a, &initiative, &KEY, CONTEXT, |_| Ok(())).unwrap(), Received::ContactPolicyChanged));
    assert!(!p.ai.is_closed(p.br.member_id()));
    assert!(p.ai.send_contact(&mut p.a, b"premature reply", &KEY, CONTEXT, |_, _| panic!("fresh introduction required")).is_err());
    assert!(p.ai.apply_resolution(&old_receipt, &p.a, &KEY, CONTEXT, |_| panic!("old receipt cannot alter current nonce")).is_err());
    assert!(p.bi.receive_contact(&mut p.b, &delayed, &KEY, CONTEXT, |_| panic!("old plaintext must not escape")).is_err());
    let (mut restored, mut b) = Inbox::restore_with_clock(&saved, &KEY, CONTEXT, p.time.clone()).unwrap();
    restored.merge_contact_sync(&stale, &b, &KEY, CONTEXT, |_| Ok(())).unwrap();
    assert!(!restored.is_closed(p.ar.member_id()), "a stale chain prefix cannot undo the owner's newer initiative");
    let intro = restored.send_contact(&mut b, b"fresh introduction", &KEY, CONTEXT, |_, _| Ok(())).unwrap();
    assert!(restored.send_contact(&mut b, b"duplicate fresh introduction", &KEY, CONTEXT, |_, _| panic!("one only")).is_err());
    assert!(matches!(p.ai.receive_contact(&mut p.a, &intro, &KEY, CONTEXT, |_| Ok(())).unwrap(), Received::Text(m) if m.text == "fresh introduction"));
    let answer = p.ai.send_contact(&mut p.a, b"fresh answer", &KEY, CONTEXT, |_, _| Ok(())).unwrap();
    assert!(matches!(restored.receive_contact(&mut b, &answer, &KEY, CONTEXT, |_| Ok(())).unwrap(), Received::Text(m) if m.text == "fresh answer"));
    assert!(p.ai.receive_contact(&mut p.a, &initiative, &KEY, CONTEXT, |_| panic!("replay")).is_err());
}

#[test]
fn both_members_must_consent_to_the_same_fresh_initiative() {
    let mut p = established();
    let a_close = p.ai.close_contact(&mut p.a, &KEY, CONTEXT, |_, _| Ok(())).unwrap();
    p.bi.receive_contact(&mut p.b, &a_close, &KEY, CONTEXT, |_| Ok(())).unwrap();
    let b_close = p.bi.close_contact(&mut p.b, &KEY, CONTEXT, |_, _| Ok(())).unwrap();
    p.ai.receive_contact(&mut p.a, &b_close, &KEY, CONTEXT, |_| Ok(())).unwrap();
    let offer = p.ai.initiate_contact(&mut p.a, &FRESH, policy(), &KEY, CONTEXT, |_, _| Ok(())).unwrap();
    assert!(p.ai.is_closed(p.br.member_id()));
    p.bi.receive_contact(&mut p.b, &offer, &KEY, CONTEXT, |_| Ok(())).unwrap();
    assert!(p.bi.is_closed(p.ar.member_id()));
    assert!(p.ai.send_contact(&mut p.a, b"without consent", &KEY, CONTEXT, |_, _| panic!("peer still blocks")).is_err());
    assert!(p.bi.consent_contact(&mut p.b, &KEY, CONTEXT, |_, _| Err(Error::InvalidStore)).is_err());
    assert!(p.bi.is_closed(p.ar.member_id()));
    let consent = p.bi.consent_contact(&mut p.b, &KEY, CONTEXT, |_, _| Ok(())).unwrap();
    p.ai.receive_contact(&mut p.a, &consent, &KEY, CONTEXT, |_| Ok(())).unwrap();
    assert!(!p.ai.is_closed(p.br.member_id()));
    assert!(!p.bi.is_closed(p.ar.member_id()));
    let intro = p.ai.send_contact(&mut p.a, b"mutually reopened", &KEY, CONTEXT, |_, _| Ok(())).unwrap();
    p.bi.receive_contact(&mut p.b, &intro, &KEY, CONTEXT, |_| Ok(())).unwrap();
    let answer = p.bi.send_contact(&mut p.b, b"accepted", &KEY, CONTEXT, |_, _| Ok(())).unwrap();
    p.ai.receive_contact(&mut p.a, &answer, &KEY, CONTEXT, |_| Ok(())).unwrap();
}

#[test]
fn optional_block_expiry_allows_only_a_new_authenticated_introduction() {
    let mut p = established();
    let delayed = p.ai.send_contact(&mut p.a, b"queued before timed block", &KEY, CONTEXT, |_, _| Ok(())).unwrap();
    let block = p.bi.close_contact_until(&mut p.b, Some(200), &KEY, CONTEXT, |_, _| Ok(())).unwrap();
    p.ai.receive_contact(&mut p.a, &block, &KEY, CONTEXT, |_| Ok(())).unwrap();
    p.time.0.store(199, Ordering::Relaxed);
    assert!(p.ai.initiate_contact(&mut p.a, &FRESH, policy(), &KEY, CONTEXT, |_, _| panic!("not expired")).is_err());
    p.time.0.store(201, Ordering::Relaxed);
    assert!(p.ai.is_closed(p.br.member_id()), "time alone cannot reopen old state");
    assert!(p.bi.receive_contact(&mut p.b, &delayed, &KEY, CONTEXT, |_| panic!("old queued data remains blocked")).is_err());
    let initiative = p.ai.initiate_contact(&mut p.a, &FRESH, policy(), &KEY, CONTEXT, |_, _| Ok(())).unwrap();
    p.bi.receive_contact(&mut p.b, &initiative, &KEY, CONTEXT, |_| Ok(())).unwrap();
    assert!(!p.ai.is_closed(p.br.member_id()));
    assert!(!p.bi.is_closed(p.ar.member_id()));
    let intro = p.ai.send_contact(&mut p.a, b"after configured expiry", &KEY, CONTEXT, |_, _| Ok(())).unwrap();
    p.bi.receive_contact(&mut p.b, &intro, &KEY, CONTEXT, |_| Ok(())).unwrap();
}

#[test]
fn competing_same_owner_device_histories_persist_a_conflict_and_fail_closed() {
    let mut p = established();
    let sibling = device(&p.br, &p.time);
    let mut sibling_inbox = Inbox::new(&sibling).unwrap();
    p.bi.block_member_until(p.ar.member_id(), None, &p.b, &KEY, CONTEXT, |_| Ok(())).unwrap();
    sibling_inbox.block_member_until(p.ar.member_id(), Some(400), &sibling, &KEY, CONTEXT, |_| Ok(())).unwrap();
    p.bi.initiate_contact(&mut p.b, &FRESH, policy(), &KEY, CONTEXT, |_, _| Ok(())).unwrap();
    assert!(!p.bi.is_closed(p.ar.member_id()));
    let conflicting = sibling_inbox.export_contact_sync(&sibling).unwrap();
    let mut saved = Vec::new();
    p.bi.merge_contact_sync(&conflicting, &p.b, &KEY, CONTEXT, |state| { saved = state.to_vec(); Ok(()) }).unwrap();
    assert!(p.bi.is_closed(p.ar.member_id()));
    let (mut restored, mut b) = Inbox::restore_with_clock(&saved, &KEY, CONTEXT, p.time.clone()).unwrap();
    assert!(restored.initiate_contact(&mut b, &[74; 32], policy(), &KEY, CONTEXT, |_, _| panic!("fork requires reconciliation")).is_err());
    assert!(restored.send_contact(&mut b, b"conflict must stay closed", &KEY, CONTEXT, |_, _| panic!("closed")).is_err());
}

#[test]
fn direct_close_after_reopening_survives_sibling_sync_until_its_owner_initiates_again() {
    let mut p = established();
    let sibling = device(&p.ar, &p.time);
    let mut sibling_inbox = Inbox::new(&sibling).unwrap();
    let close = p.bi.close_contact(&mut p.b, &KEY, CONTEXT, |_, _| Ok(())).unwrap();
    p.ai.receive_contact(&mut p.a, &close, &KEY, CONTEXT, |_| Ok(())).unwrap();
    let fresh = p.bi.initiate_contact(&mut p.b, &FRESH, policy(), &KEY, CONTEXT, |_, _| Ok(())).unwrap();
    p.ai.receive_contact(&mut p.a, &fresh, &KEY, CONTEXT, |_| Ok(())).unwrap();
    let intro = p.bi.send_contact(&mut p.b, b"fresh introduction", &KEY, CONTEXT, |_, _| Ok(())).unwrap();
    p.ai.receive_contact(&mut p.a, &intro, &KEY, CONTEXT, |_| Ok(())).unwrap();
    let answer = p.ai.send_contact(&mut p.a, b"fresh answer", &KEY, CONTEXT, |_, _| Ok(())).unwrap();
    p.bi.receive_contact(&mut p.b, &answer, &KEY, CONTEXT, |_| Ok(())).unwrap();
    sibling_inbox.merge_contact_sync(&p.ai.export_contact_sync(&p.a).unwrap(), &sibling, &KEY, CONTEXT, |_| Ok(())).unwrap();
    p.bi.block_member_until(p.ar.member_id(), None, &p.b, &KEY, CONTEXT, |_| Ok(())).unwrap();
    let receipt = p.b.sign_contact_resolution(p.ar.member_id(), &FRESH, cmsg::ContactResolutionKind::ClosedForever).unwrap();
    assert!(!p.ai.apply_resolution(&receipt, &p.a, &KEY, CONTEXT, |_| Ok(())).unwrap());
    let closed = p.ai.export_contact_sync(&p.a).unwrap();
    sibling_inbox.merge_contact_sync(&closed, &sibling, &KEY, CONTEXT, |_| Ok(())).unwrap();
    assert!(sibling_inbox.is_closed(p.br.member_id()), "a prior initiative does not erase a later direct close");
    let next = p.bi.initiate_contact(&mut p.b, &[75; 32], policy(), &KEY, CONTEXT, |_, _| Ok(())).unwrap();
    p.ai.receive_contact(&mut p.a, &next, &KEY, CONTEXT, |_| Ok(())).unwrap();
    let reopened = p.ai.export_contact_sync(&p.a).unwrap();
    sibling_inbox.merge_contact_sync(&reopened, &sibling, &KEY, CONTEXT, |_| Ok(())).unwrap();
    sibling_inbox.merge_contact_sync(&closed, &sibling, &KEY, CONTEXT, |_| Ok(())).unwrap();
    assert!(!sibling_inbox.is_closed(p.br.member_id()), "only the owner's subsequent chained initiative supersedes that close");
}

#[test]
fn authentic_unsolicited_fresh_directive_cannot_replace_an_existing_gate() {
    let mut p = established();
    p.ai.block_member_until(p.br.member_id(), None, &p.a, &KEY, CONTEXT, |_| Ok(())).unwrap();
    let group = chain(&p.ai, &p.a, p.br.member_id())[0].group_id.clone();
    let illicit = p.a.sign_contact_directive(p.br.member_id(), 1, &[0; 32], &[0; 32],
        cmsg::ContactDirectiveKind::FreshInitiative, &FRESH, p.ar.member_id(), &group, Some(policy()), None).unwrap();
    let wire = malicious_control(&mut p.a, &[illicit]);
    assert!(p.bi.receive_contact(&mut p.b, &wire, &KEY, CONTEXT,
        |_| panic!("a valid signature does not authorize a fresh gate")).is_err());
}

#[test]
fn sender_self_block_then_fresh_cannot_erase_a_received_unanswered_introduction() {
    for deliver_cancellation in [false, true] {
        let mut p = established();
        let close = p.bi.close_contact(&mut p.b, &KEY, CONTEXT, |_, _| Ok(())).unwrap();
        p.ai.receive_contact(&mut p.a, &close, &KEY, CONTEXT, |_| Ok(())).unwrap();
        let initiative = p.bi.initiate_contact(&mut p.b, &FRESH, policy(), &KEY, CONTEXT, |_, _| Ok(())).unwrap();
        p.ai.receive_contact(&mut p.a, &initiative, &KEY, CONTEXT, |_| Ok(())).unwrap();
        let introduction = p.bi.send_contact(&mut p.b, b"still unanswered", &KEY, CONTEXT, |_, _| Ok(())).unwrap();
        p.ai.receive_contact(&mut p.a, &introduction, &KEY, CONTEXT, |_| Ok(())).unwrap();
        if deliver_cancellation {
            let cancellation = p.bi.close_contact(&mut p.b, &KEY, CONTEXT, |_, _| Ok(())).unwrap();
            p.ai.receive_contact(&mut p.a, &cancellation, &KEY, CONTEXT, |_| Ok(())).unwrap();
        } else {
            p.bi.block_member_until(p.ar.member_id(), None, &p.b, &KEY, CONTEXT, |_| Ok(())).unwrap();
        }
        assert!(p.bi.awaiting_peer_resolution(p.ar.member_id()));
        assert!(p.bi.initiate_contact(&mut p.b, &[76; 32], policy(), &KEY, CONTEXT,
            |_, _| panic!("honest sender cannot self-refund")).is_err());
        let mut history = chain(&p.bi, &p.b, p.ar.member_id());
        let previous = history.last().unwrap();
        let illicit = p.b.sign_contact_directive(p.ar.member_id(), previous.revision + 1, &previous.digest().unwrap(), &[0; 32],
            cmsg::ContactDirectiveKind::FreshInitiative, &[76; 32], p.br.member_id(), &previous.group_id, Some(policy()), None).unwrap();
        history.push(illicit);
        let wire = malicious_control(&mut p.b, &history);
        let before = p.a.history().len();
        assert!(p.ai.receive_contact(&mut p.a, &wire, &KEY, CONTEXT,
            |_| panic!("peer cancellation cannot replace recipient answer or close")).is_err());
        let mut payload = b"cmsg.contact-data.v2\0".to_vec();
        payload.extend_from_slice(&[76; 32]);
        payload.push(1);
        payload.extend_from_slice(b"another unsolicited introduction");
        let bypass = p.b.send_bytes(&payload).unwrap();
        assert!(p.ai.receive_contact(&mut p.a, &bypass, &KEY, CONTEXT, |_| panic!("new data must stay blocked")).is_err());
        assert_eq!(p.a.history().len(), before);
    }
}

#[test]
fn a_valid_peer_signature_cannot_change_the_initiative_it_claims_to_accept() {
    let mut p = established();
    let a_close = p.ai.close_contact(&mut p.a, &KEY, CONTEXT, |_, _| Ok(())).unwrap();
    p.bi.receive_contact(&mut p.b, &a_close, &KEY, CONTEXT, |_| Ok(())).unwrap();
    let b_close = p.bi.close_contact(&mut p.b, &KEY, CONTEXT, |_, _| Ok(())).unwrap();
    p.ai.receive_contact(&mut p.a, &b_close, &KEY, CONTEXT, |_| Ok(())).unwrap();
    let offer = p.ai.initiate_contact(&mut p.a, &FRESH, policy(), &KEY, CONTEXT, |_, _| Ok(())).unwrap();
    p.bi.receive_contact(&mut p.b, &offer, &KEY, CONTEXT, |_| Ok(())).unwrap();
    let owner_chain = chain(&p.ai, &p.a, p.br.member_id());
    let acknowledgement = owner_chain.last().unwrap().digest().unwrap();
    for mutation in 0..5 {
        let mut history = chain(&p.bi, &p.b, p.ar.member_id());
        let previous = history.last().unwrap();
        let nonce = if mutation == 0 { [77; 32] } else { FRESH };
        let mut limits = policy();
        if mutation == 1 { limits.response_deadline += 1; }
        if mutation == 2 { limits.max_intro_bytes -= 1; }
        let group = if mutation == 3 { vec![9; 32] } else { previous.group_id.clone() };
        let initiator = if mutation == 4 { p.br.member_id() } else { p.ar.member_id() };
        let forged = p.b.sign_contact_directive(p.ar.member_id(), previous.revision + 1, &previous.digest().unwrap(), &acknowledgement,
            cmsg::ContactDirectiveKind::FreshInitiative, &nonce, initiator, &group, Some(limits), None).unwrap();
        history.push(forged);
        let wire = malicious_control(&mut p.b, &history);
        assert!(p.ai.receive_contact(&mut p.a, &wire, &KEY, CONTEXT, |_| panic!("consent must match exactly")).is_err());
    }
    let consent = p.bi.consent_contact(&mut p.b, &KEY, CONTEXT, |_, _| Ok(())).unwrap();
    p.ai.receive_contact(&mut p.a, &consent, &KEY, CONTEXT, |_| Ok(())).unwrap();
    assert!(!p.ai.is_closed(p.br.member_id()));
}

#[test]
fn stale_signed_archives_cannot_erase_an_unresolved_sent_introduction() {
    let mut p = established();
    let close = p.bi.close_contact(&mut p.b, &KEY, CONTEXT, |_, _| Ok(())).unwrap();
    p.ai.receive_contact(&mut p.a, &close, &KEY, CONTEXT, |_| Ok(())).unwrap();
    let reopen = p.bi.initiate_contact(&mut p.b, &FRESH, policy(), &KEY, CONTEXT, |_, _| Ok(())).unwrap();
    p.ai.receive_contact(&mut p.a, &reopen, &KEY, CONTEXT, |_| Ok(())).unwrap();
    let before_send = p.bi.snapshot(&p.b, &KEY, CONTEXT).unwrap();
    let first = p.bi.send_contact(&mut p.b, b"an outstanding introduction", &KEY, CONTEXT, |_, _| Ok(())).unwrap();
    p.ai.receive_contact(&mut p.a, &first, &KEY, CONTEXT, |_| Ok(())).unwrap();
    p.ai.block_member_until(p.br.member_id(), None, &p.a, &KEY, CONTEXT, |_| Ok(())).unwrap();
    // The recipient's private decision allows its own new initiative, but its
    // separate resolution receipt has not yet reached the original sender.
    let newer = p.ai.initiate_contact(&mut p.a, &[78; 32], policy(), &KEY, CONTEXT, |_, _| Ok(())).unwrap();
    p.bi.receive_contact(&mut p.b, &newer, &KEY, CONTEXT, |_| Ok(())).unwrap();
    assert!(p.bi.awaiting_peer_resolution(p.ar.member_id()));
    let (mut stale, mut old_b) = Inbox::restore_with_clock(&before_send, &KEY, CONTEXT, p.time.clone()).unwrap();
    stale.receive_contact(&mut old_b, &newer, &KEY, CONTEXT, |_| Ok(())).unwrap();
    assert!(!stale.awaiting_peer_resolution(p.ar.member_id()), "an old authentic snapshot lacks the later send");
    let stale_sync = stale.export_contact_sync(&old_b).unwrap();
    let current_sync = p.bi.export_contact_sync(&p.b).unwrap();
    p.bi.merge_contact_sync(&stale_sync, &p.b, &KEY, CONTEXT, |_| Ok(())).unwrap();
    assert!(p.bi.awaiting_peer_resolution(p.ar.member_id()), "archive merge must preserve sent=true");
    stale.merge_contact_sync(&current_sync, &old_b, &KEY, CONTEXT, |_| Ok(())).unwrap();
    assert!(stale.awaiting_peer_resolution(p.ar.member_id()), "current peer evidence heals the rolled-back send floor");
}

#[test]
fn delayed_sender_cancellation_preserves_the_recipients_own_close_provenance() {
    let mut p = pending();
    let b_close = p.bi.close_contact(&mut p.b, &KEY, CONTEXT, |_, _| Ok(())).unwrap();
    let own_close = p.bi.outbound_resolution_receipt(p.ar.member_id()).unwrap().to_vec();
    p.ai.receive_contact(&mut p.a, &b_close, &KEY, CONTEXT, |_| Ok(())).unwrap();
    let a_close = p.ai.close_contact(&mut p.a, &KEY, CONTEXT, |_, _| Ok(())).unwrap();
    let receipt: ContactResolution = serde_json::from_slice(p.ai.outbound_resolution_receipt(p.br.member_id()).unwrap()).unwrap();
    assert!(!p.bi.apply_resolution(&receipt, &p.b, &KEY, CONTEXT, |_| Ok(())).unwrap());
    assert_eq!(p.bi.outbound_resolution_receipt(p.ar.member_id()).unwrap(), own_close);
    p.bi.receive_contact(&mut p.b, &a_close, &KEY, CONTEXT, |_| Ok(())).unwrap();
    assert_eq!(p.bi.outbound_resolution_receipt(p.ar.member_id()).unwrap(), own_close);
    let offer = p.ai.initiate_contact(&mut p.a, &FRESH, policy(), &KEY, CONTEXT, |_, _| Ok(())).unwrap();
    p.bi.receive_contact(&mut p.b, &offer, &KEY, CONTEXT, |_| Ok(())).unwrap();
    let consent = p.bi.consent_contact(&mut p.b, &KEY, CONTEXT, |_, _| Ok(())).unwrap();
    p.ai.receive_contact(&mut p.a, &consent, &KEY, CONTEXT, |_| Ok(())).unwrap();
    assert!(!p.ai.is_closed(p.br.member_id()));
}
