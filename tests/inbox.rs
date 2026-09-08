mod common;
use cmsg::{Acceptance, Error, Inbox, Member, Received, Redemption};
use std::cell::RefCell;
const KEY: [u8; 32] = [31; 32];
const CONTEXT: &[u8] = b"synthetic-inbox";
fn invitation() -> (Member, Member, Vec<u8>) {
    let mut a = common::member();
    let b = common::member();
    a.create_group().unwrap();
    let welcome = a.add(&b.key_package().unwrap()).unwrap().welcome;
    (a, b, welcome)
}
#[test]
fn unknown_sender_requires_a_permit_after_full_invitation_validation() {
    let (_, mut b, welcome) = invitation();
    let mut inbox = Inbox::new(&b).unwrap();
    assert_eq!(
        inbox
            .accept(
                &mut b,
                &welcome,
                None,
                &KEY,
                CONTEXT,
                |_| panic!("no state to persist"),
                |_| panic!("no debit allowed")
            )
            .unwrap(),
        Acceptance::NeedsPermit
    );
    assert!(inbox
        .accept(
            &mut b,
            b"malformed",
            Some(b"recipient-generated opaque attempt"),
            &KEY,
            CONTEXT,
            |_| panic!("bad invitation cannot persist"),
            |_| panic!("bad invitation cannot spend")
        )
        .is_err());
}
#[test]
fn persist_pending_then_redeem_then_commit_before_delivering() {
    let (mut a, mut b, welcome) = invitation();
    let sender = a.member_id().unwrap();
    let mut inbox = Inbox::new(&b).unwrap();
    let order = RefCell::new(Vec::new());
    let saved = RefCell::new(Vec::new());
    let result = inbox
        .accept(
            &mut b,
            &welcome,
            Some(b"private-recipient-claim-with-permit"),
            &KEY,
            CONTEXT,
            |state| {
                order.borrow_mut().push("persist");
                *saved.borrow_mut() = state.to_vec();
                Ok(())
            },
            |attempt| {
                assert_eq!(attempt, b"private-recipient-claim-with-permit");
                order.borrow_mut().push("redeem");
                Redemption::Accepted
            },
        )
        .unwrap();
    assert_eq!(result, Acceptance::Joined);
    assert_eq!(*order.borrow(), vec!["persist", "redeem", "persist"]);
    assert!(inbox.is_known(&sender));
    let saved = saved.into_inner();
    assert!(!saved.windows(sender.len()).any(|b| b == sender.as_bytes()));
    let (restored, mut b) = Inbox::restore(&saved, &KEY, CONTEXT).unwrap();
    assert!(restored.is_known(&sender));
    assert!(
        matches!(b.receive(&a.send(b"accepted").unwrap()).unwrap(),Received::Text(t) if t.text=="accepted")
    );
}
#[test]
fn failed_pending_persistence_cannot_spend() {
    let (_, mut b, welcome) = invitation();
    let mut inbox = Inbox::new(&b).unwrap();
    assert!(inbox
        .accept(
            &mut b,
            &welcome,
            Some(b"opaque-attempt"),
            &KEY,
            CONTEXT,
            |_| Err(Error::InvalidStore),
            |_| panic!("no durable intent")
        )
        .is_err());
    assert!(b.send(b"not joined").is_err());
}
#[test]
fn ambiguous_redemption_restores_exact_attempt_and_does_not_replenish_it() {
    let (a, mut b, welcome) = invitation();
    let sender = a.member_id().unwrap();
    let mut inbox = Inbox::new(&b).unwrap();
    let mut saved = Vec::new();
    assert_eq!(
        inbox
            .accept(
                &mut b,
                &welcome,
                Some(b"same-private-claim"),
                &KEY,
                CONTEXT,
                |state| {
                    saved = state.to_vec();
                    Ok(())
                },
                |_| Redemption::Indeterminate
            )
            .unwrap(),
        Acceptance::Pending
    );
    assert!(!inbox.is_known(&sender));
    assert!(b.send(b"not accepted").is_err());
    let (mut inbox, mut b) = Inbox::restore(&saved, &KEY, CONTEXT).unwrap();
    assert_eq!(
        inbox
            .accept(
                &mut b,
                &welcome,
                Some(b"replacement-claim"),
                &KEY,
                CONTEXT,
                |_| panic!("cannot replace"),
                |_| panic!("cannot replace")
            )
            .unwrap(),
        Acceptance::Busy
    );
    assert_eq!(
        inbox
            .accept(
                &mut b,
                &welcome,
                None,
                &KEY,
                CONTEXT,
                |_| Ok(()),
                |attempt| {
                    assert_eq!(attempt, b"same-private-claim");
                    Redemption::Accepted
                }
            )
            .unwrap(),
        Acceptance::Joined
    );
}
#[test]
fn failed_final_write_keeps_pending_and_idempotent_retry_can_finish() {
    let (a, mut b, welcome) = invitation();
    let mut inbox = Inbox::new(&b).unwrap();
    let mut saved = Vec::new();
    let mut writes = 0;
    let result = inbox
        .accept(
            &mut b,
            &welcome,
            Some(b"durable-private-claim"),
            &KEY,
            CONTEXT,
            |state| {
                writes += 1;
                if writes == 1 {
                    saved = state.to_vec();
                    Ok(())
                } else {
                    Err(Error::InvalidStore)
                }
            },
            |_| Redemption::Accepted,
        )
        .unwrap();
    assert_eq!(result, Acceptance::Pending);
    assert!(!inbox.is_known(&a.member_id().unwrap()));
    assert!(b.send(b"not committed").is_err());
    let (mut inbox, mut b) = Inbox::restore(&saved, &KEY, CONTEXT).unwrap();
    assert_eq!(
        inbox
            .accept(
                &mut b,
                &welcome,
                None,
                &KEY,
                CONTEXT,
                |_| Ok(()),
                |attempt| {
                    assert_eq!(attempt, b"durable-private-claim");
                    Redemption::Accepted
                }
            )
            .unwrap(),
        Acceptance::Joined
    );
}
#[test]
fn rejected_permit_never_joins_or_establishes_a_known_contact() {
    let (a, mut b, welcome) = invitation();
    let mut inbox = Inbox::new(&b).unwrap();
    assert_eq!(
        inbox
            .accept(
                &mut b,
                &welcome,
                Some(b"spent-under-another-claim"),
                &KEY,
                CONTEXT,
                |_| Ok(()),
                |_| Redemption::Rejected
            )
            .unwrap(),
        Acceptance::Rejected
    );
    assert!(!inbox.is_known(&a.member_id().unwrap()));
    assert!(b.send(b"blocked").is_err());
}
