mod common;
use cmsg::{Clock, Error, Member, MemberIdentity, Received};
use std::sync::{Arc, atomic::{AtomicU64, Ordering}};

struct Time(AtomicU64);
impl Clock for Time {
    fn now(&self) -> Result<u64, Error> { Ok(self.0.load(Ordering::Relaxed)) }
}

fn device(root: &MemberIdentity, time: &Arc<Time>, device_expiry: u64) -> Member {
    let mut member = Member::new_with_clock(time.clone()).unwrap();
    let key = member.chat_public_key();
    let mut grant = common::grant(&key, 1);
    grant.member_id = root.member_id().to_owned();
    common::sign(&mut grant);
    member.bind_device_admission(grant, common::trust(), root.authorize_device(&key, 1, device_expiry).unwrap(), 100).unwrap();
    member
}

#[test]
fn expired_device_authorization_renews_with_same_root_and_key_without_rotating_identity() {
    let time = Arc::new(Time(AtomicU64::new(100)));
    let alice_root = MemberIdentity::new("synthetic-community").unwrap();
    let bob_root = MemberIdentity::new("synthetic-community").unwrap();
    let mut alice = device(&alice_root, &time, 200);
    let mut bob = device(&bob_root, &time, 1000);
    alice.create_group().unwrap();
    bob.join(&alice.add(&bob.key_package().unwrap()).unwrap().welcome).unwrap();
    time.0.store(300, Ordering::Relaxed);
    assert!(alice.send(b"expired authorization").is_err());
    let key = alice.chat_public_key();
    let mut grant = common::grant(&key, 1);
    grant.member_id = alice_root.member_id().to_owned();
    common::sign(&mut grant);
    let renewal = alice_root.authorize_device(&key, 300, 900).unwrap();
    assert!(alice.renew_device_admission(grant.clone(), renewal.clone(), |_, _| Err(Error::InvalidStore)).is_err());
    assert!(alice.member_id().is_err(), "failed durable write cannot install a root renewal");
    let mut invalid = renewal.clone();
    invalid.expires_at = 950;
    assert!(alice.renew_device_admission(grant.clone(), invalid, |_, _| panic!("invalid signature")).is_err());
    let wrong_root = bob_root.authorize_device(&key, 300, 900).unwrap();
    assert!(alice.renew_device_admission(grant.clone(), wrong_root, |_, _| panic!("wrong root")).is_err());
    let wrong_key = alice_root.authorize_device(&bob.chat_public_key(), 300, 900).unwrap();
    assert!(alice.renew_device_admission(grant.clone(), wrong_key, |_, _| panic!("wrong device")).is_err());
    let control = alice.renew_device_admission(grant, renewal, |_, _| Ok(())).unwrap();
    assert!(matches!(bob.receive(&control).unwrap(), Received::MembershipChanged));
    assert_eq!(alice.member_id().unwrap(), alice_root.member_id());
    assert_eq!(alice.chat_public_key(), key);
    assert!(matches!(bob.receive(&alice.send(b"root renewed").unwrap()).unwrap(), Received::Text(message)
        if message.member_id == alice_root.member_id() && message.text == "root renewed"));
}
