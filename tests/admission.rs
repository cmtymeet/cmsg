mod common;
use cmsg::{verify_admission, Member};
use common::{grant, sign, trust};
#[test]
fn valid_signed_community_identity_and_chat_key_are_bound() {
    let key = [23;32]; let grant = grant(&key, 7);
    assert_eq!(verify_admission(&grant, &trust(), &key, 100).unwrap(), grant.member_id);
}
#[test]
fn altered_identity_key_policy_issuer_and_expiry_are_rejected() {
    let key = [23;32]; let original = grant(&key, 7);
    assert!(verify_admission(&original, &trust(), &[24;32], 100).is_err());
    assert!(verify_admission(&original, &trust(), &key, original.expires_at).is_err());
    assert!(verify_admission(&original, &trust(), &key, 0).is_err());
    let mut changed = original.clone(); changed.member_id = grant(&key, 8).member_id;
    assert!(verify_admission(&changed, &trust(), &key, 100).is_err());
    changed = original.clone(); changed.community_id = "different-community".into(); sign(&mut changed);
    assert!(verify_admission(&changed, &trust(), &key, 100).is_err());
    changed = original.clone(); changed.policy_digest = grant(&[1;32], 0).chat_public_key; sign(&mut changed);
    assert!(verify_admission(&changed, &trust(), &key, 100).is_err());
    changed = original.clone(); changed.issuer_key_id = changed.member_id.clone(); sign(&mut changed);
    assert!(verify_admission(&changed, &trust(), &key, 100).is_err());
    let mut other = trust(); other.issuer_public_key = [10;32];
    assert!(verify_admission(&original, &other, &key, 100).is_err());
}
#[test]
fn unadmitted_identity_cannot_create_a_group_or_key_package() {
    let mut member = Member::new().unwrap();
    assert!(member.create_group().is_err());
    assert!(member.key_package().is_err());
}
