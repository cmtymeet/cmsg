//! Local synthetic process seam for cross-language admission and rules experiments.
//! Public chat keys are emitted first; one JSON line supplies signed grants.
use cmsg::{AdmissionGrant, AdmissionTrust, Member, Received};
use data_encoding::BASE64URL_NOPAD;
use serde::Deserialize;
use std::io::{BufRead, Write};
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Request {
    grants: [AdmissionGrant; 2],
    trust: AdmissionTrust,
    wrapping_key: [u8; 32],
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut a = Member::new().map_err(|_| "member creation failed")?;
    let mut b = Member::new().map_err(|_| "member creation failed")?;
    println!(
        "{}",
        serde_json::json!({"chatPublicKeys":[BASE64URL_NOPAD.encode(&a.chat_public_key()),BASE64URL_NOPAD.encode(&b.chat_public_key())]})
    );
    std::io::stdout().flush()?;
    let line = std::io::stdin()
        .lock()
        .lines()
        .next()
        .ok_or("missing admission input")??;
    if line.len() > 16 * 1024 {
        return Err("input limit".into());
    }
    let request: Request = serde_json::from_str(&line)?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    a.bind_admission(request.grants[0].clone(), request.trust.clone(), now)
        .map_err(|_| "admission rejected")?;
    b.bind_admission(request.grants[1].clone(), request.trust, now)
        .map_err(|_| "admission rejected")?;
    a.create_group().map_err(|_| "group creation failed")?;
    b.join(
        &a.add(&b.key_package().map_err(|_| "key package failed")?)
            .map_err(|_| "member addition failed")?
            .welcome,
    )
    .map_err(|_| "join failed")?;
    let wire = a
        .send(b"synthetic composition text")
        .map_err(|_| "send failed")?;
    let received = b.receive(&wire).map_err(|_| "receive failed")?;
    let valid = matches!(received, Received::Text(t) if t.text == "synthetic composition text" && t.member_id == request.grants[0].member_id);
    let snapshot = b
        .snapshot(&request.wrapping_key, b"composition-v1")
        .map_err(|_| "snapshot failed")?;
    let mut restored = Member::restore(&snapshot, &request.wrapping_key, b"composition-v1")
        .map_err(|_| "restore failed")?;
    let replay_rejected = restored.receive(&wire).is_err();
    if !valid || !replay_rejected {
        return Err("composition invariant failed".into());
    }
    println!(
        "{}",
        serde_json::json!({"delivered":true,"stableIdentityBound":true,"encryptedSnapshotRestored":true,"replayRejected":true})
    );
    Ok(())
}
