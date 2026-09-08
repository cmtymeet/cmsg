//! Synthetic process harness, never an operator relay or a production client API.
//! Two actual chat keys remain inside this child; the driver owns fixture wallets.
use cmsg::{
    verify_admission, AdmissionGrant, AdmissionTrust, Clock, Member, ReleaseContext,
    SemaphoreEnrollmentChallenge,
};
use cmsg_first_contact_release_experiment::OperatorTrust;
use data_encoding::BASE64URL_NOPAD as B64;
use ed25519_dalek::VerifyingKey;
use serde::de::DeserializeOwned;
use serde::Deserialize;
use serde_json::{json, Value};
use std::io::{BufRead, Read, Write};
use std::sync::Arc;

const MAX_LINE_BYTES: usize = 32 * 1024;
const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
type Result<T> = std::result::Result<T, &'static str>;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    id: u64,
    op: String,
    args: Value,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Init {
    now: u64,
    community_id: String,
    policy_digest: String,
    issuer_public_key: String,
    sender_commit_public_key: String,
    recipient_redemption_public_key: String,
    expected_wallet_commitments: WalletCommitments,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WalletCommitments {
    sender: String,
    recipient: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Admissions {
    sender: AdmissionGrant,
    recipient: AdmissionGrant,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
enum Actor {
    Sender,
    Recipient,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SignEnrollment {
    actor: Actor,
    challenge: SemaphoreEnrollmentChallenge,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PrepareRelease {
    context: ReleaseContext,
    preflight_expires_at: u64,
}

// The fixture's initial clock is pinned once, not accepted from later messages.
struct FixtureClock(u64);
impl Clock for FixtureClock {
    fn now(&self) -> std::result::Result<u64, cmsg::Error> {
        Ok(self.0)
    }
}

struct Actors {
    sender: Member,
    recipient: Member,
    trust: AdmissionTrust,
    _operator_trust: OperatorTrust,
    now: u64,
    expected_wallet_commitments: WalletCommitments,
    admissions: Option<Admissions>,
}

#[derive(Default)]
struct Harness {
    actors: Option<Actors>,
}

impl Harness {
    fn execute(&mut self, op: &str, args: Value) -> Result<Value> {
        match op {
            "init" => self.init(parse(args)?),
            "bindAdmissions" => self.bind_admissions(parse(args)?),
            "signEnrollment" => self.sign_enrollment(parse(args)?),
            "prepareRelease" => self.prepare_release(parse(args)?),
            _ => Err("unknown-operation"),
        }
    }

    fn init(&mut self, args: Init) -> Result<Value> {
        if self.actors.is_some() {
            return Err("invalid-state");
        }
        if args.now == 0
            || args.now > MAX_SAFE_INTEGER
            || args.community_id.is_empty()
            || args.community_id.len() > 128
            || !args.community_id.bytes().all(|b| b.is_ascii_alphanumeric() || b"._:/-".contains(&b))
            || !bounded_commitment(&args.expected_wallet_commitments.sender)
            || !bounded_commitment(&args.expected_wallet_commitments.recipient)
        {
            return Err("invalid-input");
        }
        decode32(&args.policy_digest)?;
        let issuer = public_key(&args.issuer_public_key)?;
        let sender_commit = public_key(&args.sender_commit_public_key)?;
        let recipient_redemption = public_key(&args.recipient_redemption_public_key)?;
        if sender_commit == recipient_redemption {
            return Err("invalid-input");
        }
        let clock = Arc::new(FixtureClock(args.now));
        let sender = Member::new_with_clock(clock.clone()).map_err(|_| "initialization-failed")?;
        let recipient = Member::new_with_clock(clock).map_err(|_| "initialization-failed")?;
        let response = json!({
            "sender": {"chatPublicKey": B64.encode(&sender.chat_public_key())},
            "recipient": {"chatPublicKey": B64.encode(&recipient.chat_public_key())}
        });
        self.actors = Some(Actors {
            sender,
            recipient,
            trust: AdmissionTrust {
                community_id: args.community_id,
                policy_digest: args.policy_digest,
                issuer_public_key: issuer,
            },
            _operator_trust: OperatorTrust {
                sender_commit_key: sender_commit,
                recipient_redemption_key: recipient_redemption,
            },
            now: args.now,
            expected_wallet_commitments: args.expected_wallet_commitments,
            admissions: None,
        });
        Ok(response)
    }

    fn bind_admissions(&mut self, args: Admissions) -> Result<Value> {
        let actors = self.actors.as_mut().ok_or("invalid-state")?;
        if actors.admissions.is_some() || args.sender.member_id == args.recipient.member_id {
            return Err("invalid-state");
        }
        // Validate both inputs before mutating either one-time member binding.
        verify_admission(&args.sender, &actors.trust, &actors.sender.chat_public_key(), actors.now)
            .map_err(|_| "admission-rejected")?;
        verify_admission(&args.recipient, &actors.trust, &actors.recipient.chat_public_key(), actors.now)
            .map_err(|_| "admission-rejected")?;
        actors.sender.bind_admission(args.sender.clone(), actors.trust.clone(), actors.now)
            .map_err(|_| "admission-rejected")?;
        actors.recipient.bind_admission(args.recipient.clone(), actors.trust.clone(), actors.now)
            .map_err(|_| "admission-rejected")?;
        let response = json!({
            "sender": {
                "memberId": actors.sender.member_id().map_err(|_| "admission-rejected")?,
                "chatPublicKey": B64.encode(&actors.sender.chat_public_key())
            },
            "recipient": {
                "memberId": actors.recipient.member_id().map_err(|_| "admission-rejected")?,
                "chatPublicKey": B64.encode(&actors.recipient.chat_public_key())
            }
        });
        actors.admissions = Some(args);
        Ok(response)
    }

    fn sign_enrollment(&self, args: SignEnrollment) -> Result<Value> {
        let actors = self.actors.as_ref().ok_or("invalid-state")?;
        if actors.admissions.is_none() {
            return Err("invalid-state");
        }
        // The expected commitment comes from init, never from this challenge.
        let signature = match args.actor {
            Actor::Sender => actors.sender.sign_semaphore_enrollment(
                &args.challenge, &actors.expected_wallet_commitments.sender,
            ),
            Actor::Recipient => actors.recipient.sign_semaphore_enrollment(
                &args.challenge, &actors.expected_wallet_commitments.recipient,
            ),
        }.map_err(|_| "enrollment-rejected")?;
        Ok(json!({"signature": signature}))
    }

    fn prepare_release(&self, args: PrepareRelease) -> Result<Value> {
        let actors = self.actors.as_ref().ok_or("invalid-state")?;
        if actors.admissions.is_none() {
            return Err("invalid-state");
        }
        // Deliberate fail-first boundary. The Node contracts must enroll the
        // actual two keys plus 15 filler identities before reaching this stub.
        let _ = (args.context, args.preflight_expires_at);
        Err("not-implemented")
    }
}

fn parse<T: DeserializeOwned>(args: Value) -> Result<T> {
    serde_json::from_value(args).map_err(|_| "invalid-input")
}

fn decode32(value: &str) -> Result<[u8; 32]> {
    if value.len() != 43 {
        return Err("invalid-input");
    }
    let bytes = B64.decode(value.as_bytes()).map_err(|_| "invalid-input")?;
    if B64.encode(&bytes) != value {
        return Err("invalid-input");
    }
    bytes.try_into().map_err(|_| "invalid-input")
}

fn public_key(value: &str) -> Result<[u8; 32]> {
    let key = decode32(value)?;
    VerifyingKey::from_bytes(&key).map_err(|_| "invalid-input")?;
    Ok(key)
}

fn bounded_commitment(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 77
        && matches!(value.as_bytes()[0], b'1'..=b'9')
        && value.bytes().all(|b| b.is_ascii_digit())
}

fn run() -> Result<()> {
    let mut input = std::io::stdin().lock();
    let mut output = std::io::stdout().lock();
    let mut harness = Harness::default();
    let mut next_id = 1;
    loop {
        let mut line = Vec::new();
        let size = Read::take(&mut input, (MAX_LINE_BYTES + 1) as u64)
            .read_until(b'\n', &mut line).map_err(|_| "protocol-failed")?;
        if size == 0 {
            return Ok(());
        }
        if size > MAX_LINE_BYTES || line.last() != Some(&b'\n') {
            return Err("protocol-failed");
        }
        let request: Request = serde_json::from_slice(&line).map_err(|_| "protocol-failed")?;
        if request.id != next_id || request.id > MAX_SAFE_INTEGER {
            return Err("protocol-failed");
        }
        next_id += 1;
        let response = match harness.execute(&request.op, request.args) {
            Ok(result) => json!({"id": request.id, "ok": true, "result": result}),
            Err(error) => json!({"id": request.id, "ok": false, "error": error}),
        };
        serde_json::to_writer(&mut output, &response).map_err(|_| "protocol-failed")?;
        output.write_all(b"\n").map_err(|_| "protocol-failed")?;
        output.flush().map_err(|_| "protocol-failed")?;
    }
}

fn main() {
    // The captured protocol must never print panic payloads or raw envelopes.
    std::panic::set_hook(Box::new(|_| eprintln!("counter-bridge-failed")));
    if run().is_err() {
        eprintln!("counter-bridge-failed");
        std::process::exit(1);
    }
}
