# First-contact release experiment

Separate unpublished Rust experiment for the [release-gate design](../../studies/first-contact-release-gate.md). Crow repository 10, pipeline 18 at `ed9691bd6d3b422304946a565f0591955b6b0061` compiled all fifteen specifications and failed each at the explicit `PendingRelease::prepare` stub. The group fixture constructed a real 100-member MLS Welcome before reaching that stub. Formatting also failed, but did not prevent execution. Pipeline 21 at `760948fbaddc6f7d6a5ca77521b6ae01aeb2fdbb` passed all fifteen behavioral cases, including the real group-sharing bypass; formatting alone kept that workflow red. After applying the worker's formatter output, [pipeline 23](https://crow.corbet.ch/repos/10/pipeline/23) at `bc823ade38e83f38e32b2ffd010fbea2a9775789` passed formatting and all fifteen cases. These results concern this isolated experiment, not the complete proposed protocol.

It uses actual cmsg/OpenMLS participants, Welcome messages and first ciphertexts. Operator commit/redemption signatures are synthetic Ed25519 fixtures, not outputs from the cfrm ledger and not evidence that counters committed. There is no network, provider, passkey UI, authenticated preflight signature, first-contact permit integration or shipping rule selection here.

The owned pending state holds the exact withheld Welcome/ciphertext, current context, sender and expected recipient IDs/keys, a fresh private release nonce, a separate sender authorization nonce and one bound blind request hash. Release requires both independently signed operator attestations to match, using Ed25519 `verify_strict` and canonical base64url. State exports use versioned ChaCha20-Poly1305 with the expected community/policy/cohort context as associated data. Encrypted restore authenticates saved state, not freshness, atomic host durability or protection from rollback/concurrent copies. The caller must compute the bound request hash from the actual independently validated blind request; this fixture does not perform blind RSA issuance.

`bind_request` returns the expected operator-commit fields with an empty signature for the synthetic fixture. It is not a client debit authorization or an operator request. Operator keys and the supplied time remain trusted host inputs. Restoring an older authentic snapshot can resurrect an earlier local decline; the immutable payload still confines successful release retries to the original bytes.

Canonical JSON array domains are `cfrm.directional.commit.v1` and `cfrm.directional.redemption.v1`, with separate trusted operator keys. They differ from the current cfrm `authorize.v1`/`redeem.v1` client authorization domains. The sender statement contains only its account binding, authorization nonce and blinded request hash; the receiver statement contains only its account binding and private release nonce. Both include community, policy, cohort and validity. The private release nonce must be inside the blinded receipt and absent from sender-side operator traffic, including hashes or copied preflight fields. The separately tested cfrm [release-purpose receipt](https://github.com/corbet-labs/cfrm/blob/main/experiments/directional-receipts/ATTESTATION-ACCEPTANCE.md) now includes this nonce; its ledger outputs are not yet connected to this client gate. The two signatures do not prove same-token provenance, and schema checks do not establish anonymity.

Specs cover withheld MLS input, exact retry recovery, separate sender commit, signed substitutions, key/domain/signature rejection, different pending invitations, time bounds, local decline without an operator call, encrypted restore and tampering, ordinary free replies and dishonest withholding after an apparent debit. A real 100-member group case additionally demonstrates that forwarding its shared multi-recipient Welcome can bypass another recipient's gate. This is an accepted cooperating-member limitation, not exclusion from a group that already shares keys.

The ordinary-reply case only shows established MLS traffic continuing without this first-contact release gate. It does not integrate the proposed first reversed directional acknowledgement. That action may need its own two-operation accounting exchange without a new first-contact permit; later ordinary conversation remains free of this release gate.

Run with the existing remote CI worker, using the separately checked-in lock:

```
cargo test --locked --manifest-path experiments/first-contact-release/Cargo.toml -- --nocapture
```

No local compilation or package publication is needed. All compilation and behavioral execution use the existing remote worker.

## Actual-key process composition: rejecting boundary

The new unpublished `counter_bridge` binary follows the reviewed [process outline](https://github.com/corbet-labs/cfrm/blob/main/experiments/directional-receipts/COMPOSITION-OUTLINE.md). It owns two actual `Member` keys, pins the synthetic issuer/operator trust and both independently supplied wallet commitments at initialization, verifies their admission grants, and returns narrow enrollment signatures. A Node driver supplies the separate holder-wallet possession signatures and enrolls those two exact chat keys plus fifteen fixture identities. Neither chat private key leaves the native child.

`prepareRelease` deliberately returns `not-implemented`. The new composition tests must reach this rejection after actual enrollment before the release flow is implemented. The previously passing fifteen isolated contracts and 83 core contracts are separate evidence; no successful cross-process accounting/release composition is claimed yet.

The JSON-lines protocol uses exact increasing request IDs starting at one, a 32 KiB line cap, typed argument schemas and coarse errors. Stdout is captured by the driver, never a public API or diagnostic log. One child holding both peers and one Node driver spanning synthetic holder/operator roles establish no process isolation, anonymity, production provider or mobile behavior. The eventual release path must keep MLS material, plaintext, snapshots and wrapping keys inside the child.

Build the reviewed source on the existing worker and supply the resulting executable through the driver's trusted `CMSG_RELEASE_HARNESS` path:

```
cargo build --locked --manifest-path experiments/first-contact-release/Cargo.toml --bin counter_bridge
```
