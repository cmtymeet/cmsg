# Credential renewal: review findings and proposed checks

This is a design proposal from source review, not implemented behavior or passing test evidence. The existing cvld admission verifier remains strict. The newer recipient Inbox also still awaits hosted execution as recorded in [the implementation study](implementation-experiments.md).

## Observed behavior

`Member::send` requires the local member's current cvld certificate. `Member::receive` requires both the recipient's current certificate and the actual message sender's current certificate. An unrelated inactive member with an expired certificate does not stop ordinary text between two still-authorized members.

Membership changes have a different failure: after merging a candidate commit in isolated state, `receive` validates every remaining roster certificate against the current clock. An expired, unchanged member can therefore prevent peers from accepting an unrelated addition or removal, even though the committer has already advanced its own MLS state. Joining an existing group also rejects an expired inactive roster entry. `bind_admission` permits only the first binding, so there is no renewal path.

The local history snapshot can be decrypted after expiry. However, the current receive entry check also prevents an expired member from processing control messages needed to catch up after an offline period. Adding a renewal method alone would not resolve that case.

## Proposed authorization boundary

| Operation or role | Required validation |
|---|---|
| Send or expose newly received application text | Current local admission, and current admission for the authenticated sender |
| New first contact | Current inviter and recipient admission plus the recipient's applicable Inbox/cfrm gate |
| Add a new MLS member or change a credential | Current issuer-authorized credential, bound to the actual MLS leaf signing key |
| Unchanged existing roster entry | Valid historical issuer signature and stable community/member/key binding; expiry alone does not invalidate a different member's action |
| Process ordinary membership control | Current authorization of the authenticated committer; validate additions and changes before committing state |
| Recover an expired local member's epoch | A separate control-only boundary may use the historical local binding; it must not return application text |
| Same-key credential renewal | Current replacement certificate for the same community, stable member ID and signing key, authenticated by an MLS self-update |

The historical check must still verify the issuer signature, community, policy and signing-key binding. It cannot mean accepting arbitrary expired certificate fields. Issuer or policy migration and signing-key replacement remain separate protocols.

An expired old certificate may authorize a renewal message only through a narrow recovery exception: the MLS message proves possession of its existing signing key, the candidate own leaf carries an independently verified current certificate for that same identity/key, and the commit contains no unrelated proposals or membership changes. An expired sender's text, additions, removals or unrelated commits remain rejected. Validation and persistence must be transactional, preserving legitimate retransmission after a rejected renewal.

OpenMLS already supports credential changes through `MlsGroup::self_update` and `LeafNodeParameters::with_credential_with_key`; this should use that maintained protocol path. Sources: [OpenMLS 0.9 updates](https://raw.githubusercontent.com/openmls/openmls/openmls-v0.9.0/openmls/src/group/mls_group/updates.rs), [leaf parameter builder](https://raw.githubusercontent.com/openmls/openmls/openmls-v0.9.0/openmls/src/treesync/node/leaf_node.rs).

Expiry remains an application admission check. An existing member already holds group keys and a modified client can bypass local expiry checks. Excluding that member from future cryptographic epochs requires an MLS removal and rekey. Neither certificate expiry nor this proposed renewal procedure erases previously delivered keys or plaintext.

## Required fail-first experiments

Use a trusted injectable clock for deterministic tests; do not sleep until certificates expire or make tests depend on a global mutable clock. Restoring a snapshot must explicitly reconnect its trusted time source. Production convenience methods can use the system clock; tests can advance independently held synthetic clocks.

1. Three members join while valid. One becomes inactive and its certificate expires. The other two can still exchange text, accept a new eligible member and process a removal. The inactive entry must not break their epoch agreement.
2. Expired actual senders and locally expired recipients still cannot send or expose new application text. Historical signature validity must not become a general expiry bypass.
3. A member renews its certificate using the same key and stable ID, before and after old-certificate expiry. Peers authenticate the renewal and preserve that visible ID and their local known-counterpart/block state.
4. Reject renewal with another member ID, community, policy, issuer or signing key, an invalid signature, a not-yet-valid certificate or an expired replacement. Reject a recovery commit bundled with any unrelated proposal or roster change.
5. Rejection, failed durable writes and replay leave ratchet state unchanged; a subsequent legitimate renewal succeeds. A restored authentic old snapshot still has the documented rollback limitation.
6. An expired member can catch up on authenticated control messages without exposing application text, obtain its current credential through cvld and complete renewal at the current MLS epoch.
7. A new first contact after renewal still goes through Inbox. A certified same-ID counterpart remains known or locally blocked, rather than receiving a new identity through certificate rotation.

Existing membership concurrency, missed-control delivery and durable multi-device state remain separate integration work. This review does not establish a production-ready renewal state machine.
