# Native messaging experiments

This is an experimental client library, not a deployable anonymous messenger or an audited security product. It uses released upstream implementations, with synthetic fixtures only. No phone check, payment, paid service or production credential is involved.

## Selected building blocks

| Requirement | Implementation | Boundary |
|---|---|---|
| Pair and group text encryption | OpenMLS 0.9.0 with its RustCrypto 0.6 provider; RFC 9420 MLS, X25519/ChaCha20-Poly1305/Ed25519 | The application validates membership authorization; MLS alone does not supply anonymity or quotas |
| Stable identity from community into private chats | Independently verified cvld Ed25519 grant, bound to each MLS signing key and carried as a BasicCredential | The stable member ID is intentionally visible to participants; no cross-community account linking is added |
| Local encrypted state and history | Random data key and XChaCha20-Poly1305 envelope, wrapped with caller-provided 32-byte PRF-derived material | No password, operator key, plaintext persistence or device recovery fallback |
| Network identity | Checksum-validated v3 onion endpoints through a trusted loopback Tor SOCKS listener; isolated SOCKS credentials per connection | No clearnet endpoint representation or fallback; the host application must own and verify the Tor process |
| Mobile foundation | Rust core with caller-supplied memory/key material and transport configuration | Cross-target checks are separate from native app integration and device tests |

Dependencies remain under their upstream licenses; FSL applies to this repository's own integration code. The original selection favored OpenMLS over incorporating SimpleX or libsignal: the latter introduce AGPL composition questions, and libsignal explicitly does not promise support for third-party clients. This is a reason to use the maintained MLS protocol implementation, not a claim that a smaller integration automatically has better security.

Sources: [OpenMLS](https://github.com/openmls/openmls), [RFC 9420](https://www.rfc-editor.org/rfc/rfc9420.html), [RustCrypto AEADs](https://github.com/RustCrypto/AEADs), [Tor onion protocol](https://spec.torproject.org/rend-spec/), [libsignal](https://github.com/signalapp/libsignal).

## Executable checks

The tests create actual independently keyed MLS participants and exercise encrypted two-member and 100-member conversations, addition/removal, past-epoch exclusion, tampering, exact framing, replay and out-of-order delivery. They also check UTF-8 byte limits, literal markup handling, hidden debug output, issuer/community/policy/key/expiry binding, and snapshots containing both history and ratchet state.

The first fail-first commit is `e4ff940`: all ten behavioral tests compiled and failed against explicit stubs. The admission test commit `a49fa02` likewise failed on accepting a real signed identity and preventing unadmitted creation. The 100-member specification was introduced at `b8dca4c` before bulk-add implementation.

A real integration defect appeared during testing: OpenMLS could reject an altered ciphertext after advancing receive-ratchet storage, making the authentic retransmission fail. The receive boundary now stages the operation in isolated memory storage and commits only fully authenticated, application-valid changes. Rejected ciphertext must not advance committed state; the test was retained rather than weakened.

The mocked SOCKS tests are socket-level negative tests, not proof of Tor anonymity. They observe requested onion names and per-connection isolation, use a separate clearnet trap, and verify failure replies and deceptive bind-address replies cannot cause direct connections. Receiving text with an embedded tracking URL causes zero trap connections.

`Live Tor onion experiment` is a separately dispatched workflow. It launches independent client and onion-service Tor processes on an ephemeral public runner and carries a real MLS ciphertext through an onion circuit. Its output is limited to aggregate booleans. A successful run proves this routing path works and the service sees its local Tor connection; it does not prove resistance to timing correlation, a compromised client, or a global observer. The two processes use one disposable host, not independent mobile networks.

All builds and tests run on standard public GitHub-hosted runners with public source and synthetic data. No production secret or protected input is sent to CI. Dependency resolution is locked. The normal workflow additionally checks Android arm64 and iOS arm64 Rust targets without signing or paid accounts.

## Remaining integration and security work

- The local Tor listener is a trusted deployment boundary. A loopback address is not evidence that the process is Tor. Mobile applications need a supported embedded/local Tor lifecycle, network confinement, suspension/reconnection handling and device testing. There is no ordinary-browser implementation.
- MLS outer messages expose group identifiers to whoever receives those bytes. This prototype connects directly to member onion services; intermediary Tor relays do not receive MLS plaintext. An operator-run delivery queue would need a separately reviewed outer envelope and routing design. Do not send these raw MLS objects to a central logging relay.
- The library validates cvld admission grants and binds them to signing keys. Production issuance still depends on cvld's provider and passkey integration. cfrm first-contact capabilities and private quota spending are an additional required gate; the primitive library does not pretend that an admission grant proves good standing or available allowance.
- Snapshots authenticate the saved state, not its freshness. A valid old snapshot can still roll state back, and simultaneous restored copies can fork a sender state. Production persistence requires atomic, monotonic commits and single-writer/device handling. No test here establishes crash consistency or rollback protection.
- Credential expiry is enforced against the client clock. Renewing a grant/key in an existing MLS group and migration of issuer trust require an explicit protocol path. Expiry is not a behavioral ban or a revocation database.
- History is client-local. Its recipient already knows the content and can copy it. The process necessarily holds plaintext while unlocked; zeroization reduces residual copies but does not establish protection against a compromised OS, crash dumps or all allocator copies.
- No offline ciphertext queues, recipient introduction service, attachment codec, URL fetcher, video call, operator telemetry pipeline or content-report endpoint is implemented. Limits bound bytes, not the semantic meaning of user-written text.
- The `composition` example is a synthetic local JSON process seam, not a network API. It receives already issued grants and synthetic PRF material, emits only public chat keys and boolean results, and lets the integration harness enforce cfrm decisions before admitting a first contact.
