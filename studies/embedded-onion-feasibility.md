# Embedded onion transport feasibility

Reviewed 2026-09-08. The current CI runtime has no `tor`, `tor-gencert` or `arti` executable, as verified by [pipeline 11](https://crow.corbet.ch/repos/10/pipeline/11). That prevents rerunning the existing Chutney experiment with installed tools. An embedded Tor library is a separate integration path; it does not require installing a daemon on the host or operating an intermediary for members.

## Maintained implementation

The Tor Project's [`arti-client` 0.46.0](https://crates.io/api/v1/crates/arti-client/0.46.0) was published 2026-09-02, is not yanked and declares Rust 1.91. The current CI compiler is newer. Its checked archive has SHA256 `aafcbc506657d886b27ef2d8e06a99edd9014b28130c798a3013935b46983097`. Matching [`tor-hsservice` 0.46.0](https://crates.io/api/v1/crates/tor-hsservice/0.46.0) has SHA256 `d61a6b5217c14780f54fa1c8610514b1349c93f657304dec98bd8e3083e1a09f`. Source archives were downloaded for inspection, not installed or executed.

The official [`TorClient` API](https://docs.rs/arti-client/latest/arti_client/struct.TorClient.html) supplies isolated clients, onion connections and `launch_onion_service`. Inspection of version 0.46.0 confirms that launching returns a running service handle and a stream of rendezvous requests. The application then accepts selected streams itself. This can make an app-owned service handle the origin of endpoint ownership evidence, rather than trusting a hostname or loopback socket alone.

The [`tor-hsservice` API](https://docs.rs/tor-hsservice/latest/tor_hsservice/) exposes the generated onion address, service status events and incoming stream acceptance. It supports handling application bytes directly; forwarding to a local TCP port is an optional architecture. This fits a generic bounded framing codec and a future native client without requiring a browser or TCP listener in the library core. No new Tor cryptography is proposed.

## Integration constraints

- Enable only the required Tokio/TLS, onion-client, onion-service and defensive routing features. Avoid blindly enabling the full experimental feature set. A pinned dependency lock and actual build must establish compatibility.
- Use explicit app-owned state/cache directories. Default user-wide directories are unsuitable for isolated experiments or separate community instances. `TorClientConfigBuilder::from_directories` derives its keystore location from the supplied state directory.
- The normal keystore persists identity keys. An ephemeral keystore exists behind an explicitly experimental feature; merely using a temporary folder is not a claim of encrypted storage or forensic erasure. Production key lifetime and wallet wrapping require their own integration decision.
- Verify generated endpoint and selected virtual port, use per-session isolation, and never retry through a clearnet route. The Tor source recommends accepting ordinary `BEGIN` requests and checking their port, without adding distinctive request rules.
- Own and bound incoming streams and their tasks. The provided `handle_rend_requests` helper uses unbounded concurrent rendezvous acceptance in the inspected source. A bounded application service must not inherit that behavior accidentally.
- Closing presence must stop new profile acceptance and close owned streams. Status events and handle ownership help coordinate this, but queued bytes cannot be retracted. A commented-out pause API is not an implemented lifecycle guarantee.
- Do not forward private raw MLS frames through an operator logging endpoint. An embedded client changes transport ownership, not the separate eligibility, consent, encryption or accounting requirements.

These constraints derive from the checked crate sources (`arti-client/src/client.rs`, `src/config.rs`, `Cargo.toml`, and `tor-hsservice/src/lib.rs`, `src/helpers.rs`, `src/req.rs`). The docs.rs latest pages may lag the registry; the versioned archive checks above pin the reviewed implementation.

## Next concrete experiment

Use a separately locked, non-published Rust experiment with the existing CI compiler. First validate owned-directory configuration, endpoint/virtual-port rejection, frame limits and cancellation with fail-first tests. Then run two synthetic app-owned clients and an app-owned service through actual Tor, exchanging a real cmsg ciphertext and verifying plaintext only at the recipient. Cap bootstrap, publication, request acceptance and shutdown; emit only coarse phase/results, no keys, addresses, participants or content.

Failure to bootstrap is a failed network prerequisite, not successful anonymity evidence. A successful public-network round trip would establish functional routing from that runtime, not mobile availability, battery behavior or resistance to a global observer. No Arti dependency, app binding, network service or new runtime claim accompanies this source review.
