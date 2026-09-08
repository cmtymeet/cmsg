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

## Executed experiment and remaining prerequisite

The separately locked, non-published [embedded experiment](../experiments/embedded-onion/README.md) now compiles against Arti 0.46.0. [Crow pipeline 22](https://crow.corbet.ch/repos/10/pipeline/22) at `34ab6226999f5871208b0f24f23e10ae3b33e2aa` passed all 10 behavioral contracts and formatting after the genuine failing run in pipeline 19. These checks exercise owned directories, endpoint/virtual-port refusal, deadline/cancellation ownership and a real cmsg MLS exchange over bounded in-process streams. They do not establish onion reachability.

The manual public-network [pipeline 24](https://crow.corbet.ch/repos/10/pipeline/24), at `bc823ade38e83f38e32b2ffd010fbea2a9775789`, built the experiment but failed immediately during bootstrap: Rustls 0.23.44 had no selected process crypto provider. That revision's Rustls dependency list included neither built-in provider; WebPKI's separate `ring` dependency did not enable Rustls's backend. [Pipeline 25](https://crow.corbet.ch/repos/10/pipeline/25) at `6c61bdb42310ca7f1f105774547c5a7c77da1818` then executed a new initializer regression: prior 10 tests passed and the new test failed against its stub. The correction explicitly enables Rustls's maintained `ring` backend and installs its default provider before Arti construction, following [upstream application startup guidance](https://docs.rs/rustls/latest/rustls/crypto/struct.CryptoProvider.html). Hosted validation and a successful public-network exchange remain outstanding.

The next manual run must bootstrap two synthetic app-owned clients and publish an app-owned service, then exchange actual cmsg ciphertext and verify the counterpart only at the recipient. Bootstrap, publication, acceptance and shutdown remain bounded, with only coarse phase results. A future successful round trip would establish functional routing from that runtime, not mobile availability, battery behavior, encrypted local identity storage or resistance to a global observer.
