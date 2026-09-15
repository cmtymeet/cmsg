# Browser Tor dependency boundary

The upstream source and nested Arti fork are pinned in `manifest.json`.
The stock `tor-js@0.4.1` npm artifact configures `arti-client` with
`default-features = false` and only `experimental-api`. That does not include
`onion-service-client`; browser HTTP fetch support alone is insufficient.

`tor-js-onion-client.patch` enables onion clients and vanguards, and exposes a
capability marker through the actual Wasm module. cmsg checks that marker before
creating a client. A marker proves which integration API was built; a real Tor
round-trip is still required to prove network operation.

Apply the patch to the exact TorJS revision with `git apply --check` followed by
`git apply` in an isolated CI checkout. Regenerate the dependency lock only in
that checkout, preserve it as an artifact, and build the Wasm and JS together.
The released npm artifact must not be relabeled as a patched build. Record the
patched source revision, patch hash, Cargo/npm locks and artifact hash.

## Security review boundary

The Tor protocol and circuit cryptography come from Arti. This integration does
not change those algorithms. The fork's Rust runtime, gateway adapters,
persistence, TLS backend and JavaScript bindings remain separate review scope.
In particular, `rustls-rustcrypto` is an alpha dependency; an Arti audit does not
automatically certify that backend or the browser port. No complete external
browser integration audit was verified.

Native socket emulation is a byte transport to Tor entry relays. All messaging
must still use browser-owned circuits and onion endpoints. The gateway sees
the client's network address, selected entry, timing and encrypted byte volume.
This adapter's application messages never use native browser `fetch`.

## Onion service hosting work

The inspected Arti revision's onion service runtime still requires
`StateDirectory`, file-backed introduction replay logs, and service keys. Simply
enabling `onion-service-service` fails to establish browser hosting. A browser
backend must preserve introduction replay protection for the full lifetime of
each introduction key, enforce one service owner per active state, expose
bounded cancellable streams, and stop accepting streams when closed.

Per-session onion keys could make in-memory service state valid, provided every
restart generates fresh service/introduction keys and old key material is never
restored independently of its replay state. Permanent cmsg identity remains a
different member root key. This is an implementation path requiring tests,
not a current hosting capability or a settled persistence policy.
