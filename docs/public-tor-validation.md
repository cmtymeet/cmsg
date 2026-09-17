# Public Tor browser validation

The `tor-browser` CI workflow has an explicit public-network mode:
`TOR_NETWORK=public`, `TOR_STAGE=service`, `RUN_RUNTIME=1`.
It builds the pinned TorJS/Arti service overlay without the private-network
feature, then runs `browser/upstream/public-runtime-fixture.py`.
All test participants and payloads are synthetic.

## Required evidence

The browser owns its Arti clients, circuits and ephemeral onion services.
A disposable native Tor client supplies SOCKS transport for the separate Rust
cmsg participant. The browser's KPS gateway transports encrypted Tor bytes to
advertised relays. It is a loopback-only child of the test, with its own state;
it is not a deployed gateway.

The runtime contract requires:

- Two browser clients bootstrap using the public Tor directory authorities.
- Two distinct browser-owned onion services publish with full vanguards.
- Browser peers exchange binary cmsg frames through an onion service.
- A separate native Rust participant connects to a browser-owned onion and
  exchanges authenticated MLS binary messages in both directions.
- Replayed MLS ciphertext is rejected; closing the service cancels acceptance.
- The gateway refuses local and unadvertised non-relay targets. The owned local
  canary receives zero connections.
- Invalid onion routes fail in Wasm, and the page makes no unexpected external
  HTTP requests.

The generated bindings, Wasm modules, native binaries, source overlays and
dependency locks are recorded by digest. Public mode retains the dependency
snapshot documented in [the lock provenance](../browser/upstream/locks/README.md).
It does not perform a fresh dependency upgrade. CI artifacts distinguish
public-network results from the signed private-network fixture.

## Scope

A passing run demonstrates interoperability on the public network for its
recorded source and environment. It does not measure mobile feasibility,
multiple independent physical hosts, long-running reliability, censorship
resistance, or production gateway capacity. Page request interception does not
establish process-wide browser network confinement or absence of metadata
leaks. The gateway can observe the client address and traffic timing/volume.

The native participant is an onion client in this test; the browser owns the
onion service. Native onion hosting has separate earlier experiment evidence.
The fixture does not deploy a service or publish the experimental package.

## Result

Public browser runtime validation is pending. Earlier native public-Tor
validation and browser private-Tor validation are separate evidence.
