# cmsg browser bindings

The browser package runs the same Rust MLS core and wire format as native cmsg.
It accepts opaque binary messages and offers a text convenience method.

```js
import { init, BrowserIdentity, BrowserMember } from '@corbet-labs/cmsg';

await init();
const member = new BrowserMember();
const identity = new BrowserIdentity(communityId);
const publicKey = member.chatPublicKey();
const deviceAuthorization = identity.authorizeDevice(publicKey, issuedAt, expiresAt);
// Obtain issuer eligibility for identity.memberId() and this device public key.
member.bindDeviceAdmission(JSON.stringify(grant), JSON.stringify(trustedIssuer), deviceAuthorization);
```

`BrowserIdentity` owns the permanent community identity root and authorizes
independently generated device keys. Issuer eligibility alone cannot enroll a
device under somebody else's identity. Identity recovery exports only sealed
ciphertext, bound to the expected community and member ID.

`BrowserMember` exposes low-level group creation, invitations, joining, binary/text
encryption, authenticated receive, participant removal and encrypted snapshots.
`sendBytes(Uint8Array)` preserves arbitrary bytes, including invalid UTF-8;
`sendText(string)` has the core text size limit. A received object exposes
`kind`, `memberId`, `bytes`, and optional `text`. Display text literally.

Trust configuration uses the Rust `AdmissionTrust` JSON field names:
`community_id`, `policy_digest`, `issuer_public_key` (32 numbers).
An admission grant uses its existing camelCase wire fields. Issuer trust is
application configuration; do not accept it from a conversation peer.

Call `free()` on Wasm-owned objects when finished. Erase JavaScript's own key
and plaintext copies. Rust memory is accessible to code in the same JavaScript
context. The host must supply secure code distribution, passkey wrapping
material, and atomic durable storage for sealed state. Restoring old valid
snapshots does not detect rollback or merge concurrent device state.

## Tor transport

The optional `@corbet-labs/cmsg/tor-js` entrypoint uses the actual `tor-js@0.4.1`
package. It requires an explicitly configured TorJS gateway and a whole-request
deadline. No gateway, billing account, CDN fallback or direct-IP message route
is supplied. Bundle and serve TorJS' `wasm-file` asset with the application.

```js
import { createTorJsOnionTransport } from '@corbet-labs/cmsg/tor-js';

const transport = await createTorJsOnionTransport({
  gateway: configuredGateway,
  deadlineMs: 45000,
});
const replyWire = await transport.exchange(peerOnion, peerPort, encryptedWire);
const reply = member.receive(replyWire);
```

This adapter performs one request/reply exchange against a peer-owned onion
HTTP listener. It does not publish a browser onion service, provide an inbox
server, queue offline messages, or make a suspended browser reachable.
TorJS 0.4.1 exposes client HTTP fetch, not a public onion-service hosting API.
Transport connectivity and hosting need separate end-to-end evidence; codec
tests and browser crypto tests do not establish either.

The browser constructs Tor circuits. Its gateway forwards encrypted bytes and
can observe client IP, timing, volume, and the entry relay. The gateway is part
of the bandwidth path for the entire session. The adapter suppresses its TorJS
logger, sends a fixed generic User-Agent, accepts only checksum-valid v3 onion
destinations, rejects redirects, and applies strict response bounds. A deadline
closes the dedicated TorJS client and rejects the operation; upstream in-flight
connection cancellation is limited by TorJS' own implementation.

### Peer HTTP wire contract

- Request: `POST /cmsg/v1/exchange`.
- Content-Type and Accept: `application/vnd.cmsg.frame`.
- Body: one nonempty frame, encoded as uint32 big-endian length plus bytes.
- Response: status 200, the same Content-Type, and an exact Content-Length.
- Response body: exactly one frame, at most `MAX_WIRE_BYTES` payload bytes.
- Redirects, compression, chunked responses and multiple response frames fail.

Applications supply MLS ciphertext as frame payloads. This HTTP wrapper does
not identify members, attest a gateway, or enforce first-contact admission.
Do not replace TorJS fetch with browser fetch or a cleartext onion gateway.

## Build and evidence

Build the Rust library for `wasm32-unknown-unknown`, then generate the Web
bindings with a `wasm-bindgen` CLI matching the resolved crate version, output
name `cmsg`, into `browser/pkg/`. Copy the repository license into the package
before packing. The checked-in package excludes generated artifacts.

`tests/browser.rs` runs in a real browser using `wasm-bindgen-test` and covers
binary/text MLS round-trips, authentication failures, replay rejection,
encrypted restore, and the portable route/framing bindings.
