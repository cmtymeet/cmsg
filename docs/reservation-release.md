# Protected reservation release

`Inbox::new_accounted` / `BrowserInbox.newAccounted` combine live delivery with a
mandatory private reservation gate. Existing generic Member and unaccounted
Inbox constructors remain separate integration choices. Blind introduction
permits are a separate admission path and never stand in for reservation proofs.

Before an application payload, `require_active_reservations` durably records the
actual introduction, permanent pair/roles, MLS group binding, contact policy,
current block-history context, shared openedAt/lease, pinned accounting policy
and fresh peer challenges. Each side adopts only the challenge for its own
presentation. The recipient explicitly calls `authorize_incoming_reservation`
after the outgoing **Active** presentation verifies. This records permission to
reserve incoming capacity, not a ledger debit. `bind_active_reservations` then
requires both matching Active proofs and a trusted current-own-state check.
Prepared proofs, unacknowledged persistence, missing consent and changed context
cannot release application data. Control, receipt and recovery traffic continue
without a new application allowance.

The trusted `ReservationVerifier` verifies actual proof bytes under locally
pinned circuits/verification keys, exact public statement and signed accounting
acceptance. `verify_current_local` additionally checks the embedding's accepted
own state. Browser bindings await a host verifier returning a typed verified
statement; a peer's boolean has no authority. The test fixture invokes a fixed
Node verifier executable and trusted paths from process configuration, which
verifies actual BB proofs and cfrm Rust certificates/current-own state. No peer
proof or pair transcript is sent to the named operator.

A pending accounted introduction belongs to its original two device MLS roster.
Its peer proof exposes the reservation's ownerAuthority only to the peer; the
trusted verifier binds that leaf to the original verified delegation/device.
Another authorized sibling cannot bind or release that pending introduction.
Roster expansion waits until the contact is established. Moving a pending first
contact to another device requires closure and a fresh admitted introduction;
recovery does not silently transfer first-payload authority. Established devices
can still exchange and synchronize authenticated accepted history.

A device needs one durable writer. Browser persistence includes expectedVersion
and nextVersion for an atomic IndexedDB comparison; concurrent restored copies
must fail the comparison. Native hosts provide equivalent serialization.
Restored/synchronized gates retain evidence and restrictions, but require fresh
trusted binding before application release. The host invalidates a gate before
publishing an accepted own accounting state that removes its obligation.

A remote Active acceptance proves a past accepted state, not non-supersession.
A fresh challenge does not change that fact. Local contact/closure, exact nonce,
lease, current-own state and one-introduction rules remain mandatory. There is
no claim that both remote budgets remain locked at one instantaneous global
time. Full rollback of every copy or deliberate device-key cloning remains
outside local journal guarantees.

Native test doubles exercise authorization/storage boundaries; they are not
proof-validity evidence. Actual proof composition and native/Wasm/IndexedDB
results must identify the tested revisions. Source additions alone are not
validation results.

Verification runs remote proof work first, refreshes the trusted contact context,
and queries current own state last. A verifier also returns `validUntil` as
trusted metadata, separate from the proof statement. It bounds the common
policy expiry, reservation lease and original reserved device delegation expiry.
The accepted accounting request's commit horizon is not the Active state's
lifetime. Binding and first-payload release independently require time strictly
before both verification bounds. Browser cached verdicts match the complete
device, role, tuple, evidence digest and verification mode, permit forward time
within that bound, and reject clock rollback.

Current-own verification is a snapshot, not a lock across verification, network
I/O and persistence. The embedding serializes own accounting updates and Inbox
publication and invalidates the gate when the accepted own obligation changes.
The fixture's actual Close checkpoint is read back and restored before it emits
accounting evidence; signatures cannot substitute for durable local history.
