# Proposed component boundaries

| Component | Responsibility | State boundary |
|---|---|---|
| cvld | Prove admission eligibility from configured factor gates | Protected factor/duplicate-use state at the gate; public verification policy; no behavioral sanctions |
| Authentication module, possible clgn | Passkey possession and local credential unlocking | Client private keys; relying-party public authentication data if remote login is selected |
| cfrm | Live member discovery and rendezvous | Short-lived presence leases; profiles remain member-held; no offline directory or operator profile store |
| crls, working name | Deterministic quotas, reciprocity, standing and optional epoch votes | Minimal durable anti-reset/double-spend state; private-state proofs are a research dependency |
| cmsg | Private text conversations and encrypted local history | Client-held content and keys; bounded encrypted relay state if selected |

These are logical boundaries. Separate deployment and repositories are not automatically necessary for every module. Authentication should not become a global tracking endpoint. Admission credentials should be presented locally to relying services where possible instead of calling cvld for each message.

A presence lease expires after disconnect or missed heartbeats; a network partition is not instantly detectable. Peers may retain information they have already received. Rules state must survive disconnect or a malicious client can reset allowances. Keeping that state in crls allows cfrm's own live roster to remain transient.

No component accepts content reports, maintains a moderator queue or asks an operator to arbitrate private conversations. Conduct rules operate on protocol-valid numerical events and local recipient choices.

Open questions: gate trust and expiry, native versus browser execution, offline private-message delivery, group-introduction costs, and the exact metadata available to the rules verifier.
