# Proposed component boundaries

| Component | Responsibility | State boundary |
|---|---|---|
| cvld | Passkey authentication, local credential unlocking and admission eligibility | Client private keys; protected factor/duplicate-use state at the gate; public authentication/verification material; no behavioral sanctions |
| cfrm | Live member discovery and rendezvous | Short-lived presence leases; profiles remain member-held; no offline directory or operator profile store |
| crls, working name | Deterministic quotas, reciprocity, standing and optional epoch votes | Minimal durable anti-reset/double-spend state; private-state proofs are a research dependency |
| cmsg | Private text conversations and encrypted local history | Client-held content and keys; bounded encrypted relay state if selected |

These are repository boundaries. cvld encapsulates both passkeys and eligibility; there is no separate clgn repository. Deployment boundaries are an implementation choice. Authentication should not become a global tracking endpoint. Admission credentials should be presented locally to relying services where possible instead of calling cvld for each message.

A presence lease expires after disconnect or missed heartbeats; a network partition is not instantly detectable. Peers may retain information they have already received. Rules state must survive disconnect or a malicious client can reset allowances. Keeping that state in crls allows cfrm's own live roster to remain transient.

No component accepts content reports, maintains a moderator queue or asks an operator to arbitrate private conversations. Conduct rules operate on protocol-valid numerical events and local recipient choices.

Engineering work must select and test gate trust/expiry mechanisms, client execution and private accounting. Surface material functional tradeoffs such as offline private-message delivery, group-introduction costs or required additional metadata; do not ask the user to choose libraries or implementation mechanics.
