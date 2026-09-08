# cmsg

Private text messaging with encrypted local state and an explicit metadata-privacy boundary.

This repository contains an experimental Rust client built on OpenMLS, with encrypted local snapshots and authenticated community identities. Its tests exercise real pair and 100-member text exchanges, membership changes, tamper recovery and replay rejection. Android and iOS Rust target checks pass; native applications, device passkeys and background networking still require integration and device testing.

It is not yet a deployable anonymous messenger. Onion-only transport fails closed; public Tor connectivity has not passed its experiment. Admission, participation rules, durable device state and transport must be composed before deployment. See the implementation study for the precise tested boundaries and remaining work.

- [Messaging contract](docs/contract.md)
- [Component boundaries](docs/components.md)
- [Reuse study](studies/messaging-components.md)
- [Implementation and security experiments](studies/implementation-experiments.md)
- [Passing 100-member and mobile-target checks](https://github.com/corbet-labs/cmsg/actions/runs/34257557064)
- [Experiments](experiments/README.md)

License: [FSL-1.1-ALv2](LICENSE.md). Third-party dependencies retain their own licenses.
