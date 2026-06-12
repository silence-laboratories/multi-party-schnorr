**Table of Contents**

- [Introduction](#introduction)
- [Features](#features)
- [Installing, Testing, Benchmarks](#installing-testing-benchmarks)
  - [Building](#building)
  - [Running Tests](#running-tests)
  - [Examples](#examples)
- [Implementation Details](#implementation-details)
  - [Threshold MPC VRF and hard derivation](#threshold-mpc-vrf-and-hard-derivation)
  - [Feature Flags](#feature-flags)

<!-- END doctoc generated TOC please keep comment here to allow auto update -->

## Introduction
This is a high-performance threshold EdDSA/Schnorr signing protocol based on the paper [Simple Three-Round Multiparty Schnorr Signing with Full Simulatability](https://eprint.iacr.org/2022/374.pdf).


This is a production-ready, audited implementation  and has undergone a comprehensive [security audit](./docs/Hashcloak-SilenceLaboratories_2025_04_09.pdf) by HashCloak.

## Features

- Distributed Key Generation (DKG)
- Distributed Signature Generation (DSG)
- Key refresh
- Quorum Change: dynamically change the participant set by adding or removing parties
- **Threshold MPC VRF** (`vrf` feature): Shamir VRF DKG and t-of-n VRF evaluation on Ristretto, following the [MPC VRF spec](https://github.com/coinbase/cb-mpc/blob/master/docs/spec/vrf-spec.pdf)
- **VRF-backed hard derivation**: derive child threshold signing keys from a root signing keyshare and a **separate** VRF DKG keyshare (Ed25519 and secp256k1 signing curves)



## Installing, Testing, Benchmarks
### Building
```bash
cargo build
```
### Running Tests
```bash
cargo test
```

With VRF and hard derivation enabled:

```bash
cargo test --features "vrf test-support"
```


### Examples
Under [`examples/`](./examples/) directory there are examples on how to perform keygen, sign and refresh.

Running the examples:
```bash
cargo run --example keygen --features "eddsa test-support"
cargo run --example sign --features "eddsa test-support"
cargo run --example refresh --features "eddsa test-support"
```




## Implementation Details

- This library provides Distributed Key Generation generic over any elliptic curve group that implements the `Group` trait from the `elliptic-curve` crate.
- We currently support threshold Schnorr signing with random nonce over curve25519 and Bitcoin Taproot Schnorr over the secp256k1 curve.

**Not in scope**:
- This library contains only the cryptographic protocol and does not provide any networking functions.
- The parties in the protocol do not authenticate themselves and do not establish e2e secure channels

### Threshold MPC VRF and hard derivation

Enable with the `vrf` Cargo feature (implies `eddsa`, [`sl-mpc-derive`](./crates/sl-mpc-derive/), and [`sl-mpc-vrf`](./crates/sl-mpc-vrf/)). Wire-level VRF DKG and eval live in `sl-mpc-vrf`; this crate exposes them as [`Round`](./src/common/traits.rs) state machines under [`crate::vrf`](./src/vrf/).

**Typical flow**

1. **Root signing DKG** — standard `KeygenParty` on Ed25519 or secp256k1 (unchanged).
2. **VRF DKG** — separate DKG on Ristretto (`VrfPoint`).
3. **VRF eval or hard derivation** — three-round MPC VRF over a quorum of VRF keyshares.
4. **Sign** with the derived root keyshare (hard derive) or use the VRF output directly (eval).

**VRF DKG** ([`vrf::dkg`](./src/vrf/dkg.rs), Protocol 12) produces a Ristretto `Keyshare<VrfPoint>` with per-party additive public shares required for eval. Entry points:

- [`VrfDkgParty`](./src/vrf/dkg.rs) / [`VrfDkgR0`](./src/vrf/dkg.rs) / [`VrfDkgR1`](./src/vrf/dkg.rs) / [`VrfDkgR2`](./src/vrf/dkg.rs) — [`Round`](./src/common/traits.rs) adapter over `sl_mpc_vrf`
- [`VrfKeygenMsg1`](./src/vrf/dkg.rs) / [`VrfKeygenMsg2`](./src/vrf/dkg.rs) — broadcast messages
- [`setup_vrf_keygen(t, n)`](./src/vrf/dkg.rs) — initialize all parties (`Result`, rejects invalid parameters)
- [`run_vrf_keygen`](./src/vrf/dkg.rs) — local full-quorum run (`test-support` only)

**VRF evaluation** ([`vrf::eval`](./src/vrf/eval.rs)): [`VrfParty`](./src/vrf/eval.rs) / [`VrfR0`](./src/vrf/eval.rs) / [`VrfR1`](./src/vrf/eval.rs) / [`VrfR2`](./src/vrf/eval.rs) over `Keyshare<VrfPoint>` from VRF DKG.

**Hard derivation** ([`vrf::hard_derivation`](./src/vrf/hard_derivation.rs)) runs the same three VRF eval rounds on a derivation path, then applies a local tweak to the **root signing** keyshare. The `vrf_keyshare` argument **must** come from VRF DKG above (not from `KeygenParty<VrfPoint>`). Entry points:

- [`MpcDeriveInit::with_ristretto_vrf`](./src/vrf/hard_derivation.rs)(`root_keyshare`, `vrf_keyshare`)
- [`HardDeriveParty`](./src/vrf/hard_derivation.rs) and [`keyshare_after_hard_derive`](./src/vrf/hard_derivation.rs)
- Ed25519 aliases: `MpcDeriveInitEd25519`, `HardDerivePartyEd25519` (with `eddsa` + `vrf`)


### Feature Flags

| Feature              | Default? | Description |
| :---                 |  :---:   | :---        |
| `eddsa`              |    ✓     | Enables signing over curve25519 with ed25519-dalek signing objects compatibility |
| `vrf`                |          | Shamir VRF DKG + MPC VRF eval on Ristretto (`sl-mpc-vrf`) and VRF-backed hard derivation (requires `eddsa`) |
| `taproot`            |          | Enables Bitcoin Taproot Schnorr signing over secp256k1 |
| `redpallas`          |          | Enables RedDSA signing over Pallas (Zcash Orchard–compatible, verifiable with the `reddsa` crate) |
| `session`            |    ✓     | Enables session support (serde + ciborium for encoding) |
| `serde`              |          | Make messages, state and session structures serializable |
| `keyshare-session-id`|          | Enable field `final_session_id` in `Keyshare` structure and use it to calculate session-id for DSG |
| `test-support`       |          | Enable internal helpers and fixtures required by the bundled examples |


## Security

If you discover a vulnerability, please follow the instructions in [SECURITY](SECURITY.md).

## Security Audit

HashCloak has performed a security audit in April, 2025 on the following commit:
- `146d4a57a82c62cf8d24fbd6b713d9bfc7cd534c`

and the report is available here: [security audit](./docs/Hashcloak-SilenceLaboratories_2025_04_09.pdf)


## Contributing

Please refer to [CONTRIBUTING](CONTRIBUTING.md).

## Reach out to us
Don't hesitate to contact us if you need any assistance.

info@silencelaboratories.com

security@silencelaboratories.com

**Happy signing!**
