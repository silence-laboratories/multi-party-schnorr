# sl-mpc-vrf

Threshold multiparty VRF (verifiable random function) protocols on **Ristretto**, following the [Coinbase MPC VRF specification](https://github.com/coinbase/cb-mpc/blob/master/docs/spec/vrf-spec.pdf).

This crate provides the shared wire-level protocol logic for VRF distributed key generation (DKG) and VRF evaluation. Host libraries (for example [`multi-party-schnorr`](https://github.com/silence-laboratories/multi-party-schnorr) and DKLS23) wrap the round `Context` types in their own session APIs.

## Protocols

| Module | Role |
|--------|------|
| [`dkg`](src/dkg/mod.rs) | Shamir threshold DKG on Ristretto (Protocol 12). Produces a [`VrfKeyshare`](src/dkg/messages.rs) and per-party additive public shares. |
| [`eval`](src/eval/mod.rs) | Three-round MPC VRF evaluation. Consumes a quorum of VRF keyshares and an input message; returns [`VrfOutput`](src/eval/context.rs). |
| [`dh_tuple`](src/dh_tuple.rs) | Discrete-log tuple proofs used during evaluation. |
| [`crypto`](src/crypto.rs) | Shared hashing, session-id derivation, and message validation helpers. |

## Dependencies

- **[`sl-mpc-derive`](https://crates.io/crates/sl-mpc-derive)** (`0.1.0`, `vrf` feature) — Ristretto VRF curve types, hash-to-curve, Lagrange helpers, and output sizing.
- **[`sl-mpc-mate`](https://crates.io/crates/sl-mpc-mate)** — Shamir polynomial arithmetic for DKG.
## Features

| Feature | Description |
|---------|-------------|
| `serde` | `Serialize` / `Deserialize` for protocol messages and keyshares where applicable. |

## Usage sketch

VRF DKG is a two-round protocol after PKI setup:

```rust
use sl_mpc_vrf::{VrfDkgContext, VrfDkgParty};

// Build a per-party Context and run round 1 → round 2.
let party = VrfDkgParty::new(total_parties, threshold, party_id);
let mut ctx = VrfDkgContext::new(party, &mut rng)?;
// ... ctx.round1_out(..), ctx.round1_in(..) → VrfKeygenMsg2, then ctx.round2_in(..) → VrfKeyshare
```

VRF evaluation is three rounds over a quorum of keyshares:

```rust
use sl_mpc_vrf::VrfEvalContext;

let mut ctx = VrfEvalContext::new_with_output_bits(
    party_id,
    threshold,
    total_parties,
    message.to_vec(),
    output_bits,
    shamir_share,
    public_key,
    party_public_shares,
    None,
    &mut rng,
)?;
// ... round 0 (VrfMsg0), round 1 (VrfMsg1), round 2 → VrfOutput
```

Host crates typically adapt these `Context` methods to their `Round` trait or WASM session types.

## Building

From the workspace root:

```bash
cargo build -p sl-mpc-vrf
cargo test -p sl-mpc-vrf
```

With serde support:

```bash
cargo build -p sl-mpc-vrf --features serde
```

## License

Licensed under the Silence Laboratories License Agreement. See [`LICENSE`](../../LICENSE) in the repository root.
