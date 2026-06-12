# Changelog

All notable changes to `sl-mpc-vrf` are documented in this file.

## [Unreleased]

## [0.1.0-pre.2] - 2026-05-27

### Changed

- VRF DKG P2P shares are plaintext ([`P2pShare`](src/dkg/crypto.rs)) instead of `crypto_box` ciphertexts; removed `generate_pki`, `encrypt_message`, and `decrypt_message`.
- [`VrfDkgContext::new`](src/dkg/context.rs) takes only [`Party`](src/dkg/context.rs) and an RNG (no encryption key material).
- The `serde` feature also enables `sl-mpc-mate/serde`, so DKG [`Party`](src/dkg/context.rs) and [`Context`](src/dkg/context.rs) can be serialized when `serde` is enabled.

### Fixed

- [`sl-mpc-derive`](https://crates.io/crates/sl-mpc-derive) is now a required dependency (not optional) so consumers using `default-features = false` still compile.

### Added

- VRF eval integration tests: 2-of-3 and 3-of-3 quorums, deterministic output checks, and malformed keyshare rejection.

### Dependencies

- Requires [`sl-mpc-derive`](https://crates.io/crates/sl-mpc-derive) **0.1.0** with the `vrf` feature.

## [0.1.0] - 2026-05-27

### Added

- Initial release: threshold MPC VRF on Ristretto per the [Coinbase MPC VRF spec](https://github.com/coinbase/cb-mpc/blob/master/docs/spec/vrf-spec.pdf).
- **VRF DKG** (`dkg`): Shamir key generation with encrypted round-1 payloads, discrete-log proofs, and [`VrfKeyshare`](src/dkg/messages.rs) output.
- **VRF evaluation** (`eval`): three-round MPC protocol with [`VrfOutput`](src/eval/context.rs).
- **DH-tuple proofs** (`dh_tuple`) and shared **crypto** / **transcript** helpers.
- Optional **`serde`** feature for wire message serialization.
- Dependency on [`sl-mpc-derive`](https://crates.io/crates/sl-mpc-derive) `0.1.0` with the `vrf` feature.

[0.1.0-pre.2]: https://github.com/silence-laboratories/multi-party-schnorr/compare/sl-mpc-vrf/v0.1.0...sl-mpc-vrf/v0.1.0-pre.2
[0.1.0]: https://github.com/silence-laboratories/multi-party-schnorr/releases/tag/sl-mpc-vrf/v0.1.0
