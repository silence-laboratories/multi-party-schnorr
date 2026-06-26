# Changelog



## [Unreleased]

## [1.3.0-pre.6] - 2026-06-26

### Changed

- [`Bip32Public`](src/common/soft_derive.rs) soft derivation now follows the Cardano BIP32-Ed25519 scheme using **two** HMAC-SHA512 evaluations keyed by the parent chain code (instead of a single HMAC): child key = `HMAC(chain_code, 0x02 || pk (32 bytes) || child index LE)[0..32]` and child chain code = `HMAC(chain_code, 0x03 || pk (32 bytes) || child index LE)[32..64]` (Ed25519 / Taproot).
- New [`ChildHmacData`](src/common/soft_derive.rs) enum (`Joint` / `Separate`) lets each [`SoftDeriveChildHmac`](src/common/soft_derive.rs) format choose the single- or two-HMAC layout; [`Legacy`](src/common/soft_derive.rs) stays single-HMAC.

### Added

- Soft-derivation format unit tests for `Joint` vs `Separate` bodies (prefix bytes, hardened-child rejection, RedPallas unsupported) and a BIP32-Ed25519 (Cardano) `m/0/1/2` derivation test vector.

### Breaking

- `Bip32Public` derived keys and chain codes change versus the previous single-HMAC `0x03` layout; child keys derived with the old scheme are not compatible.

[1.3.0-pre.6]: https://github.com/silence-laboratories/multi-party-schnorr/compare/multi-party-schnorr/v1.3.0-pre.3...multi-party-schnorr/v1.3.0-pre.6

## [1.3.0-pre.3] - 2026-06-11

### Added

- Workspace crate [`sl-mpc-vrf`](crates/sl-mpc-vrf/) (`0.1.0-pre.2`): shared threshold VRF **DKG** and **eval** wire protocols on Ristretto.
- [`vrf::dkg`](src/vrf/dkg.rs): Shamir VRF DKG (Protocol 12) via [`VrfDkgParty`](src/vrf/dkg.rs), [`VrfDkgR0`](src/vrf/dkg.rs) / [`VrfDkgR1`](src/vrf/dkg.rs) / [`VrfDkgR2`](src/vrf/dkg.rs), [`VrfKeygenMsg1`](src/vrf/dkg.rs) / [`VrfKeygenMsg2`](src/vrf/dkg.rs), and [`setup_vrf_keygen`](src/vrf/dkg.rs).
- [`run_vrf_keygen`](src/vrf/dkg.rs) test helper (`test-support`) for local VRF DKG runs.
- VRF eval integration tests (2-of-3 / 3-of-3 quorums, malformed keyshare rejection).

### Changed

- **`vrf` feature** now depends on [`sl-mpc-vrf`](crates/sl-mpc-vrf/) `0.1.0-pre.2` (with `serde`); VRF DKG and eval in this crate are thin [`Round`] adapters over `sl_mpc_vrf`.
- **VRF DKG protocol**: dedicated Shamir VRF DKG replaces EdDSA-style [`KeygenParty`](src/keygen/dkg.rs) on [`VrfPoint`](src/derive/impls/ristretto.rs); P2P shares are **plaintext** (no `crypto_box` / PKI for VRF keygen).
- [`setup_vrf_keygen`](src/vrf/dkg.rs) returns `Result<Vec<VrfDkgParty<VrfDkgR0>>, VrfKeygenError>` instead of panicking on invalid `(t, n)`.
- [`VrfOutput`](src/vrf/eval.rs) is re-exported from `sl_mpc_vrf`; VRF eval logic moved out of this crate.
- DH-tuple proof helpers used by VRF eval moved to `sl_mpc-vrf`; `sl-transcript` is no longer a direct dependency of `multi-party-schnorr`.
- Hard-derivation tests obtain VRF keyshares from [`run_vrf_keygen`](src/vrf/dkg.rs) rather than [`run_keygen`](src/common/utils.rs) on `VrfPoint`.

### Breaking

- **VRF DKG wire format and session API changed** (`VrfKeygenMsg1` / `VrfKeygenMsg2`, no encryption keys). WASM and host integrations must use the new VRF DKG path before hard derivation.
- VRF key material from the old `KeygenParty<VrfPoint>` DKG is **not** compatible with the new Shamir VRF DKG output.

[1.3.0-pre.3]: https://github.com/silence-laboratories/multi-party-schnorr/compare/multi-party-schnorr/v1.3.0-pre.2...multi-party-schnorr/v1.3.0-pre.3

## [1.3.0-pre.2] - 2026-06-04

### Added

- Pluggable **soft-derivation HMAC layouts** via marker types [`Legacy`](src/common/soft_derive.rs) and [`Bip32Public`](src/common/soft_derive.rs), with the [`SoftDeriveChildHmac`](src/common/soft_derive.rs) trait.
- [`Keyshare::derive_with_offset`](src/keygen/messages.rs) and [`Keyshare::derive_child_pubkey`](src/keygen/messages.rs) select the HMAC layout via a type parameter (e.g. `derive_with_offset::<Legacy>(path)`).
- [`SignerParty::new_with_format`](src/sign/shared_rounds.rs) for explicit format at sign setup (`new_with_format::<_, Bip32Public>(...)`); [`SignerParty::new`](src/sign/shared_rounds.rs) defaults to `Legacy`.
- [`DeriveParty<G, F>`](src/soft_derive.rs) is generic over the format marker (`PhantomData<F>`).

### Changed

- Soft derivation: HMAC **key** is parent chain code; **message** is built by the selected format (`Legacy`: pubkey bytes + child index BE; `Bip32Public`: `0x02 || pk[32] || child index LE` on Ed25519/Taproot; not supported on RedPallas).
- Signing tests exercise `SignerParty::new`, `new_with_format::<_, Legacy>`, and `new_with_format::<_, Bip32Public>`; internal helpers share `finish_sign_rounds` to avoid duplicating MPC round loops.

[1.3.0-pre.2]: https://github.com/silence-laboratories/multi-party-schnorr/compare/d113ca2999dcd183d53487867f928993d49a555f...HEAD

## [1.3.0-pre.1] - 2026-05-27

### Added

- **`vrf` feature**: threshold MPC VRF on Ristretto ([Coinbase MPC VRF spec](https://github.com/coinbase/cb-mpc/blob/master/docs/spec/vrf-spec.pdf)), exposed under [`crate::vrf`](src/vrf/).
- **`sl-mpc-derive` companion crate** ([`crates/sl-mpc-derive`](crates/sl-mpc-derive/), `0.1.0`) for VRF-backed **hard derivation** of child threshold signing keys (Ed25519 and secp256k1).
- [`MpcDeriveInit::with_ristretto_vrf`](src/vrf/hard_derivation.rs), [`HardDeriveParty`](src/vrf/hard_derivation.rs), and `keyshare_after_hard_derive` entry points.
- Per-party VRF additive public shares on `Keyshare` when `vrf` is enabled.
- README section on threshold MPC VRF and hard derivation.

[1.3.0-pre.1]: https://github.com/silence-laboratories/multi-party-schnorr/compare/7511971e757a2260afa797283cf239c9cdfd5f19...d113ca2999dcd183d53487867f928993d49a555f

## [1.2.0-pre.1] - 2026-02-10

### Added

- **`redpallas` feature**: threshold RedDSA signing over Pallas (Zcash Orchard–compatible; verifiable with the `reddsa` crate).
- Re-randomization support for RedPallas key material.

### Changed

- Serde support for RedPallas signing types and messages ([#40](https://github.com/silence-laboratories/multi-party-schnorr/pull/40)).

[1.2.0-pre.1]: https://github.com/silence-laboratories/multi-party-schnorr/compare/multi-party-schnorr/v1.1.0...7511971e757a2260afa797283cf239c9cdfd5f19

## [1.1.0] - 2026-01-13

### Added

- **DKG session** API ([#34](https://github.com/silence-laboratories/multi-party-schnorr/pull/34)).
- **Server session** API for orchestrating protocol rounds ([#38](https://github.com/silence-laboratories/multi-party-schnorr/pull/38)).
- `Serialize` / `Deserialize` for `KeygenParty` and signing party state ([#32](https://github.com/silence-laboratories/multi-party-schnorr/pull/32)).

### Changed

- Minimum supported Rust version bumped (see `rust-version` in `Cargo.toml`) ([#33](https://github.com/silence-laboratories/multi-party-schnorr/pull/33)).

[1.1.0]: https://github.com/silence-laboratories/multi-party-schnorr/compare/1.0.0-beta...multi-party-schnorr/v1.1.0

## [1.0.0-beta] - 2025-05-09

### Added

- `Keyshare::final_session_id` and optional `keyshare-session-id` feature for DSG session-id derivation ([#25](https://github.com/silence-laboratories/multi-party-schnorr/pull/25)).
- `SECURITY.md` and expanded README / license packaging ([#30](https://github.com/silence-laboratories/multi-party-schnorr/pull/30)).

### Fixed

- Post-audit fixes ([#22](https://github.com/silence-laboratories/multi-party-schnorr/pull/22)).
- Key refresh respects `root_chain_code` from callers ([#24](https://github.com/silence-laboratories/multi-party-schnorr/pull/24)).
- Chain code handling for parties with lagging key shares ([#27](https://github.com/silence-laboratories/multi-party-schnorr/pull/27)).
- Typo: `reset_constant()` vs `reset_contant()` ([#29](https://github.com/silence-laboratories/multi-party-schnorr/pull/29)).

[1.0.0-beta]: https://github.com/silence-laboratories/multi-party-schnorr/compare/v0.1.2-beta...1.0.0-beta

## [0.1.2-beta] - 2025-02-18

### Added

- **Quorum change**: add or remove participants while preserving the threshold key ([#13](https://github.com/silence-laboratories/multi-party-schnorr/pull/13)).
- **Soft derivation** with BIP32-style chain codes ([#12](https://github.com/silence-laboratories/multi-party-schnorr/pull/12)).

### Fixed

- Taproot signing ([#17](https://github.com/silence-laboratories/multi-party-schnorr/pull/17)).
- Encryption of root chain messages in refresh ([#18](https://github.com/silence-laboratories/multi-party-schnorr/pull/18)).
- Chain code propagation during quorum change ([#16](https://github.com/silence-laboratories/multi-party-schnorr/pull/16)).
- Serialization of `KeyRefreshData<ProjectivePoint>` ([#15](https://github.com/silence-laboratories/multi-party-schnorr/pull/15)).

[0.1.2-beta]: https://github.com/silence-laboratories/multi-party-schnorr/compare/v0.1.0-beta...v0.1.2-beta

## [0.1.0-beta] - 2025-02-07

### Fixed

- Post-audit fixes ([#11](https://github.com/silence-laboratories/multi-party-schnorr/pull/11)).

[0.1.0-beta]: https://github.com/silence-laboratories/multi-party-schnorr/releases/tag/v0.1.0-beta
