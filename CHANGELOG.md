# Changelog



## [Unreleased]

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
