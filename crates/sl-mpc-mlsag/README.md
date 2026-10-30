# sl-mpc-mlsag

Threshold setup and signing for MobileCoin-style MLSAG keys on Ristretto.

## DKG

[`MlsagDkgContext`](src/dkg.rs) runs Feldman–Shamir keygen of the root spend key `b` with `B = b·G`, and then has all `n` parties assemble `I_B = b * H_p(B)`.

`H_p(P) = Blake2b-512("mc_onetime_key_hash_to_point" || compress(P))`. Each partial `I_j` has a DH-tuple proof.

Output is [`MlsagKeyshare`](src/messages.rs): Shamir share of `b`, public key `B`, and `I_B`. DKG runs once.

## DSG

Each output is spent with its one-time key `x = b + t` and `P = B + t·G`. The public tweak `t = Hs(a || i) + Hs(a·R)` comes from whoever holds the view key `a`; this crate takes `t` as given. Signers check that `P` is the real ring member and bind `B`, `t` and `P` into the session id. With `t = 0` the output key is `B` and the key image is `I_B`.

[`MlsagSignContext`](src/sign.rs) closes the spend response. Amounts, blindings, decoys, and Bulletproofs stay with whoever knows `z` (no amount confidentiality in MPC).

1. Each signer samples a fresh session id and commits to it together with `(L0_j, R0_j) = (α0,j·G, α0,j·H_p(P))`. The first message is that session id and the commitment.
2. After every commitment is in, the signer hashes those session ids into one session id, proves the DH tuple under that id, and opens the nonce. The same message carries its key-image share `I_j = k_j·H_p(P)` with `k_j = λ_j·(b_j + t)` and a DH-tuple proof against `k_j·G`. Every signer checks each share and sums `I = x·H_p(P)`, the output's key image.
3. Whoever knows `z` sums the opened nonces and calls [`fill_ring`](src/ring_mlsag.rs) with that key image.
4. Parties return `r_{π,0}^{(j)} = α0,j − c_π·k_j`. The sum is the MobileCoin spend response.

[`RingMLSAG::verify`](src/ring_mlsag.rs) checks the signature with the MobileCoin challenge tag `mc_ring_mlsag_challenge`. The verifier does not see `t`.
