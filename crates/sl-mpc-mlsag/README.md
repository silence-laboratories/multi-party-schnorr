# sl-mpc-mlsag

Threshold setup and signing for MobileCoin-style MLSAG keys on Ristretto.

## DKG

[`MlsagDkgContext`](src/dkg.rs) runs Feldman–Shamir keygen and then has all `n` parties assemble `I = x * H_p(P)`.

`H_p(P) = Blake2b-512("mc_onetime_key_hash_to_point" || compress(P))`. Each partial `I_j` has a DH-tuple proof.

Output is [`MlsagKeyshare`](src/messages.rs): Shamir share of the onetime secret `x`, public key `P`, and key image `I`.

## DSG

[`MlsagSignContext`](src/sign.rs) closes the spend response. Amounts, blindings, decoys, and Bulletproofs stay with whoever knows `z` (no amount confidentiality in MPC).

1. Each signer samples a fresh session id and commits to it together with `(L0_j, R0_j) = (α0,j·G, α0,j·H_p(P))`. The first message is that session id and the commitment.
2. After every commitment is in, the signer hashes those session ids into one session id, proves the DH tuple under that id, and opens the nonce.
3. Whoever knows `z` sums the opened nonces and calls [`fill_ring`](src/ring_mlsag.rs).
4. Parties return `r_{π,0}^{(j)} = α0,j − c_π·k_j`. The sum is the MobileCoin spend response.

[`RingMLSAG::verify`](src/ring_mlsag.rs) checks the signature with the MobileCoin challenge tag `mc_ring_mlsag_challenge`.

The DKG secret `x` is the onetime signing key. 

