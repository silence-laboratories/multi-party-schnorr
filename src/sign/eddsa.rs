// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use curve25519_dalek::{EdwardsPoint, Scalar};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use elliptic_curve::group::GroupEncoding;
use sha2::{Digest, Sha512};

use crate::common::traits::Round;

use super::{
    messages::{SignComplete, SignMsg3},
    validate_input_messages, PartialSign, SignError, SignReady,
};

impl Round for SignReady<EdwardsPoint> {
    type InputMessage = ();
    type Input = ();
    type Error = SignError;
    type Output = (PartialSign<EdwardsPoint>, SignMsg3<EdwardsPoint>);

    /// The signer party processes the message to sign and returns the partial signature
    /// # Arguments
    fn process(self, _: Self::Input) -> Result<Self::Output, Self::Error> {
        let big_a = self.public_key.to_bytes();

        let digest = Sha512::new()
            .chain_update(self.big_r.to_bytes())
            .chain_update(big_a)
            .chain_update(&self.message)
            .finalize()
            .into();

        let e = Scalar::from_bytes_mod_order_wide(&digest);
        let s_i = self.k_i + self.d_i * e;

        let msg3 = SignMsg3 {
            from_party: self.party_id,
            session_id: self.session_id,
            s_i,
            #[cfg(feature = "ad")]
            auth_proof: self.auth_proof,
        };

        let next = PartialSign {
            party_id: self.party_id,
            session_id: self.session_id,
            public_key: self.public_key,
            big_r: self.big_r,
            s_i,
            msg_to_sign: self.message,
            pid_list: self.pid_list,
        };

        Ok((next, msg3))
    }
}

impl Round for PartialSign<EdwardsPoint> {
    type InputMessage = SignMsg3<EdwardsPoint>;
    type Input = Vec<SignMsg3<EdwardsPoint>>;
    type Error = SignError;
    type Output = (Signature, SignComplete);

    fn process(self, messages: Self::Input) -> Result<Self::Output, Self::Error> {
        let messages = validate_input_messages(messages, &self.pid_list)?;
        let mut s = self.s_i;
        for msg in messages {
            if msg.from_party == self.party_id {
                continue;
            }
            s += msg.s_i;
        }

        let mut sig_bytes = [0u8; 64];
        sig_bytes[..32].copy_from_slice(&self.big_r.to_bytes());
        sig_bytes[32..].copy_from_slice(&s.to_bytes());
        let signature = ed25519_dalek::Signature::from_bytes(&sig_bytes);

        VerifyingKey::from(self.public_key)
            .verify(&self.msg_to_sign, &signature)
            .map_err(|_| SignError::InvalidSignature)?;

        let sign_complete = SignComplete {
            from_party: self.party_id,
            session_id: self.session_id,
            signature: sig_bytes,
        };

        Ok((signature, sign_complete))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use curve25519_dalek::EdwardsPoint;
    #[cfg(feature = "ad")]
    use ed25519_dalek::VerifyingKey;
    use rand::seq::SliceRandom;

    use super::*;

    use crate::{
        common::utils::support::{run_keygen, run_round},
        keygen::Keyshare,
        sign::SignerParty,
    };

    fn run_sign(shares: Vec<Keyshare<EdwardsPoint>>) -> Signature {
        let msg = b"The Times 03/Jan/2009 Chancellor on brink of second bailout for banks";

        let mut rng = rand::thread_rng();

        let parties = shares
            .into_iter()
            .map(Arc::new)
            .map(|keyshare| {
                SignerParty::<_, EdwardsPoint>::new(
                    keyshare,
                    msg.into(),
                    "m/0".parse().unwrap(),
                    &mut rng,
                )
            })
            .collect::<Vec<_>>();

        let (parties, msgs): (Vec<_>, Vec<_>) = run_round(parties, ()).into_iter().unzip();
        let (parties, msgs): (Vec<_>, Vec<_>) = run_round(parties, msgs).into_iter().unzip();
        let ready_parties = run_round(parties, msgs);

        let (parties, partial_sigs): (Vec<_>, Vec<_>) =
            run_round(ready_parties, ()).into_iter().unzip();

        let (signatures, _complete_msg): (Vec<_>, Vec<_>) =
            run_round(parties, partial_sigs).into_iter().unzip();

        signatures[0]
    }

    #[cfg(feature = "ad")]
    fn run_sign_with_auth_data(shares: Vec<Keyshare<EdwardsPoint>>) -> Signature {
        run_sign_with_auth_data_inner(
            shares,
            b"Update your infra to PQ secures systems",
            b"SL is securing the world",
        )
        .0
    }

    #[cfg(feature = "ad")]
    fn run_sign_with_auth_data_inner(
        shares: Vec<Keyshare<EdwardsPoint>>,
        msg: &[u8],
        auth_data: &[u8],
    ) -> (
        Signature,
        crate::sign::auth_data::AssociatedDataProof,
        VerifyingKey,
        EdwardsPoint,
    ) {
        let mut rng = rand::thread_rng();

        let parties = shares
            .into_iter()
            .map(Arc::new)
            .map(|keyshare| {
                SignerParty::<_, EdwardsPoint>::new_with_auth_data(
                    keyshare,
                    msg.into(),
                    "m/0".parse().unwrap(),
                    auth_data.to_vec(),
                    &mut rng,
                )
            })
            .collect::<Vec<_>>();

        let (parties, msgs): (Vec<_>, Vec<_>) = run_round(parties, ()).into_iter().unzip();
        let (parties, msgs): (Vec<_>, Vec<_>) = run_round(parties, msgs).into_iter().unzip();
        let ready_parties = run_round(parties, msgs);

        let (parties, msg3s): (Vec<_>, Vec<_>) =
            run_round(ready_parties, ()).into_iter().unzip();

        let auth_proof = msg3s[0].auth_proof;
        let vk = VerifyingKey::from(parties[0].public_key);
        let pk = parties[0].public_key;

        let (signatures, _complete_msg): (Vec<_>, Vec<_>) =
            run_round(parties, msg3s).into_iter().unzip();

        let sig = signatures[0];
        assert!(
            auth_proof.verify(&vk, msg, &sig, auth_data, &pk),
            "AssociatedDataProof::verify failed"
        );

        (sig, auth_proof, vk, pk)
    }

    #[test]
    fn sign_2_2() {
        let shares = run_keygen::<2, 2, EdwardsPoint>();
        let subset: Vec<_> = shares
            .choose_multiple(&mut rand::thread_rng(), 2)
            .cloned()
            .collect();
        run_sign(subset);
    }

    #[test]
    fn sign_2_3() {
        let shares = run_keygen::<2, 3, EdwardsPoint>();
        let subset: Vec<_> = shares
            .choose_multiple(&mut rand::thread_rng(), 2)
            .cloned()
            .collect();
        run_sign(subset);
    }

    #[test]
    fn sign_2_3_3() {
        let shares = run_keygen::<2, 3, EdwardsPoint>();
        let subset: Vec<_> = shares
            .choose_multiple(&mut rand::thread_rng(), 3)
            .cloned()
            .collect();
        run_sign(subset);
    }

    #[test]
    fn sign_3_3() {
        let shares = run_keygen::<3, 3, EdwardsPoint>();
        let subset: Vec<_> = shares
            .choose_multiple(&mut rand::thread_rng(), 3)
            .cloned()
            .collect();
        run_sign(subset);
    }

    #[test]
    fn sign_3_5() {
        let shares = run_keygen::<3, 5, EdwardsPoint>();
        let subset: Vec<_> = shares
            .choose_multiple(&mut rand::thread_rng(), 3)
            .cloned()
            .collect();
        run_sign(subset);
    }

    #[test]
    fn sign_5_10() {
        let shares = run_keygen::<5, 10, EdwardsPoint>();
        let subset: Vec<_> = shares
            .choose_multiple(&mut rand::thread_rng(), 5)
            .cloned()
            .collect();
        run_sign(subset);
    }

    #[cfg(feature = "ad")]
    #[test]
    fn sign_2_3_with_auth_data() {
        let shares = run_keygen::<2, 3, EdwardsPoint>();
        let subset: Vec<_> = shares
            .choose_multiple(&mut rand::thread_rng(), 2)
            .cloned()
            .collect();
        run_sign_with_auth_data(subset);
    }

    /// Micro-benchmark extra proving and verification for associated-data EdDSA.
    ///
    /// Run with:
    /// `cargo test --release --features "eddsa,ad,test-support" bench_associated_data_1000 -- --ignored --nocapture`
    #[cfg(feature = "ad")]
    #[test]
    #[ignore]
    fn bench_associated_data_1000() {
        use std::hint::black_box;
        use std::time::{Duration, Instant};

        use crate::sign::auth_data::AssociatedDataProof;
        use elliptic_curve::group::GroupEncoding;

        const N: usize = 1000;
        const MICRO_ITERS: usize = 10_000;

        fn stats_ns(samples: &[u128]) -> (u128, f64, f64, u128, u128, u128) {
            let n = samples.len() as f64;
            let sum: u128 = samples.iter().sum();
            let mean = sum as f64 / n;
            let var = samples
                .iter()
                .map(|&x| {
                    let d = x as f64 - mean;
                    d * d
                })
                .sum::<f64>()
                / n;
            let mut sorted = samples.to_vec();
            sorted.sort_unstable();
            let median = sorted[sorted.len() / 2];
            (
                sum,
                mean,
                var.sqrt(),
                median,
                sorted[0],
                *sorted.last().unwrap(),
            )
        }

        let msg = b"Update your infra to PQ secures systems";
        let auth_data = b"SL is securing the world";
        let shares = run_keygen::<2, 3, EdwardsPoint>();
        let subset: Vec<_> = shares
            .choose_multiple(&mut rand::thread_rng(), 2)
            .cloned()
            .collect();

        let mut prove_extra_ns = Vec::with_capacity(N);
        let mut verify_ns = Vec::with_capacity(N);
        let mut proof_sizes = Vec::with_capacity(N);
        let mut last_proof = None;
        let mut last_sig = None;
        let mut last_vk = None;
        let mut last_pk = None;

        let protocol_start = Instant::now();
        for i in 0..N {
            let (sig, proof, vk, pk) =
                run_sign_with_auth_data_inner(subset.clone(), msg, auth_data);

            let t0 = Instant::now();
            let tweak = AssociatedDataProof::ro(auth_data, &pk, &proof.big_r_prime);
            let _tweaked = black_box(proof.big_r_prime * tweak);
            let _k = black_box(tweak * tweak);
            prove_extra_ns.push(t0.elapsed().as_nanos());

            let t1 = Instant::now();
            let ok = proof.verify(&vk, msg, &sig, auth_data, &pk);
            verify_ns.push(t1.elapsed().as_nanos());
            assert!(ok, "verification failed at iteration {i}");

            proof_sizes.push(proof.big_r_prime.to_bytes().len());
            last_proof = Some(proof);
            last_sig = Some(sig);
            last_vk = Some(vk);
            last_pk = Some(pk);
        }
        let protocol_wall = protocol_start.elapsed();

        let proof = last_proof.unwrap();
        let sig = last_sig.unwrap();
        let vk = last_vk.unwrap();
        let pk = last_pk.unwrap();
        let proof_size = proof.big_r_prime.to_bytes().len();

        for _ in 0..1_000 {
            let tweak = AssociatedDataProof::ro(auth_data, &pk, &proof.big_r_prime);
            let _ = black_box(proof.big_r_prime * tweak);
            let _ = black_box(tweak * tweak);
        }
        let t_prove = Instant::now();
        for _ in 0..MICRO_ITERS {
            let tweak = AssociatedDataProof::ro(
                black_box(auth_data),
                black_box(&pk),
                black_box(&proof.big_r_prime),
            );
            let _ = black_box(proof.big_r_prime * black_box(tweak));
            let _ = black_box(black_box(tweak) * black_box(tweak));
        }
        let prove_micro_total = t_prove.elapsed();

        for _ in 0..100 {
            assert!(proof.verify(&vk, msg, &sig, auth_data, &pk));
        }
        let t_verify = Instant::now();
        for _ in 0..MICRO_ITERS {
            let ok = proof.verify(
                black_box(&vk),
                black_box(msg),
                black_box(&sig),
                black_box(auth_data),
                black_box(&pk),
            );
            assert!(black_box(ok));
        }
        let verify_micro_total = t_verify.elapsed();

        let (prove_sum, prove_mean, prove_std, prove_med, prove_min, prove_max) =
            stats_ns(&prove_extra_ns);
        let (ver_sum, ver_mean, ver_std, ver_med, ver_min, ver_max) = stats_ns(&verify_ns);

        println!("=== associated-data EdDSA evaluation (N={N}) ===");
        println!("curve: ed25519 (curve25519-dalek)");
        println!("threshold: 2-of-3");
        println!("associated_data_len_bytes: {}", auth_data.len());
        println!("proof_size_bytes: {proof_size}");
        println!(
            "proof_size_min_max: {:?} {:?}",
            proof_sizes.iter().min(),
            proof_sizes.iter().max()
        );
        println!("protocol_wall_1000: {protocol_wall:?}");
        println!(
            "extra_prove_per_run_ns: sum={prove_sum} mean={prove_mean:.2} std={prove_std:.2} median={prove_med} min={prove_min} max={prove_max}"
        );
        println!(
            "verify_per_run_ns: sum={ver_sum} mean={ver_mean:.2} std={ver_std:.2} median={ver_med} min={ver_min} max={ver_max}"
        );
        println!(
            "verify_cumulative_1000_protocol: {:?}",
            Duration::from_nanos(ver_sum as u64)
        );
        println!(
            "extra_prove_micro_{MICRO_ITERS}: total={prove_micro_total:?} mean_ns={}",
            prove_micro_total.as_nanos() as f64 / MICRO_ITERS as f64
        );
        println!(
            "verify_micro_{MICRO_ITERS}: total={verify_micro_total:?} mean_ns={}",
            verify_micro_total.as_nanos() as f64 / MICRO_ITERS as f64
        );
        println!("verify_cumulative_micro_{MICRO_ITERS}: {verify_micro_total:?}");
        println!(
            "BENCH_JSON {{\"n\":{N},\"micro_iters\":{MICRO_ITERS},\"ad_len\":{},\"proof_size\":{proof_size},\"protocol_wall_ms\":{},\"extra_prove_sum_ns\":{prove_sum},\"extra_prove_mean_ns\":{prove_mean},\"extra_prove_std_ns\":{prove_std},\"extra_prove_median_ns\":{prove_med},\"extra_prove_min_ns\":{prove_min},\"extra_prove_max_ns\":{prove_max},\"verify_sum_ns\":{ver_sum},\"verify_mean_ns\":{ver_mean},\"verify_std_ns\":{ver_std},\"verify_median_ns\":{ver_med},\"verify_min_ns\":{ver_min},\"verify_max_ns\":{ver_max},\"prove_micro_total_ns\":{},\"prove_micro_mean_ns\":{},\"verify_micro_total_ns\":{},\"verify_micro_mean_ns\":{}}}",
            auth_data.len(),
            protocol_wall.as_millis(),
            prove_micro_total.as_nanos(),
            prove_micro_total.as_nanos() as f64 / MICRO_ITERS as f64,
            verify_micro_total.as_nanos(),
            verify_micro_total.as_nanos() as f64 / MICRO_ITERS as f64
        );
    }
}
