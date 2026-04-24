use ff::{FromUniformBytes, PrimeField};
use garbled_circuit::{
    functionality::{
        circuit_eval::yao_circuit_eval_functionality,
        output::{batch_output_yao_functionality, output_yao_functionality},
        setup::setup_yao_functionality,
        utils::FilteredMsgRelay,
        utils_dep::ProtocolError,
    },
    utilities::{
        commitments::{Commitment, HashCommitment},
        hash_function::{AesHash, HashFunction},
        types::{YaoSetup, YaoShare},
    },
};
use pasta_curves::pallas::{Base, Scalar};
use rand::{rngs::StdRng, SeedableRng};
use sl_compute_common::CommonRandomness;
use sl_messages::{relay::Relay, setup::ProtocolParticipant};
use zcash::{
    shamir_to_rss::run_shamir_to_scalar_rss_pallas,
    utils::{bits_to_bytes_le, bytes_to_bits_be},
    zcash::build_zcash_import_function,
};

use crate::{common::redpallas::RedPallasPoint, keygen::Keyshare};

pub async fn run_orchard_key_components<S, R, H, C>(
    setup: &S,
    relay: &mut FilteredMsgRelay<R>,
    keyshare: &Keyshare<RedPallasPoint>,
    randomness: &mut CommonRandomness,
    comm: &C,
    hash: &H,
    yao_setup: &mut YaoSetup,
) -> Result<(Vec<YaoShare>, Vec<YaoShare>, Vec<YaoShare>), ProtocolError>
where
    S: ProtocolParticipant,
    R: Relay,
    H: HashFunction,
    C: Commitment,
{
    use garbled_circuit::functionality::input::run_batch_input_from_all_yao;

    let (rss_prev, rss_next) =
        run_shamir_to_scalar_rss_pallas(setup, relay, keyshare.shamir_share(), randomness).await?;

    let prev = bytes_to_bits_be(&rss_prev.to_repr());
    let next = bytes_to_bits_be(&rss_next.to_repr());

    let mut all_ip = prev;
    all_ip.extend_from_slice(&next);

    let (i1_yao, i2_yao, i3_yao) =
        run_batch_input_from_all_yao(setup, relay, &all_ip, yao_setup, comm).await?;

    let mut inputs = [vec![], vec![], vec![], vec![], vec![], vec![]];

    inputs[0].extend_from_slice(&i1_yao[256..]);
    inputs[1].extend_from_slice(&i2_yao[256..]);
    inputs[2].extend_from_slice(&i3_yao[256..]);

    inputs[3].extend_from_slice(&i1_yao[..256]);
    inputs[4].extend_from_slice(&i2_yao[..256]);
    inputs[5].extend_from_slice(&i3_yao[..256]);

    let circuit = build_zcash_import_function();

    let output =
        yao_circuit_eval_functionality(setup, relay, &inputs, &circuit, hash, yao_setup).await?;

    let out_yao = circuit
        .output_gate_ids()
        .iter()
        .map(|v| output.get(v).unwrap().clone())
        .collect::<Vec<_>>();

    let ver = &out_yao[0];
    let verification = output_yao_functionality(setup, relay, ver).await?;
    if !verification {
        return Err(ProtocolError::VerificationError);
    }
    let mut ask_i = Vec::new();
    let mut nk_i = Vec::new();
    let mut rivk_i = Vec::new();
    for i in &out_yao[1..513] {
        ask_i.push(i.clone());
    }
    for i in &out_yao[513..1025] {
        nk_i.push(i.clone());
    }
    for i in &out_yao[1025..] {
        rivk_i.push(i.clone());
    }

    Ok((ask_i, nk_i, rivk_i))
}

pub async fn run_derivation<S, R>(
    setup: S,
    keyshare: Keyshare<RedPallasPoint>,
    relay: R,
) -> Result<(Scalar, Base, Scalar), ProtocolError>
where
    S: ProtocolParticipant,
    R: Relay,
{
    use garbled_circuit::functionality::utils::run_common_randomness;
    use rand::RngCore;

    let mut relay = FilteredMsgRelay::new(relay);
    let mut rng = StdRng::from_entropy();
    let mut seed = [0u8; 32];
    rng.fill_bytes(&mut seed);

    let mut yao_setup = setup_yao_functionality(&setup, &mut relay).await?;

    let (hash, comm) = match &yao_setup {
        YaoSetup::E(e) => {
            let hash = AesHash::new(e.comm_crs);
            let comm = HashCommitment::new(hash);
            (hash, comm)
        }
        YaoSetup::G(g) => {
            let hash = AesHash::new(g.comm_crs);
            let comm = HashCommitment::new(hash);
            (hash, comm)
        }
    };
    // run setup for serverstate
    let mut randomness = run_common_randomness(&setup, &seed, &mut relay).await?;

    let output = run_orchard_key_components(
        &setup,
        &mut relay,
        &keyshare,
        &mut randomness,
        &comm,
        &hash,
        &mut yao_setup,
    )
    .await?;

    let out = batch_output_yao_functionality(
        &setup,
        &mut relay,
        &[output.0, output.1, output.2].concat(),
    )
    .await?;

    let ask_i = bits_to_bytes_le(&out[0..512]);
    let nk_i = bits_to_bytes_le(&out[512..1024]);
    let rivk_i = bits_to_bytes_le(&out[1024..]);

    let ask = Scalar::from_uniform_bytes(&ask_i.try_into().unwrap());
    let nk = Base::from_uniform_bytes(&nk_i.try_into().unwrap());
    let rivk = Scalar::from_uniform_bytes(&rivk_i.try_into().unwrap());

    Ok((ask, nk, rivk))
}

#[cfg(test)]
mod tests {

    use crate::orchard::derivation::run_derivation;
    use blake2b_simd::Params;
    use ff::{Field, FromUniformBytes, PrimeField};
    use garbled_circuit::functionality::utils::SetupMessage;
    use pasta_curves::pallas::{Base, Scalar};

    use sl_messages::setup::ProtocolParticipant;
    use zcash::utils::get_evaluation;

    use crate::{
        common::{redpallas::RedPallasPoint, utils::support::run_keygen},
        keygen::Keyshare,
    };

    /// Generate setup messages and seeds for parties.
    pub fn run_init(instance: Option<[u8; 32]>) -> Vec<(SetupMessage, [u8; 32])> {
        use std::time::Duration;

        use garbled_circuit::functionality::utils::{NoSigningKey, NoVerifyingKey, SetupMessage};
        use sl_messages::{message::InstanceId, setup::ProtocolParticipant};

        let n = 3;

        let instance = instance.unwrap_or_else(rand::random);

        // a signing key for each party.
        let party_sk: Vec<NoSigningKey> = std::iter::repeat_with(|| NoSigningKey)
            .take(n as usize)
            .collect();

        let party_vk: Vec<NoVerifyingKey> = party_sk
            .iter()
            .enumerate()
            .map(|(party_id, _)| NoVerifyingKey::new(party_id))
            .collect();

        party_sk
            .into_iter()
            .enumerate()
            .map(|(party_id, sk)| {
                SetupMessage::new(InstanceId::new(instance), sk, party_id, party_vk.clone())
                    .with_ttl(Duration::from_secs(1000)) // for dkls-metrics benchmarks
            })
            .map(|setup| {
                use sha2::{Digest, Sha256};

                let mixin = [setup.participant_index() as u8 + 1];

                (
                    setup,
                    Sha256::new()
                        .chain_update(instance)
                        .chain_update(b"party-seed")
                        .chain_update(mixin)
                        .finalize()
                        .into(),
                )
            })
            .collect::<Vec<_>>()
    }

    #[cfg(any(test, feature = "test-support"))]
    async fn test_orchard_key_components_util(
        keyshare: [Keyshare<RedPallasPoint>; 3],
    ) -> [(Scalar, Base, Scalar); 3] {
        use sl_messages::relay::SimpleMessageRelay;

        let mut parties = tokio::task::JoinSet::new();
        let coord = SimpleMessageRelay::new();
        for (setup, _) in run_init(None) {
            let relay = coord.connect();
            let pid = setup.participant_index();
            parties.spawn(run_derivation(setup, keyshare[pid].clone(), relay));
        }

        let mut shares = vec![];

        while let Some(fini) = parties.join_next().await {
            if let Err(ref err) = fini {
                println!("error {err:?}");
            } else {
                match fini.unwrap() {
                    Err(err) => panic!("err {err:?}"),
                    Ok(share) => shares.push(share),
                }
            }
        }

        shares.try_into().unwrap()
    }

    /// PRF^expand_Orchard(sk, t) = BLAKE2b-512("Zcash_ExpandSeed", sk || t)
    fn prf_expand(sk: &[u8; 32], t: u8) -> [u8; 64] {
        let mut hasher = Params::new()
            .hash_length(64)
            .personal(b"Zcash_ExpandSeed")
            .to_state();
        hasher.update(sk);
        hasher.update(&[t]);
        let hash = hasher.finalize();
        let mut res = [0u8; 64];
        res.copy_from_slice(hash.as_bytes());
        res
    }

    pub fn get_ideal_execution(sk: [u8; 32]) -> (Scalar, Base, Scalar) {
        let ask_bytes = prf_expand(&sk, 0x06);
        let ask = Scalar::from_uniform_bytes(&ask_bytes);

        let nk_bytes = prf_expand(&sk, 0x07);
        let nk = Base::from_uniform_bytes(&nk_bytes);

        let rivk_bytes = prf_expand(&sk, 0x08);
        let rivk = Scalar::from_uniform_bytes(&rivk_bytes);

        (ask, nk, rivk)
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_orchard_key_components() {
        let keyshares: [Keyshare<RedPallasPoint>; 3] = run_keygen::<2, 3, RedPallasPoint>();

        let pts = (0..2).map(|v| Scalar::from(v + 1)).collect::<Vec<_>>();

        let sk = get_evaluation(
            &pts,
            &[*keyshares[0].shamir_share(), *keyshares[1].shamir_share()],
            &Scalar::ZERO,
        );
        let (ask_ideal, nk_ideal, rivk_ideal) = get_ideal_execution(sk.to_repr());

        let out = test_orchard_key_components_util(keyshares).await;
        assert_eq!(out[0], out[1]);
        assert_eq!(out[0], out[2]);
        let ask = out[0].0;
        let nk = out[0].1;
        let rivk = out[0].2;

        assert_eq!(ask, ask_ideal);
        assert_eq!(nk, nk_ideal);
        assert_eq!(rivk, rivk_ideal);

        assert!(!bool::from(ask.is_zero()));

        use orchard::{
            keys::FullViewingKey,
            primitives::redpallas::{SigningKey, SpendAuth, VerificationKey},
        };

        let mut ask_eff = ask;
        let ak_bytes = loop {
            let signing_key: SigningKey<SpendAuth> = ask_eff.to_repr().try_into().unwrap();
            let vk: VerificationKey<SpendAuth> = (&signing_key).into();
            let ak_bytes: [u8; 32] = (&vk).into();

            if (ak_bytes[31] >> 7) == 1 {
                // If the last bit of repr_P(ak) is 1, negate ask.
                ask_eff = -ask_eff;
                continue;
            }

            break ak_bytes;
        };

        let mut fvk_bytes = [0u8; 96];
        fvk_bytes[0..32].copy_from_slice(&ak_bytes);
        fvk_bytes[32..64].copy_from_slice(&nk.to_repr());
        fvk_bytes[64..96].copy_from_slice(&rivk.to_repr());

        let fvk = FullViewingKey::from_bytes(&fvk_bytes).expect("valid Orchard FullViewingKey");

        // Derive the incoming viewing keys (ivk) from the full viewing key.
        let internal_ivk = fvk.to_ivk(orchard::keys::Scope::Internal);
        let external_ivk = fvk.to_ivk(orchard::keys::Scope::External);

        // Spec sanity checks: `ivk` must be neither 0 nor ⊥. 
        for ivk in [internal_ivk, external_ivk] {
            let ivk_bytes = ivk.to_bytes();
            assert_ne!(ivk_bytes, [0u8; 64]);
            assert!(bool::from(
                orchard::keys::IncomingViewingKey::from_bytes(&ivk_bytes).is_some()
            ));
        }
    }
}
