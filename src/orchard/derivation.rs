use ff::PrimeField;
use garbled_circuit::{
    functionality::{
        circuit_eval::yao_circuit_eval_functionality, output::output_yao_functionality,
        utils::FilteredMsgRelay, utils_dep::ProtocolError,
    },
    utilities::{
        commitments::Commitment,
        hash_function::HashFunction,
        types::{YaoSetup, YaoShare},
    },
};
use sl_compute_common::CommonRandomness;
use sl_messages::{relay::Relay, setup::ProtocolParticipant};
use zcash::{
    shamir_to_rss::run_shamir_to_scalar_rss_pallas, utils::bytes_to_bits_be,
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

#[cfg(test)]
mod tests {

    use garbled_circuit::{
        functionality::{
            output::batch_output_yao_functionality,
            setup::setup_yao_functionality,
            utils::{FilteredMsgRelay, SetupMessage},
            utils_dep::ProtocolError,
        },
        utilities::{commitments::HashCommitment, hash_function::AesHash, types::YaoSetup},
    };

    use rand::{rngs::StdRng, SeedableRng};

    use sl_compute_common::BinaryString;
    use sl_messages::{relay::Relay, setup::ProtocolParticipant};

    use crate::{
        common::{redpallas::RedPallasPoint, utils::support::run_keygen}, keygen::Keyshare,
        orchard::derivation::run_orchard_key_components,
    };

    async fn test_run_orchard_key_components<S, R>(
        setup: S,
        keyshare: Keyshare<RedPallasPoint>,
        relay: R,
    ) -> Result<(usize, Vec<bool>), ProtocolError>
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

        Ok((setup.participant_index(), out))
    }

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
    ) -> Vec<bool> {
        use sl_messages::relay::SimpleMessageRelay;

        let mut parties = tokio::task::JoinSet::new();
        let coord = SimpleMessageRelay::new();
        for (setup, _) in run_init(None) {
            let relay = coord.connect();
            let pid = setup.participant_index();
            parties.spawn(test_run_orchard_key_components(
                setup,
                keyshare[pid].clone(),
                relay,
            ));
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

        assert_eq!(shares[0].1, shares[2].1);
        assert_eq!(shares[0].1, shares[1].1);

        shares[0].1.clone()
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_zcash_dkg() {
        let out: [Keyshare<RedPallasPoint>; 3] = run_keygen::<2, 3, RedPallasPoint>();

        let out = test_orchard_key_components_util(out).await;
        let mut ask_i = BinaryString::new();
        let mut nk_i = BinaryString::new();
        let mut rivk_i = BinaryString::new();
        for i in &out[0..512] {
            ask_i.push(*i);
        }
        for i in &out[512..1024] {
            nk_i.push(*i);
        }
        for i in &out[1024..] {
            rivk_i.push(*i);
        }
        println!("ask_i: {:?}", hex::encode(ask_i.value));
        println!("nk_i: {:?}", hex::encode(nk_i.value));
        println!("rivk_i: {:?}", hex::encode(rivk_i.value));
    }
}
