//! Shared transaction data must preserve versioned authorization and every
//! input's own index, value, state and creation clocks.
use super::*;

#[tokio::test]
async fn mixed_versions_and_creation_signatures_share_only_the_matching_intent() {
    for versions in [[0, 1, 0, 1], [1, 0, 1, 0]] {
        let fed = Harness::new();
        let owner = key();
        let mut programs = vec![];
        let mut consumed = vec![];
        let mut successors = vec![];
        for (index, version) in versions.into_iter().enumerate() {
            let session = index as u64 + 1;
            let blocks = 10 * session;
            let state = [index as u8; 32];
            let amount = Amount::from_msats(10_000 * session);
            let program = ContractProgram::compile(
                "fn main() {
                    assert!(jet::eq_32(jet::fm_input_count(), 4));
                    assert!(jet::eq_32(jet::fm_current_index(), param::INDEX));
                    assert!(jet::eq_64(jet::fm_current_amount(), param::AMOUNT));
                    assert!(jet::eq_256(jet::fm_current_state(), param::STATE));
                    assert!(jet::eq_64(jet::fm_creation_session(), param::SESSION));
                    assert!(jet::eq_64(jet::fm_creation_block_count(), param::BLOCKS));
                    assert!(jet::eq_64(jet::fm_session_index(), 10));
                    assert!(jet::eq_64(jet::fm_block_count(), 50));
                    assert!(jet::eq_256(jet::fm_output_state(param::INDEX), param::STATE));
                    jet::bip_0340_verify((param::OWNER, jet::fm_sig_hash_all()), witness::SIGNATURE);
                }",
                arguments([
                    ("INDEX", Value::u32(index as u32)),
                    ("AMOUNT", Value::u64(amount.msats)),
                    ("STATE", market::word(state)),
                    ("SESSION", Value::u64(session)),
                    ("BLOCKS", Value::u64(blocks)),
                    ("OWNER", market::word(owner.x_only_public_key().0.serialize())),
                ]),
            ).unwrap();
            let contract = if version == 0 {
                program
                    .output(amount, state, vec![index as u8; 1024])
                    .unwrap()
            } else {
                program
                    .asset_output(amount, state, vec![index as u8; 1024], bundle(&[], &[]))
                    .unwrap()
            };
            fed.vote(blocks).await;
            let (mut funding, sponsor) = sponsored(vec![], vec![output(contract.clone())]);
            sign_transaction(&mut funding, &[sponsor]).unwrap();
            fed.process(&funding, session).await.unwrap();
            programs.push(program);
            consumed.push(point(&funding, 0));
            successors.push(output(contract));
        }
        fed.vote(50).await;

        // Both creation signatures use the same v1 intent as the v1 spends.
        // V0 spends also commit to the actual creation signatures.
        let creators = [key(), key()];
        let mut creations = vec![];
        let mut ids = vec![];
        for (index, creator) in creators.iter().enumerate() {
            let (creation, created) =
                assets::creation(federation_id(), SIMP, creator, vec![4 + index as u32]).unwrap();
            successors.push(output(
                programs[0]
                    .asset_output(Amount::ZERO, [0; 32], vec![], bundle(&[], &created))
                    .unwrap(),
            ));
            creations.push(creation);
            ids.push(created[0]);
        }
        successors.push(output(
            assets::action_output(AssetActions {
                creations,
                ..Default::default()
            })
            .unwrap(),
        ));
        let inputs = programs
            .iter()
            .zip(&consumed)
            .map(|(program, point)| owner_input(program, *point, &owner, placeholder_signature()))
            .collect();
        let (mut tx, sponsor) = sponsored(inputs, successors);
        for creator in &creators {
            assets::sign_creation(&mut tx, federation_id(), SIMP, creator).unwrap();
        }
        let legacy_signature = signature_value(federation_id(), SIMP, &tx, &owner).unwrap();
        let asset_signature = assets::signature_value(federation_id(), SIMP, &tx, &owner).unwrap();
        assert_ne!(legacy_signature, asset_signature);
        for index in 0..4 {
            tx.inputs[index] = owner_input(
                &programs[index],
                consumed[index],
                &owner,
                if versions[index] == 0 {
                    legacy_signature.clone()
                } else {
                    asset_signature.clone()
                },
            );
        }
        let keys = [owner, owner, owner, owner, sponsor];
        sign_transaction(&mut tx, &keys).unwrap();
        fed.check_submission(&tx, 10).await.unwrap();

        for index in 0..4 {
            let mut wrong_version = tx.clone();
            wrong_version.inputs[index] = owner_input(
                &programs[index],
                consumed[index],
                &owner,
                if versions[index] == 0 {
                    asset_signature.clone()
                } else {
                    legacy_signature.clone()
                },
            );
            sign_transaction(&mut wrong_version, &keys).unwrap();
            assert_error(fed.process(&wrong_version, 10).await, "program rejected");
        }
        let mut changed = tx.clone();
        changed.nonce[0] ^= 1;
        sign_transaction(&mut changed, &keys).unwrap();
        assert_error(fed.process(&changed, 10).await, "creation authorization");
        for point in &consumed {
            assert!(fed.contract(*point).await.is_some());
        }

        fed.process(&tx, 10).await.unwrap();
        for point in &consumed {
            assert!(fed.contract(*point).await.is_none());
        }
        let db = fed.db.with_prefix_module_id(SIMP).0;
        let mut dbtx = db.begin_transaction_nc().await;
        for (index, id) in ids.iter().enumerate() {
            assert_eq!(
                dbtx.get_value(&AssetKey(*id))
                    .await
                    .unwrap()
                    .authority_outpoint,
                point(&tx, 4 + index as u64)
            );
        }
    }
}
