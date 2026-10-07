use bitcoin::hashes::{Hash, sha256};
use fedimint_core::config::FederationId;
use fedimint_core::secp256k1::{Keypair, SECP256K1, SecretKey};
use fedimint_core::{Amount, OutPoint, TransactionId};

use crate::common::assets::{AssetAmount, AssetBundle, AssetId};
use crate::{assets, market};

#[test]
fn selection_preserves_other_assets_and_excludes_issuance_authorities() {
    let owner = Keypair::from_secret_key(SECP256K1, &SecretKey::from_slice(&[1; 32]).unwrap());
    let program = market::owner_program(owner.x_only_public_key().0).unwrap();
    let yes = AssetId([1; 32]);
    let no = AssetId([2; 32]);
    let balance = |asset, quantity| AssetAmount { asset, quantity };
    let authority = program
        .asset_output(
            Amount::ZERO,
            [0; 32],
            vec![],
            AssetBundle {
                balances: vec![balance(yes, 100)],
                authorities: vec![yes],
            },
        )
        .unwrap();
    let positions = program
        .asset_output(
            Amount::ZERO,
            [0; 32],
            vec![],
            AssetBundle {
                balances: vec![balance(yes, 10), balance(no, 20)],
                authorities: vec![],
            },
        )
        .unwrap();
    let txid = TransactionId::from_raw_hash(sha256::Hash::hash(b"coin-selection"));
    let first = OutPoint { txid, out_idx: 0 };
    let second = OutPoint { txid, out_idx: 1 };
    let available = [(first, &authority), (second, &positions)];
    let (selected, change) = assets::select_assets(available, &[balance(yes, 4)]).unwrap();
    assert_eq!(selected, vec![second]);
    assert_eq!(change, vec![balance(yes, 6), balance(no, 20)]);
    assert!(assets::select_assets(available, &[balance(yes, 11)]).is_err());
    assert!(
        assets::select_assets(
            [(second, &positions), (second, &positions)],
            &[balance(yes, 15)]
        )
        .is_err()
    );
}

#[test]
fn creation_ids_are_known_before_funding_and_scoped_to_the_module_and_federation() {
    let key = Keypair::from_secret_key(SECP256K1, &SecretKey::from_slice(&[2; 32]).unwrap());
    let federation = FederationId(sha256::Hash::hash(b"first"));
    let (_, ids) = assets::creation(federation, 4, &key, vec![0, 0, 0]).unwrap();
    assert_ne!(ids[0], ids[1]);
    assert_ne!(ids[1], ids[2]);
    let (_, other_module) = assets::creation(federation, 5, &key, vec![0]).unwrap();
    let (_, other_federation) = assets::creation(
        FederationId(sha256::Hash::hash(b"second")),
        4,
        &key,
        vec![0],
    )
    .unwrap();
    assert_ne!(ids[0], other_module[0]);
    assert_ne!(ids[0], other_federation[0]);
}

#[test]
fn creation_signatures_compose_across_instances_in_either_order() {
    use fedimint_core::core::DynOutput;
    use fedimint_core::secp256k1::Message;
    use fedimint_core::transaction::{Transaction, TransactionSignature};

    use crate::common::assets::{AssetActions, AssetExtension, signature_hash_v1};
    let key = Keypair::from_secret_key(SECP256K1, &SecretKey::from_slice(&[3; 32]).unwrap());
    let federation = FederationId(sha256::Hash::hash(b"composable-creation"));
    let program = market::owner_program(key.x_only_public_key().0).unwrap();
    let mut outputs = vec![];
    for (index, module) in [4, 5].into_iter().enumerate() {
        let (creation, ids) =
            assets::creation(federation, module, &key, vec![index as u32 * 2]).unwrap();
        let contract = program
            .asset_output(
                Amount::ZERO,
                [0; 32],
                vec![],
                AssetBundle {
                    balances: vec![],
                    authorities: ids,
                },
            )
            .unwrap();
        outputs.push(DynOutput::from_typed(module, contract));
        outputs.push(DynOutput::from_typed(
            module,
            assets::action_output(AssetActions {
                creations: vec![creation],
                ..Default::default()
            })
            .unwrap(),
        ));
    }
    let draft = Transaction {
        inputs: vec![],
        outputs,
        nonce: [0; 8],
        signatures: TransactionSignature::NaiveMultisig(vec![]),
    };
    for order in [[4, 5], [5, 4]] {
        let mut tx = draft.clone();
        for module in order {
            assets::sign_creation(&mut tx, federation, module, &key).unwrap();
        }
        for (index, module) in [4, 5].into_iter().enumerate() {
            let output = tx.outputs[index * 2 + 1]
                .as_any()
                .downcast_ref::<crate::common::ContractOutput>()
                .unwrap();
            let signature = output.actions().unwrap().creations[0].signature;
            let message = Message::from_digest(signature_hash_v1(federation, module, &tx).unwrap());
            SECP256K1
                .verify_schnorr(&signature, &message, &key.x_only_public_key().0)
                .unwrap();
        }
        // Foreign creation signatures are excluded; foreign creation parameters
        // remain authenticated by the first instance's creator.
        let signature = tx.outputs[1]
            .as_any()
            .downcast_ref::<crate::common::ContractOutput>()
            .unwrap()
            .actions()
            .unwrap()
            .creations[0]
            .signature;
        let mut foreign = tx.outputs[3]
            .as_any()
            .downcast_ref::<crate::common::ContractOutput>()
            .unwrap()
            .clone();
        if let Some(AssetExtension::Actions(actions)) = &mut foreign.extension {
            actions.creations[0].authority_outputs[0] = 0;
        }
        tx.outputs[3] = DynOutput::from_typed(5, foreign);
        let message = Message::from_digest(signature_hash_v1(federation, 4, &tx).unwrap());
        assert!(
            SECP256K1
                .verify_schnorr(&signature, &message, &key.x_only_public_key().0)
                .is_err()
        );
    }
}
