use std::sync::Arc;

use bitcoin::hashes::sha256;
use fedimint_client_module::transaction::{ClientOutput, ClientOutputBundle, TransactionBuilder};
use fedimint_core::core::{DynInput, IntoDynInstance};
use fedimint_core::module::Amounts;
use fedimint_core::module::registry::ModuleDecoderRegistry;
use fedimint_core::secp256k1::{Message, SECP256K1};
use fedimint_core::transaction::TransactionSignature;
use fedimint_derive_secret::DerivableSecret;

use super::*;
use crate::assets;
use crate::authorization::Authorization;
use crate::common::assets::AssetActions;
use crate::descriptor::ContractDescriptor;

fn federation() -> FederationId {
    FederationId(sha256::Hash::hash(b"receipt-test"))
}
fn plan(module: u16, output_index: usize) -> ReceiptPlan {
    ReceiptPlan {
        keys: WalletKeys::new(
            &DerivableSecret::new_root(&[1; 32], b"receipt-test"),
            federation(),
            module,
        ),
        federation: federation(),
        module,
        output_index,
        receipt: SenderReceipt {
            context: Some(ReceiptContext {
                application: "test".to_owned(),
                version: 1,
                data: b"private context".to_vec(),
            }),
        },
    }
}
fn transaction(plan: &ReceiptPlan) -> Transaction {
    let mut output = ContractOutput::action_output(Default::default());
    output.recovery = plan.placeholder().unwrap();
    Transaction {
        inputs: vec![
            DynInput::consensus_decode_whole(
                &[9, 3, 1, 2, 3],
                &ModuleDecoderRegistry::default().with_fallback(),
            )
            .unwrap(),
        ],
        outputs: vec![DynOutput::from_typed(plan.module, output)],
        nonce: [3; 8],
        signatures: TransactionSignature::NaiveMultisig(vec![]),
    }
}

#[test]
fn receipts_bind_payers_outputs_nonce_and_scope_and_keep_reserved_size() {
    let plan = plan(4, 0);
    let mut tx = transaction(&plan);
    let placeholder = tx.outputs[0].clone();
    let first = plan.prepare(&tx).unwrap();
    let second = plan.prepare(&tx).unwrap();
    assert_ne!(first, second, "fresh encryption randomness");
    assert_eq!(
        first.consensus_encode_to_vec().len(),
        placeholder.consensus_encode_to_vec().len()
    );
    tx.outputs[0] = first;
    plan.verify(&tx).unwrap();
    let output = tx.outputs[0]
        .as_any()
        .downcast_ref::<ContractOutput>()
        .unwrap();
    assert_eq!(
        read(&plan.keys, federation(), 4, &tx, &output.recovery).unwrap(),
        Some(plan.receipt.clone())
    );
    for mutation in 0..4 {
        let mut copied = tx.clone();
        match mutation {
            0 => copied.nonce[0] ^= 1,
            1 => copied.inputs.clear(),
            2 => {
                copied.inputs[0] = DynInput::consensus_decode_whole(
                    &[9, 3, 1, 2, 4],
                    &ModuleDecoderRegistry::default().with_fallback(),
                )
                .unwrap()
            }
            _ => copied.outputs.push(DynOutput::from_typed(
                8,
                ContractOutput::action_output(Default::default()),
            )),
        }
        assert!(plan.verify(&copied).is_err());
        assert_eq!(
            read(&plan.keys, federation(), 4, &copied, &output.recovery).unwrap(),
            None
        );
    }
    assert_eq!(
        read(&plan.keys, federation(), 5, &tx, &output.recovery).unwrap(),
        None
    );
    let other = super::tests::plan(5, 0);
    assert_eq!(
        read(&other.keys, federation(), 4, &tx, &output.recovery).unwrap(),
        None
    );
    let mut corrupted = output.recovery.clone();
    *corrupted.last_mut().unwrap() ^= 1;
    assert_eq!(
        read(&plan.keys, federation(), 4, &tx, &corrupted).unwrap(),
        None
    );
    let mut oversized = plan.clone();
    oversized.receipt.context.as_mut().unwrap().data = vec![0; MAX_RECOVERY_BYTES];
    assert!(oversized.placeholder().is_err());
}

#[test]
fn authenticated_future_receipts_stop_recovery_but_copies_do_not() {
    let plan = plan(4, 0);
    let tx = transaction(&plan);
    let plaintext =
        (commitment(federation(), 4, &tx), 2u16, &plan.receipt).consensus_encode_to_vec();
    let mut annotation = ENVELOPE.to_vec();
    annotation.extend(fedimint_aead::encrypt(plaintext, &plan.keys.receipt_key()).unwrap());
    assert!(read(&plan.keys, federation(), 4, &tx, &annotation).is_err());
    let mut other = tx.clone();
    other.nonce[0] ^= 1;
    assert_eq!(
        read(&plan.keys, federation(), 4, &other, &annotation).unwrap(),
        None
    );
}

#[test]
fn receipts_precede_creation_signatures_across_instances_in_either_order() {
    for modules in [[4, 5], [5, 4]] {
        let mut builder = TransactionBuilder::new();
        let mut plans = vec![];
        let mut keys = vec![];
        for (i, module) in modules.into_iter().enumerate() {
            let plan = plan(module, i);
            let key = plan.keys.signing_key(&ContractDescriptor::owner([1; 32]));
            let (creation, _) = assets::creation(federation(), module, &key, vec![0]).unwrap();
            let mut output = ContractOutput::action_output(AssetActions {
                creations: vec![creation],
                ..Default::default()
            });
            output.recovery = plan.placeholder().unwrap();
            builder = builder
                .with_outputs(
                    ClientOutputBundle::new_no_sm(vec![ClientOutput {
                        output,
                        amounts: Amounts::ZERO,
                    }])
                    .into_dyn(module),
                )
                .with_finalizer(
                    module,
                    Arc::new(Authorization {
                        federation: federation(),
                        module,
                        spends: vec![],
                        creations: vec![key],
                        receipt: Some(plan.clone()),
                        max_fee: None,
                    }),
                );
            plans.push(plan);
            keys.push(key);
        }
        let (tx, _) = builder.build(SECP256K1, rand::thread_rng()).unwrap();
        for (i, plan) in plans.iter().enumerate() {
            plan.verify(&tx).unwrap();
            let output = tx.outputs[i]
                .as_any()
                .downcast_ref::<ContractOutput>()
                .unwrap();
            let signature = output.actions().unwrap().creations[0].signature;
            SECP256K1
                .verify_schnorr(
                    &signature,
                    &Message::from_digest(
                        crate::common::assets::signature_hash_v1(federation(), plan.module, &tx)
                            .unwrap(),
                    ),
                    &keys[i].x_only_public_key().0,
                )
                .unwrap();
        }
    }
}
