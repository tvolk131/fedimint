use std::fmt;
use std::sync::{Arc, Mutex};

use bitcoin::hashes::Hash;
use fedimint_core::core::{DynInput, DynOutput, Input, IntoDynInstance, ModuleKind, Output};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::module::Amounts;
use fedimint_core::secp256k1::{Keypair, Message, SECP256K1};
use fedimint_core::transaction::{Transaction, TransactionSignature};

use super::TransactionFinalizer;
use crate::error::ClientModuleError;
use crate::transaction::{
    ClientInput, ClientInputBundle, ClientInputSM, ClientOutput, ClientOutputBundle,
    NeverClientStateMachine, TransactionBuilder,
};

#[derive(Debug, Clone, Eq, PartialEq, Hash, Encodable, Decodable)]
struct TestInput(u64);

impl Input for TestInput {
    const KIND: ModuleKind = ModuleKind::from_static_str("test");
}

impl fmt::Display for TestInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl IntoDynInstance for TestInput {
    type DynType = DynInput;

    fn into_dyn(self, instance: u16) -> DynInput {
        DynInput::from_typed(instance, self)
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Encodable, Decodable)]
struct TestOutput(u64);

impl Output for TestOutput {
    const KIND: ModuleKind = ModuleKind::from_static_str("test");
}

impl fmt::Display for TestOutput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl IntoDynInstance for TestOutput {
    type DynType = DynOutput;

    fn into_dyn(self, instance: u16) -> DynOutput {
        DynOutput::from_typed(instance, self)
    }
}

#[derive(Debug)]
struct SignFinalItems;

impl TransactionFinalizer for SignFinalItems {
    fn finalize_outputs(
        &self,
        _: &Transaction,
    ) -> Result<Vec<(usize, DynOutput)>, ClientModuleError> {
        Ok(vec![(0, TestOutput(7).into_dyn(1))])
    }

    fn finalize_inputs(
        &self,
        tx: &Transaction,
    ) -> Result<Vec<(usize, DynInput)>, ClientModuleError> {
        assert_eq!(
            tx.outputs[0]
                .as_any()
                .downcast_ref::<TestOutput>()
                .unwrap()
                .0,
            7
        );
        assert_eq!(
            tx.outputs[1]
                .as_any()
                .downcast_ref::<TestOutput>()
                .unwrap()
                .0,
            42
        );
        Ok(vec![(
            0,
            TestInput(u64::from_le_bytes(tx.nonce)).into_dyn(1),
        )])
    }
}

#[test]
fn authorization_sees_final_outputs_and_nonce_before_outer_signatures_and_states() {
    let key = Keypair::from_seckey_slice(SECP256K1, &[1; 32]).unwrap();
    let observed = Arc::new(Mutex::new(None));
    let observed_clone = observed.clone();
    let input = ClientInputBundle::<_, NeverClientStateMachine>::new(
        vec![ClientInput {
            input: TestInput(0),
            keys: vec![key],
            amounts: Amounts::ZERO,
        }],
        vec![ClientInputSM {
            state_machines: Arc::new(move |range| {
                *observed_clone.lock().unwrap() = Some(range.txid());
                vec![]
            }),
        }],
    )
    .into_dyn(1);
    let (tx, _) = TransactionBuilder::new()
        .with_inputs(input)
        .with_outputs(
            ClientOutputBundle::new_no_sm(vec![ClientOutput {
                output: TestOutput(0),
                amounts: Amounts::ZERO,
            }])
            .into_dyn(1),
        )
        .with_finalizer(1, Arc::new(SignFinalItems))
        // Simulates change added by the primary module after explicit items.
        .with_outputs(
            ClientOutputBundle::new_no_sm(vec![ClientOutput {
                output: TestOutput(42),
                amounts: Amounts::ZERO,
            }])
            .into_dyn(2),
        )
        .build(SECP256K1, rand::thread_rng())
        .unwrap();
    assert_eq!(
        tx.inputs[0].as_any().downcast_ref::<TestInput>().unwrap().0,
        u64::from_le_bytes(tx.nonce)
    );
    assert_eq!(*observed.lock().unwrap(), Some(tx.tx_hash()));
    let TransactionSignature::NaiveMultisig(signatures) = &tx.signatures else {
        panic!("expected Schnorr signatures")
    };
    SECP256K1
        .verify_schnorr(
            &signatures[0],
            &Message::from_digest(tx.tx_hash().to_byte_array()),
            &key.x_only_public_key().0,
        )
        .unwrap();
}

#[derive(Debug)]
struct WrongOutput {
    index: usize,
    module: u16,
}

impl TransactionFinalizer for WrongOutput {
    fn finalize_outputs(
        &self,
        _: &Transaction,
    ) -> Result<Vec<(usize, DynOutput)>, ClientModuleError> {
        Ok(vec![(self.index, TestOutput(1).into_dyn(self.module))])
    }
}

#[test]
fn finalizers_cannot_append_reassign_or_overwrite_another_modules_items() {
    for (index, module) in [(1, 1), (0, 2)] {
        let result = TransactionBuilder::new()
            .with_outputs(
                ClientOutputBundle::new_no_sm(vec![ClientOutput {
                    output: TestOutput(0),
                    amounts: Amounts::ZERO,
                }])
                .into_dyn(1),
            )
            .with_finalizer(1, Arc::new(WrongOutput { index, module }))
            .build(SECP256K1, rand::thread_rng());
        assert!(result.is_err());
    }
    let result = TransactionBuilder::new()
        .with_outputs(
            ClientOutputBundle::new_no_sm(vec![ClientOutput {
                output: TestOutput(0),
                amounts: Amounts::ZERO,
            }])
            .into_dyn(2),
        )
        .with_finalizer(
            1,
            Arc::new(WrongOutput {
                index: 0,
                module: 2,
            }),
        )
        .build(SECP256K1, rand::thread_rng());
    assert!(result.is_err());
}
