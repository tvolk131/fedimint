//! Construct pruned adversarial fixtures without weakening guardian execution.
use std::collections::BTreeSet;

use fedimint_simplicity_client::pruning::PruningSnapshot;
use fedimint_simplicity_common::jet::FedimintJet;
use fedimint_simplicity_common::runtime::{self, Environment};
use simplicity::jet::{Core, JetEnvironment};
use simplicity_sys::c_jets::frame_ffi::CFrameItem;

use super::*;

// Negative tests deliberately contain wrong signatures/assertions, and clock
// tests prepare spends before their validity window. Those unit-returning
// proof checks do not select branches. Skip them only during fixture pruning;
// all context/data jets and the actual guardian validation remain unchanged.
struct FixtureEnvironment(Environment);
impl JetEnvironment for FixtureEnvironment {
    type Jet = FedimintJet;
    type CJetEnvironment = Environment;
    fn c_jet_env(&self) -> &Environment {
        &self.0
    }
    fn c_jet_ptr(jet: &FedimintJet) -> fn(&mut CFrameItem, CFrameItem, &Environment) -> bool {
        match jet {
            FedimintJet::Core(Core::Verify | Core::Bip0340Verify) => |_, _, _| true,
            _ => Environment::c_jet_ptr(jet),
        }
    }
}

pub(super) fn prune_fixture(
    tx: &mut Transaction,
    federation: FederationId,
    module: u16,
    snapshot: &PruningSnapshot,
) {
    let mut replacements = Vec::new();
    for (index, (outer, item)) in tx
        .inputs
        .iter()
        .enumerate()
        .filter(|(_, item)| item.module_instance_id() == module)
        .enumerate()
    {
        let input = item.as_any().downcast_ref::<ContractInput>().unwrap();
        // Malformed/unknown inputs must reach guardian rejection unchanged.
        let (Ok(env), Ok(program)) = (
            snapshot.environment(federation, module, tx, index),
            runtime::decode_program(input),
        ) else {
            continue;
        };
        let Ok(pruned) =
            fedimint_simplicity_common::compiler::prune(&program, &FixtureEnvironment(env))
        else {
            continue;
        };
        let mut input = input.clone();
        (input.program, input.witness) = pruned.to_vec_with_witness();
        replacements.push((outer, DynInput::from_typed(module, input)));
    }
    for (index, input) in replacements {
        tx.inputs[index] = input;
    }
}

impl Harness {
    pub(super) async fn prune(&self, tx: &mut Transaction, session: u64) {
        let modules: BTreeSet<_> = tx
            .inputs
            .iter()
            .filter(|input| input.as_any().is::<ContractInput>())
            .map(|input| input.module_instance_id())
            .collect();
        for module in modules {
            let database = self.db.with_prefix_module_id(module).0;
            let mut dbtx = database.begin_transaction_nc().await;
            let mut snapshot = PruningSnapshot {
                session_index: session,
                block_count: self
                    .modules
                    .get_expect(module)
                    .as_any()
                    .downcast_ref::<Simplicity>()
                    .unwrap()
                    .consensus_block_count(&mut dbtx)
                    .await,
                ..Default::default()
            };
            for input in tx
                .inputs
                .iter()
                .filter(|input| input.module_instance_id() == module)
            {
                let input = input.as_any().downcast_ref::<ContractInput>().unwrap();
                if let Some(stored) = dbtx.get_value(&ContractKey(input.outpoint)).await {
                    snapshot.contracts.insert(input.outpoint, stored);
                }
            }
            prune_fixture(tx, federation_id(), module, &snapshot);
        }
    }

    pub(super) async fn sign(&self, tx: &mut Transaction, keys: &[Keypair]) -> anyhow::Result<()> {
        self.prune(tx, 0).await;
        sign_transaction(tx, keys)
    }
}

#[tokio::test]
async fn unpruned_spends_fail_admission_and_consensus_without_consuming_old_commitments() {
    let fed = Harness::new();
    let owner = key();
    let program = ContractProgram::compile(
        "fn main() { match witness::PATH { true => { assert!(jet::eq_32(42, 42)); }, false => { assert!(jet::eq_64(7, 7)); }, } }",
        Default::default(),
    ).unwrap();
    let output = program
        .output(Amount::from_sats(10), [0; 32], vec![])
        .unwrap();
    let funding = fed
        .fund(vec![DynOutput::from_typed(SIMP, output.clone())])
        .await;
    let point = OutPoint {
        txid: funding.tx_hash(),
        out_idx: 0,
    };
    let input = program
        .input(
            point,
            owner.public_key(),
            witnesses([("PATH", Value::from(true))]),
        )
        .unwrap();
    let mut tx = transaction(vec![DynInput::from_typed(SIMP, input.clone())], vec![]);
    sign_transaction(&mut tx, &[owner]).unwrap();
    for result in [
        fed.check_submission(&tx, 1).await,
        fed.process(&tx, 1).await,
    ] {
        assert!(result.unwrap_err().to_string().contains("program rejected"));
    }
    assert_eq!(fed.contract(point).await.unwrap().output, output);
    fed.sign(&mut tx, &[owner]).await.unwrap();
    let pruned = tx.inputs[0]
        .as_any()
        .downcast_ref::<ContractInput>()
        .unwrap();
    assert_ne!(input.program, pruned.program);
    assert_eq!(
        runtime::decode_program(pruned)
            .unwrap()
            .cmr()
            .to_byte_array(),
        output.cmr
    );
    fed.check_submission(&tx, 1).await.unwrap();
    fed.process(&tx, 1).await.unwrap();
    assert!(fed.contract(point).await.is_none());
}
