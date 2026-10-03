//! Two instances in the real core transaction processor, sharing one database.
use fedimint_core::db::IDatabaseTransactionOpsCore;
use fedimint_simplicity_client::assets;
use fedimint_simplicity_common::ContractOutput;
use fedimint_simplicity_common::assets::{AssetActions, AssetBundle, AssetId, namespace};
use futures::StreamExt;

use super::*;
use crate::db::{AssetKey, NamespaceKey};

pub(super) const OTHER: u16 = 7;
const INSTANCES: [u16; 2] = [SIMP, OTHER];

pub(super) fn harness() -> Harness {
    let mut decoders = ModuleDecoderRegistry::default();
    let mut modules = ServerModuleRegistry::default();
    for id in INSTANCES {
        decoders.register_module(id, fedimint_simplicity_common::KIND, Simplicity::decoder());
        modules.register_module(
            id,
            fedimint_simplicity_common::KIND,
            DynServerModule::from(Simplicity::new_for_testing(vec![PeerId::from(0)]).unwrap()),
        );
    }
    decoders.register_module(DUMMY, fedimint_dummy_common::KIND, Dummy::decoder());
    modules.register_module(
        DUMMY,
        fedimint_dummy_common::KIND,
        DynServerModule::from(Dummy::new(DummyConfig {
            private: DummyConfigPrivate,
            consensus: DummyConfigConsensus,
        })),
    );
    Harness {
        db: Database::new(MemDatabase::new(), decoders),
        modules,
    }
}

pub(super) async fn snapshot(fed: &Harness) -> Vec<(Vec<u8>, Vec<u8>)> {
    fed.db
        .begin_transaction_nc()
        .await
        .raw_find_by_prefix(&[])
        .await
        .unwrap()
        .collect()
        .await
}

fn output(module: u16, contract: ContractOutput) -> DynOutput {
    DynOutput::from_typed(module, contract)
}

struct Pair {
    fed: Harness,
    owner: Keypair,
    programs: [ContractProgram; 2],
    ids: [AssetId; 2],
    funding: Transaction,
}

impl Pair {
    async fn new() -> Self {
        let fed = harness();
        let creator = key(); // Deliberately the same key in both instances.
        let owner = key();
        let programs = INSTANCES.map(|module| {
            ContractProgram::compile(
                "fn main() {
                    assert!(jet::eq_32(jet::fm_input_count(), 1));
                    assert!(jet::eq_32(jet::fm_current_index(), 0));
                    assert!(jet::eq_64(jet::fm_input_amount(0), jet::fm_current_amount()));
                    assert!(jet::eq_16(jet::fm_output_module(param::OUTPUT), param::MODULE));
                    assert!(jet::eq_64(jet::fm_output_amount(param::OUTPUT), param::AMOUNT));
                    jet::bip_0340_verify((param::OWNER, jet::fm_sig_hash_all()), witness::SIGNATURE);
                }",
                arguments([
                    ("OWNER", Value::u256(U256::from_byte_array(owner.x_only_public_key().0.serialize()))),
                    ("MODULE", Value::u16(module)),
                    ("AMOUNT", Value::u64(if module == SIMP { 1000 } else { 2000 })),
                    ("OUTPUT", Value::u32(if module == SIMP { 0 } else { 2 })),
                ]),
            ).unwrap()
        });
        let mut outputs = vec![];
        let mut ids = vec![];
        for (i, module) in INSTANCES.into_iter().enumerate() {
            let (creation, created) =
                assets::creation(federation_id(), module, &creator, vec![(i * 2) as u32]).unwrap();
            ids.push(created[0]);
            outputs.push(output(
                module,
                programs[i]
                    .asset_output(
                        Amount::from_msats(1000 * (i as u64 + 1)),
                        [0; 32],
                        vec![],
                        bundle(&[], &created),
                    )
                    .unwrap(),
            ));
            outputs.push(output(
                module,
                assets::action_output(AssetActions {
                    creations: vec![creation],
                    ..Default::default()
                })
                .unwrap(),
            ));
        }
        let (mut funding, sponsor) = sponsored(vec![], outputs);
        // Signing one instance must not invalidate the other's creation intent.
        for module in INSTANCES.into_iter().rev() {
            assets::sign_creation(&mut funding, federation_id(), module, &creator).unwrap();
        }
        sign_transaction(&mut funding, &[sponsor]).unwrap();
        let before = snapshot(&fed).await;
        let mut unfunded = funding.clone();
        unfunded.inputs.clear();
        sign_transaction(&mut unfunded, &[]).unwrap();
        assert_error(fed.process(&unfunded, 0).await, "unbalanced");
        // Includes UTXOs, both namespace markers, immutable asset origins and
        // output outcomes: no writes from either instance may survive.
        assert_eq!(snapshot(&fed).await, before);
        fed.check_submission(&funding, 0).await.unwrap();
        assert_eq!(snapshot(&fed).await, before);
        fed.process(&funding, 0).await.unwrap();
        assert_ne!(ids[0], ids[1]);
        for (i, module) in INSTANCES.into_iter().enumerate() {
            let db = fed.db.with_prefix_module_id(module).0;
            let mut dbtx = db.begin_transaction_nc().await;
            let own = dbtx.get_value(&AssetKey(ids[i])).await.unwrap();
            assert_eq!(own.authority_outpoint, point(&funding, (i * 2) as u64));
            assert!(dbtx.get_value(&AssetKey(ids[1 - i])).await.is_none());
            assert!(
                dbtx.get_value(&NamespaceKey(namespace(
                    federation_id(),
                    module,
                    creator.public_key()
                )))
                .await
                .is_some()
            );
            assert!(
                dbtx.get_value(&NamespaceKey(namespace(
                    federation_id(),
                    INSTANCES[1 - i],
                    creator.public_key()
                )))
                .await
                .is_none()
            );
            assert!(
                dbtx.get_value(&ContractKey(point(&funding, ((1 - i) * 2) as u64)))
                    .await
                    .is_none()
            );
        }
        Self {
            fed,
            owner,
            programs,
            ids: ids.try_into().unwrap(),
            funding,
        }
    }

    fn authorize(&self, tx: &mut Transaction, sponsor: &Keypair) {
        for (i, module) in INSTANCES.into_iter().enumerate() {
            let signature =
                assets::signature_value(federation_id(), module, tx, &self.owner).unwrap();
            // Read the draft outpoint so tests can also sign an invalid lookup.
            let point = tx.inputs[i]
                .as_any()
                .downcast_ref::<ContractInput>()
                .unwrap()
                .outpoint;
            tx.inputs[i] = DynInput::from_typed(
                module,
                self.programs[i]
                    .input(
                        point,
                        self.owner.public_key(),
                        witnesses([("SIGNATURE", signature)]),
                    )
                    .unwrap(),
            );
        }
        sign_transaction(tx, &[self.owner, self.owner, *sponsor]).unwrap();
    }

    fn issue(&self) -> (Transaction, Keypair) {
        let mut inputs = vec![];
        let mut outputs = vec![];
        for (i, module) in INSTANCES.into_iter().enumerate() {
            inputs.push(DynInput::from_typed(
                module,
                self.programs[i]
                    .input(
                        point(&self.funding, (i * 2) as u64),
                        self.owner.public_key(),
                        witnesses([("SIGNATURE", placeholder_signature())]),
                    )
                    .unwrap(),
            ));
            outputs.push(output(
                module,
                self.programs[i]
                    .asset_output(
                        Amount::from_msats(1000 * (i as u64 + 1)),
                        [0; 32],
                        vec![],
                        bundle(&[(self.ids[i], 9)], &[self.ids[i]]),
                    )
                    .unwrap(),
            ));
            outputs.push(output(
                module,
                assets::action_output(AssetActions {
                    issuance: values(&[(self.ids[i], 9)]),
                    ..Default::default()
                })
                .unwrap(),
            ));
        }
        let (mut tx, sponsor) = sponsored(inputs, outputs);
        self.authorize(&mut tx, &sponsor);
        (tx, sponsor)
    }
}

#[tokio::test]
async fn two_instances_have_separate_contexts_namespaces_and_atomic_funding() {
    let pair = Pair::new().await;
    let (issue, sponsor) = pair.issue();
    let before = snapshot(&pair.fed).await;
    let mut unfunded = issue.clone();
    unfunded.inputs[2] = DynInput::from_typed(
        DUMMY,
        DummyInput {
            amount: Amount::ZERO,
            unit: AmountUnit::BITCOIN,
            pub_key: sponsor.public_key(),
        },
    );
    sign_transaction(&mut unfunded, &[pair.owner, pair.owner, sponsor]).unwrap();
    assert_error(pair.fed.process(&unfunded, 1).await, "unbalanced");
    assert_eq!(snapshot(&pair.fed).await, before);
    pair.fed.check_submission(&issue, 1).await.unwrap();
    assert_eq!(snapshot(&pair.fed).await, before);
    pair.fed.process(&issue, 1).await.unwrap();
    for (i, module) in INSTANCES.into_iter().enumerate() {
        let db = pair.fed.db.with_prefix_module_id(module).0;
        let mut dbtx = db.begin_transaction_nc().await;
        assert!(
            dbtx.get_value(&ContractKey(point(&pair.funding, (i * 2) as u64)))
                .await
                .is_none()
        );
        let contract = dbtx
            .get_value(&ContractKey(point(&issue, (i * 2) as u64)))
            .await
            .unwrap();
        assert_eq!(
            contract.output.bundle().unwrap(),
            &bundle(&[(pair.ids[i], 9)], &[pair.ids[i]])
        );
        assert_eq!(contract.creation_session, 1);
    }
}

#[tokio::test]
async fn cross_instance_substitutions_and_bad_second_witness_leave_both_unchanged() {
    let pair = Pair::new().await;
    let (issue, sponsor) = pair.issue();
    let before = snapshot(&pair.fed).await;
    // A correctly signed input cannot look up another instance's UTXO.
    let mut wrong_point = issue.clone();
    wrong_point.inputs[1] = DynInput::from_typed(
        OTHER,
        pair.programs[1]
            .input(
                point(&pair.funding, 0),
                pair.owner.public_key(),
                witnesses([("SIGNATURE", placeholder_signature())]),
            )
            .unwrap(),
    );
    pair.authorize(&mut wrong_point, &sponsor);
    assert_error(pair.fed.process(&wrong_point, 1).await, "already spent");
    assert_eq!(snapshot(&pair.fed).await, before);
    // Quantities and authorities cannot balance across module boundaries.
    let mut wrong_assets = issue.clone();
    wrong_assets.outputs[2] = output(
        OTHER,
        pair.programs[1]
            .asset_output(
                Amount::from_msats(2000),
                [0; 32],
                vec![],
                AssetBundle {
                    balances: values(&[(pair.ids[0], 9)]),
                    authorities: vec![pair.ids[1]],
                },
            )
            .unwrap(),
    );
    pair.authorize(&mut wrong_assets, &sponsor);
    assert_error(pair.fed.process(&wrong_assets, 1).await, "asset transition");
    assert_eq!(snapshot(&pair.fed).await, before);
    // Instance A's signature commits B's output too, even though A cannot
    // inspect its rich contract data.
    let mut changed = issue.clone();
    let mut other = changed.outputs[2]
        .as_any()
        .downcast_ref::<ContractOutput>()
        .unwrap()
        .clone();
    other.state = [1; 32];
    changed.outputs[2] = output(OTHER, other);
    let signature = assets::signature_value(federation_id(), OTHER, &changed, &pair.owner).unwrap();
    changed.inputs[1] = DynInput::from_typed(
        OTHER,
        pair.programs[1]
            .input(
                point(&pair.funding, 2),
                pair.owner.public_key(),
                witnesses([("SIGNATURE", signature)]),
            )
            .unwrap(),
    );
    sign_transaction(&mut changed, &[pair.owner, pair.owner, sponsor]).unwrap();
    assert_error(pair.fed.process(&changed, 1).await, "program rejected");
    assert_eq!(snapshot(&pair.fed).await, before);
    let mut bad_second = issue.clone();
    bad_second.inputs[1] = DynInput::from_typed(
        OTHER,
        pair.programs[1]
            .input(
                point(&pair.funding, 2),
                pair.owner.public_key(),
                witnesses([("SIGNATURE", placeholder_signature())]),
            )
            .unwrap(),
    );
    sign_transaction(&mut bad_second, &[pair.owner, pair.owner, sponsor]).unwrap();
    assert_error(pair.fed.process(&bad_second, 1).await, "program rejected");
    assert_eq!(snapshot(&pair.fed).await, before);
    pair.fed.process(&issue, 1).await.unwrap();
}

#[tokio::test]
async fn legacy_and_asset_programs_cannot_read_the_other_instances_rich_outputs() {
    let fed = harness();
    let owner = key();
    let program = ContractProgram::compile(
        "fn main() { assert!(jet::eq_64(jet::fm_output_amount(witness::OUTPUT), 1000)); }",
        arguments([]),
    )
    .unwrap();
    let outputs = vec![
        output(
            SIMP,
            program
                .output(Amount::from_msats(1000), [0; 32], vec![])
                .unwrap(),
        ),
        output(
            OTHER,
            program
                .asset_output(
                    Amount::from_msats(1000),
                    [0; 32],
                    vec![],
                    AssetBundle::default(),
                )
                .unwrap(),
        ),
    ];
    let funding = fed.fund(outputs.clone()).await;
    let inputs = INSTANCES
        .into_iter()
        .enumerate()
        .map(|(i, module)| {
            DynInput::from_typed(
                module,
                program
                    .input(
                        point(&funding, i as u64),
                        owner.public_key(),
                        witnesses([("OUTPUT", Value::u32(i as u32))]),
                    )
                    .unwrap(),
            )
        })
        .collect();
    let (mut spend, sponsor) = sponsored(inputs, outputs);
    sign_transaction(&mut spend, &[owner, owner, sponsor]).unwrap();
    let before = snapshot(&fed).await;
    for (i, module) in INSTANCES.into_iter().enumerate() {
        let mut foreign_read = spend.clone();
        foreign_read.inputs[i] = DynInput::from_typed(
            module,
            program
                .input(
                    point(&funding, i as u64),
                    owner.public_key(),
                    witnesses([("OUTPUT", Value::u32((1 - i) as u32))]),
                )
                .unwrap(),
        );
        sign_transaction(&mut foreign_read, &[owner, owner, sponsor]).unwrap();
        assert_error(fed.process(&foreign_read, 1).await, "program rejected");
        assert_eq!(snapshot(&fed).await, before);
    }
    fed.process(&spend, 1).await.unwrap();
}
