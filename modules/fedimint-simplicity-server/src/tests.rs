mod api;
mod assets;
mod config;
mod preflight;

use std::collections::BTreeMap;

use bitcoin::hashes::{Hash, sha256};
use fedimint_core::config::FederationId;
use fedimint_core::core::{DynInput, DynModuleConsensusItem, DynOutput};
use fedimint_core::db::mem_impl::MemDatabase;
use fedimint_core::db::{Database, IDatabaseTransactionOpsCoreTyped};
use fedimint_core::module::audit::Audit;
use fedimint_core::module::registry::ModuleDecoderRegistry;
use fedimint_core::module::{AmountUnit, CoreConsensusVersion};
use fedimint_core::secp256k1::{Keypair, SECP256K1};
use fedimint_core::transaction::{Transaction, TransactionError, TransactionSignature};
use fedimint_core::{Amount, OutPoint, PeerId};
use fedimint_dummy_common::config::{DummyConfig, DummyConfigConsensus, DummyConfigPrivate};
use fedimint_dummy_common::{DummyInput, DummyOutput};
use fedimint_dummy_server::Dummy;
use fedimint_mintv2_common::{Denomination, MintInput, MintOutput, Note, nonce_message};
use fedimint_mintv2_server::db::BlindedSignatureShareKey;
use fedimint_mintv2_server::{Mint, MintInit};
use fedimint_server::consensus::transaction::{TxProcessingMode, process_transaction_with_dbtx};
use fedimint_server_core::{
    ConfigGenModuleArgs, DynServerModule, ServerModule, ServerModuleInit, ServerModuleRegistry,
    TransactionConsensusContext,
};
use fedimint_simplicity_client::compiler::{U256, Value, ValueConstructible, arguments, witnesses};
use fedimint_simplicity_client::{
    ContractProgram, TOP_UP_OR_RELEASE, placeholder_signature, sign_transaction, signature_value,
};
use fedimint_simplicity_common::{
    BlockCountVote, ContractError, ContractInput, MAX_PROGRAM_BYTES, MAX_RECOVERY_BYTES,
    MAX_WITNESS_BYTES, output_fee,
};

use super::Simplicity;
use super::db::{ContractKey, StoredContract};

const SIMP: u16 = 4;
const MINT: u16 = 5;
const DUMMY: u16 = 6;

fn key() -> Keypair {
    Keypair::new(SECP256K1, &mut rand::thread_rng())
}
fn federation_id() -> FederationId {
    FederationId(sha256::Hash::hash(b"simplicity-test-federation"))
}
fn transaction(inputs: Vec<DynInput>, outputs: Vec<DynOutput>) -> Transaction {
    Transaction {
        inputs,
        outputs,
        nonce: rand::random(),
        signatures: TransactionSignature::NaiveMultisig(vec![]),
    }
}

fn contract_program(owner: &Keypair, session: u64, block_count: u64) -> ContractProgram {
    ContractProgram::compile(
        TOP_UP_OR_RELEASE,
        arguments([
            (
                "OWNER",
                Value::u256(U256::from_byte_array(
                    owner.x_only_public_key().0.serialize(),
                )),
            ),
            ("MIN_SESSION", Value::u64(session)),
            ("MIN_BLOCK_COUNT", Value::u64(block_count)),
        ]),
    )
    .unwrap()
}

fn spend_input(
    program: &ContractProgram,
    point: OutPoint,
    owner: &Keypair,
    release: bool,
    signature: Value,
) -> ContractInput {
    program
        .input(
            point,
            owner.public_key(),
            witnesses([("SIGNATURE", signature), ("RELEASE", Value::from(release))]),
        )
        .unwrap()
}

fn authorize(
    tx: &mut Transaction,
    program: &ContractProgram,
    point: OutPoint,
    owner: &Keypair,
    release: bool,
    other_keys: &[Keypair],
) {
    let signature = signature_value(federation_id(), SIMP, tx, owner).unwrap();
    tx.inputs[0] =
        DynInput::from_typed(SIMP, spend_input(program, point, owner, release, signature));
    let mut keys = vec![*owner];
    keys.extend_from_slice(other_keys);
    sign_transaction(tx, &keys).unwrap();
}

fn draft_spend(
    program: &ContractProgram,
    point: OutPoint,
    owner: &Keypair,
    release: bool,
    outputs: Vec<DynOutput>,
) -> Transaction {
    transaction(
        vec![DynInput::from_typed(
            SIMP,
            spend_input(program, point, owner, release, placeholder_signature()),
        )],
        outputs,
    )
}

struct MintRequest {
    key: Keypair,
    blind: tbs::BlindingKey,
    denomination: Denomination,
}
impl MintRequest {
    fn new(denomination: Denomination) -> Self {
        Self {
            key: key(),
            blind: tbs::BlindingKey::random(),
            denomination,
        }
    }
    fn output(&self) -> DynOutput {
        DynOutput::from_typed(
            MINT,
            MintOutput::new_v0(
                self.denomination,
                tbs::blind_message(nonce_message(self.key.public_key()), self.blind),
                [0; 16],
            ),
        )
    }
}

struct Harness {
    db: Database,
    modules: ServerModuleRegistry,
}
impl Harness {
    fn new() -> Self {
        let decoders = ModuleDecoderRegistry::new([
            (
                SIMP,
                fedimint_simplicity_common::KIND,
                Simplicity::decoder(),
            ),
            (MINT, fedimint_mintv2_common::KIND, Mint::decoder()),
            (DUMMY, fedimint_dummy_common::KIND, Dummy::decoder()),
        ]);
        let db = Database::new(MemDatabase::new(), decoders);
        let peers = vec![PeerId::from(0)];
        let cfg = MintInit
            .trusted_dealer_gen(
                &peers,
                &ConfigGenModuleArgs {
                    network: bitcoin::Network::Regtest,
                    disable_base_fees: true,
                },
            )
            .remove(&peers[0])
            .unwrap()
            .to_typed()
            .unwrap();
        let modules = ServerModuleRegistry::new([
            (
                SIMP,
                fedimint_simplicity_common::KIND,
                DynServerModule::from(Simplicity::new_for_testing(peers).unwrap()),
            ),
            (
                MINT,
                fedimint_mintv2_common::KIND,
                DynServerModule::from(Mint::new(cfg, db.with_prefix_module_id(MINT).0)),
            ),
            (
                DUMMY,
                fedimint_dummy_common::KIND,
                DynServerModule::from(Dummy::new(DummyConfig {
                    private: DummyConfigPrivate,
                    consensus: DummyConfigConsensus,
                })),
            ),
        ]);
        Self { db, modules }
    }
    async fn process(&self, tx: &Transaction, session: u64) -> anyhow::Result<()> {
        let mut dbtx = self.db.begin_transaction().await;
        let result = process_transaction_with_dbtx(
            self.modules.clone(),
            &mut dbtx.to_ref_nc(),
            tx,
            CoreConsensusVersion::new(2, 1),
            TxProcessingMode::Consensus,
            TransactionConsensusContext {
                federation_id: federation_id(),
                session_index: session,
            },
        )
        .await;
        match result {
            Ok(()) => {
                dbtx.commit_tx_result().await?;
                Ok(())
            }
            Err(error) => {
                dbtx.ignore_uncommitted();
                Err(anyhow::anyhow!(error))
            }
        }
    }
    async fn check_submission(&self, tx: &Transaction, session: u64) -> anyhow::Result<()> {
        let mut dbtx = self.db.begin_transaction().await;
        let result = process_transaction_with_dbtx(
            self.modules.clone(),
            &mut dbtx.to_ref_nc(),
            tx,
            CoreConsensusVersion::new(2, 1),
            TxProcessingMode::Submission,
            TransactionConsensusContext {
                federation_id: federation_id(),
                session_index: session,
            },
        )
        .await;
        dbtx.ignore_uncommitted();
        result.map_err(anyhow::Error::from)
    }
    async fn fund(&self, outputs: Vec<DynOutput>) -> Transaction {
        let key = key();
        let mut tx = transaction(
            vec![DynInput::from_typed(
                DUMMY,
                DummyInput {
                    amount: Amount::from_sats(100_000),
                    unit: AmountUnit::BITCOIN,
                    pub_key: key.public_key(),
                },
            )],
            outputs,
        );
        sign_transaction(&mut tx, &[key]).unwrap();
        self.process(&tx, 0).await.unwrap();
        tx
    }
    async fn note(&self, request: &MintRequest, point: OutPoint) -> Note {
        let db = self.db.with_prefix_module_id(MINT).0;
        let share = db
            .begin_transaction_nc()
            .await
            .get_value(&BlindedSignatureShareKey(point))
            .await
            .unwrap();
        let signature = tbs::aggregate_signature_shares(&BTreeMap::from([(0, share)]));
        Note {
            denomination: request.denomination,
            nonce: request.key.public_key(),
            signature: tbs::unblind_signature(request.blind, signature),
        }
    }
    async fn contract(&self, point: OutPoint) -> Option<StoredContract> {
        self.db
            .with_prefix_module_id(SIMP)
            .0
            .begin_transaction_nc()
            .await
            .get_value(&ContractKey(point))
            .await
    }
    async fn vote(&self, count: u64) {
        let db = self.db.with_prefix_module_id(SIMP).0;
        let mut dbtx = db.begin_transaction().await;
        self.modules
            .get_expect(SIMP)
            .process_consensus_item(
                &mut dbtx.to_ref_nc(),
                &DynModuleConsensusItem::from_typed(SIMP, BlockCountVote(count)),
                PeerId::from(0),
            )
            .await
            .unwrap();
        dbtx.commit_tx_result().await.unwrap();
    }
    async fn audit(&self) -> i64 {
        let db = self.db.with_prefix_module_id(SIMP).0;
        let mut audit = Audit::default();
        self.modules
            .get_expect(SIMP)
            .audit(&mut db.begin_transaction_nc().await, &mut audit, SIMP)
            .await;
        audit.net_assets().unwrap().milli_sat
    }
}

#[tokio::test]
async fn ecash_deposit_top_up_and_redeem_through_core() {
    let fed = Harness::new();
    let owner = key();
    let program = contract_program(&owner, 2, 100);
    let first = MintRequest::new(Denomination(20));
    let second = MintRequest::new(Denomination(20));
    let issue = fed.fund(vec![first.output(), second.output()]).await;
    let note = fed
        .note(
            &first,
            OutPoint {
                txid: issue.tx_hash(),
                out_idx: 0,
            },
        )
        .await;
    let top_up_note = fed
        .note(
            &second,
            OutPoint {
                txid: issue.tx_hash(),
                out_idx: 1,
            },
        )
        .await;

    let initial = program
        .output(
            Amount::from_msats(note.amount().msats - 100),
            [7; 32],
            vec![],
        )
        .unwrap();
    let mut deposit = transaction(
        vec![DynInput::from_typed(MINT, MintInput::new_v0(note))],
        vec![DynOutput::from_typed(SIMP, initial.clone())],
    );
    sign_transaction(&mut deposit, &[first.key]).unwrap();
    fed.process(&deposit, 1).await.unwrap();
    let point = OutPoint {
        txid: deposit.tx_hash(),
        out_idx: 0,
    };
    assert_eq!(fed.audit().await, -(initial.amount.msats as i64));

    let mut successor = initial.clone();
    successor.amount.msats += top_up_note.amount().msats;
    let mut top_up = draft_spend(
        &program,
        point,
        &owner,
        false,
        vec![DynOutput::from_typed(SIMP, successor.clone())],
    );
    top_up
        .inputs
        .push(DynInput::from_typed(MINT, MintInput::new_v0(top_up_note)));
    let input = top_up.inputs[0]
        .as_any()
        .downcast_ref::<ContractInput>()
        .unwrap();
    successor.amount.msats -= fedimint_simplicity_common::runtime::input_fee(input)
        .unwrap()
        .msats
        + output_fee(&successor).msats;
    top_up.outputs[0] = DynOutput::from_typed(SIMP, successor.clone());
    authorize(&mut top_up, &program, point, &owner, false, &[second.key]);

    fed.vote(99).await;
    assert!(
        fed.process(&top_up, 2).await.is_err(),
        "Bitcoin consensus count is too early"
    );
    fed.vote(100).await;
    assert!(
        fed.process(&top_up, 1).await.is_err(),
        "session index is too early"
    );
    assert_eq!(fed.contract(point).await.unwrap().output, initial);

    // Re-signing the outer transaction cannot bypass inner authorization.
    let mut changed = top_up.clone();
    let mut changed_successor = successor.clone();
    changed_successor.state = [9; 32];
    changed.outputs[0] = DynOutput::from_typed(SIMP, changed_successor);
    sign_transaction(&mut changed, &[owner, second.key]).unwrap();
    assert!(fed.process(&changed, 2).await.is_err());

    // The owner cannot bypass the covenant by authorizing changed state.
    authorize(&mut changed, &program, point, &owner, false, &[second.key]);
    assert!(fed.process(&changed, 2).await.is_err());
    assert_eq!(fed.contract(point).await.unwrap().output, initial);

    // A valid inner signature still requires the outer input signature.
    let mut missing_signature = top_up.clone();
    missing_signature.signatures = TransactionSignature::NaiveMultisig(vec![]);
    assert!(fed.process(&missing_signature, 2).await.is_err());
    assert!(fed.contract(point).await.is_some());

    // Even a valid program and owner signature cannot create unfunded value.
    let mut unfunded = top_up.clone();
    unfunded.inputs.pop();
    authorize(&mut unfunded, &program, point, &owner, false, &[]);
    let error = fed.process(&unfunded, 2).await.unwrap_err();
    assert!(matches!(
        error.downcast_ref::<TransactionError>(),
        Some(TransactionError::UnbalancedTransaction { .. })
    ));
    assert!(
        fed.contract(point).await.is_some(),
        "failed funding must roll back consumption"
    );

    fed.process(&top_up, 2).await.unwrap();
    assert!(fed.contract(point).await.is_none());
    let successor_point = OutPoint {
        txid: top_up.tx_hash(),
        out_idx: 0,
    };
    let stored = fed.contract(successor_point).await.unwrap();
    assert_eq!(stored.output, successor);
    assert_eq!(stored.creation_session, 2);
    assert_eq!(stored.creation_block_count, 100);
    assert!(stored.output.amount > initial.amount);
    assert_eq!(fed.audit().await, -(successor.amount.msats as i64));
    assert!(
        fed.process(&top_up, 3).await.is_err(),
        "contract cannot be spent twice"
    );

    let mut release = draft_spend(&program, successor_point, &owner, true, vec![]);
    let input = release.inputs[0]
        .as_any()
        .downcast_ref::<ContractInput>()
        .unwrap();
    let withdrawal_msats = successor.amount.msats
        - fedimint_simplicity_common::runtime::input_fee(input)
            .unwrap()
            .msats;
    let withdrawals = (0..64)
        .filter(|bit| withdrawal_msats & (1u64 << bit) != 0)
        .map(|bit| MintRequest::new(Denomination(bit)))
        .collect::<Vec<_>>();
    release.outputs = withdrawals.iter().map(MintRequest::output).collect();
    authorize(&mut release, &program, successor_point, &owner, true, &[]);
    fed.process(&release, 3).await.unwrap();
    assert!(fed.contract(successor_point).await.is_none());
    assert_eq!(fed.audit().await, 0);
    let mut released_notes = Vec::new();
    for (index, request) in withdrawals.iter().enumerate() {
        released_notes.push(
            fed.note(
                request,
                OutPoint {
                    txid: release.tx_hash(),
                    out_idx: index as u64,
                },
            )
            .await,
        );
    }
    assert_eq!(
        released_notes
            .iter()
            .map(|note| note.amount().msats)
            .sum::<u64>(),
        withdrawal_msats
    );
    // Verify every released blind signature by spending all resulting notes.
    let mut spend = transaction(
        released_notes
            .into_iter()
            .map(|note| DynInput::from_typed(MINT, MintInput::new_v0(note)))
            .collect(),
        vec![DynOutput::from_typed(
            DUMMY,
            DummyOutput {
                amount: Amount::from_msats(withdrawal_msats),
                unit: AmountUnit::BITCOIN,
            },
        )],
    );
    sign_transaction(
        &mut spend,
        &withdrawals
            .iter()
            .map(|request| request.key)
            .collect::<Vec<_>>(),
    )
    .unwrap();
    fed.process(&spend, 4).await.unwrap();
}

#[tokio::test]
async fn signatures_commit_to_claim_key_federation_module_and_foreign_outputs() {
    let fed = Harness::new();
    let owner = key();
    let program = contract_program(&owner, 0, 0);
    let original = program
        .output(Amount::from_sats(100), [0; 32], vec![])
        .unwrap();
    let funding = fed.fund(vec![DynOutput::from_typed(SIMP, original)]).await;
    let point = OutPoint {
        txid: funding.tx_hash(),
        out_idx: 0,
    };
    let mut tx = draft_spend(
        &program,
        point,
        &owner,
        true,
        vec![MintRequest::new(Denomination(10)).output()],
    );
    authorize(&mut tx, &program, point, &owner, true, &[]);
    let original_hash =
        fedimint_simplicity_common::signature_hash(federation_id(), SIMP, &tx).unwrap();
    assert_ne!(
        original_hash,
        fedimint_simplicity_common::signature_hash(
            FederationId(sha256::Hash::hash(b"other")),
            SIMP,
            &tx
        )
        .unwrap()
    );
    assert_ne!(
        original_hash,
        fedimint_simplicity_common::signature_hash(federation_id(), SIMP + 1, &tx).unwrap()
    );

    let mut redirected = tx.clone();
    redirected.outputs[0] = MintRequest::new(Denomination(10)).output();
    sign_transaction(&mut redirected, &[owner]).unwrap();
    assert!(
        fed.process(&redirected, 0).await.is_err(),
        "blinded payout cannot be substituted"
    );

    let attacker = key();
    let mut stolen = tx.clone();
    let mut input = stolen.inputs[0]
        .as_any()
        .downcast_ref::<ContractInput>()
        .unwrap()
        .clone();
    input.claim_key = attacker.public_key();
    stolen.inputs[0] = DynInput::from_typed(SIMP, input);
    sign_transaction(&mut stolen, &[attacker]).unwrap();
    assert!(fed.process(&stolen, 0).await.is_err());
    assert!(fed.contract(point).await.is_some());
    fed.process(&tx, 0).await.unwrap();
}

#[tokio::test]
async fn malformed_oversized_and_wrong_programs_do_not_consume_contracts() {
    let fed = Harness::new();
    let owner = key();
    let program = contract_program(&owner, 0, 0);
    let funding = fed
        .fund(vec![DynOutput::from_typed(
            SIMP,
            program
                .output(Amount::from_sats(100), [0; 32], vec![])
                .unwrap(),
        )])
        .await;
    let point = OutPoint {
        txid: funding.tx_hash(),
        out_idx: 0,
    };
    let mut tx = draft_spend(&program, point, &owner, true, vec![]);
    authorize(&mut tx, &program, point, &owner, true, &[]);
    for program_bytes in [vec![], vec![255; 24], vec![0; MAX_PROGRAM_BYTES + 1]] {
        let mut invalid = tx.clone();
        let mut input = invalid.inputs[0]
            .as_any()
            .downcast_ref::<ContractInput>()
            .unwrap()
            .clone();
        input.program = program_bytes;
        invalid.inputs[0] = DynInput::from_typed(SIMP, input);
        sign_transaction(&mut invalid, &[owner]).unwrap();
        assert!(fed.process(&invalid, 0).await.is_err());
        assert!(fed.contract(point).await.is_some());
    }
    for witness_bytes in [vec![], vec![255; 64], vec![0; MAX_WITNESS_BYTES + 1]] {
        let mut invalid = tx.clone();
        let mut input = invalid.inputs[0]
            .as_any()
            .downcast_ref::<ContractInput>()
            .unwrap()
            .clone();
        input.witness = witness_bytes;
        invalid.inputs[0] = DynInput::from_typed(SIMP, input);
        sign_transaction(&mut invalid, &[owner]).unwrap();
        assert!(fed.process(&invalid, 0).await.is_err());
        assert!(fed.contract(point).await.is_some());
    }
    let trivial = ContractProgram::compile("fn main() {}", Default::default()).unwrap();
    tx.inputs[0] = DynInput::from_typed(
        SIMP,
        trivial
            .input(point, owner.public_key(), Default::default())
            .unwrap(),
    );
    sign_transaction(&mut tx, &[owner]).unwrap();
    assert!(fed.process(&tx, 0).await.is_err());
    assert!(fed.contract(point).await.is_some());
}

#[tokio::test]
async fn consensus_clock_requires_threshold_and_rejects_unknown_or_stale_votes() {
    let peers = (0..4).map(PeerId::from).collect();
    let module = Simplicity::new_for_testing(peers).unwrap();
    let db = Database::new(MemDatabase::new(), Default::default());
    let mut tx = db.begin_transaction().await;
    module
        .process_consensus_item(
            &mut tx.to_ref_nc(),
            BlockCountVote(999_999),
            PeerId::from(0),
        )
        .await
        .unwrap();
    module
        .process_consensus_item(&mut tx.to_ref_nc(), BlockCountVote(100), PeerId::from(1))
        .await
        .unwrap();
    assert_eq!(module.consensus_block_count(&mut tx.to_ref_nc()).await, 0);
    module
        .process_consensus_item(&mut tx.to_ref_nc(), BlockCountVote(99), PeerId::from(2))
        .await
        .unwrap();
    assert_eq!(module.consensus_block_count(&mut tx.to_ref_nc()).await, 99);
    assert!(
        module
            .process_consensus_item(&mut tx.to_ref_nc(), BlockCountVote(1000), PeerId::from(99))
            .await
            .is_err()
    );
    assert!(
        module
            .process_consensus_item(&mut tx.to_ref_nc(), BlockCountVote(98), PeerId::from(2))
            .await
            .is_err()
    );
    assert_eq!(module.consensus_block_count(&mut tx.to_ref_nc()).await, 99);
    tx.commit_tx_result().await.unwrap();
}

#[tokio::test]
async fn invalid_outputs_and_duplicate_spends_roll_back() {
    let fed = Harness::new();
    let owner = key();
    let program = contract_program(&owner, 0, 0);
    let output = program
        .output(
            Amount::from_sats(100),
            [0; 32],
            vec![42; MAX_RECOVERY_BYTES],
        )
        .unwrap();
    let funding = fed
        .fund(vec![DynOutput::from_typed(SIMP, output.clone())])
        .await;
    let point = OutPoint {
        txid: funding.tx_hash(),
        out_idx: 0,
    };
    for change in 0..3 {
        let mut invalid = output.clone();
        match change {
            0 => invalid.version += 1,
            1 => invalid.recovery.push(0),
            _ => invalid.amount = Amount::from_msats(u64::MAX),
        }
        let mut tx = draft_spend(
            &program,
            point,
            &owner,
            true,
            vec![DynOutput::from_typed(SIMP, invalid)],
        );
        authorize(&mut tx, &program, point, &owner, true, &[]);
        let error = fed.process(&tx, 0).await.unwrap_err();
        let Some(TransactionError::Input(error)) = error.downcast_ref::<TransactionError>() else {
            panic!("expected a structural preflight error: {error:#}");
        };
        let expected = if change == 0 {
            ContractError::Version
        } else {
            ContractError::Limit
        };
        assert_eq!(
            error.as_any().downcast_ref::<ContractError>().unwrap(),
            &expected
        );
        assert_eq!(fed.contract(point).await.unwrap().output, output);
    }
    let mut duplicate = draft_spend(&program, point, &owner, true, vec![]);
    duplicate.inputs.push(duplicate.inputs[0].clone());
    let signature = signature_value(federation_id(), SIMP, &duplicate, &owner).unwrap();
    for input in &mut duplicate.inputs {
        *input = DynInput::from_typed(
            SIMP,
            spend_input(&program, point, &owner, true, signature.clone()),
        );
    }
    sign_transaction(&mut duplicate, &[owner, owner]).unwrap();
    assert!(fed.process(&duplicate, 0).await.is_err());
    assert_eq!(fed.contract(point).await.unwrap().output, output);
}
