use std::sync::Arc;

use bitcoin::hashes::{Hash as _, sha256};
use fedimint_client_module::transaction::TransactionFinalizer as _;
use fedimint_core::TransactionId;
use fedimint_core::config::FederationId;
use fedimint_core::module::ModuleConsensusVersion;
use fedimint_core::secp256k1::{SECP256K1, SecretKey};
use fedimint_derive_secret::DerivableSecret;

use super::*;
use crate::common::StoredContract;
use crate::descriptor::{BuiltinTemplates, ContractDescriptor};
use crate::receipt::ReceiptContext;

const MODULE: u16 = 4;

fn federation() -> FederationId {
    FederationId(sha256::Hash::hash(b"preparation-test"))
}

async fn store() -> WalletStore {
    WalletStore::open(
        fedimint_core::db::Database::new(
            fedimint_core::db::mem_impl::MemDatabase::new(),
            Default::default(),
        ),
        &DerivableSecret::new_root(&[1; 32], b"preparation-test"),
        federation(),
        MODULE,
        Arc::new(BuiltinTemplates),
    )
    .await
    .unwrap()
}

/// An output carrying its encrypted recovery descriptor, so the wallet can
/// recover the transaction from its mnemonic without a sender receipt.
fn owned_output(store: &WalletStore, nonce: u8, msats: u64) -> ContractOutput {
    let descriptor = ContractDescriptor::owner([nonce; 32]);
    let (_, program) = store
        .keys
        .program(&descriptor, store.templates.as_ref())
        .unwrap();
    program
        .asset_output(
            Amount::from_msats(msats),
            [0; 32],
            store.keys.encrypt(&descriptor).unwrap(),
            Default::default(),
        )
        .unwrap()
}

/// The same policy without a recovery annotation: not recoverable by itself.
fn watched_output(store: &WalletStore, nonce: u8, msats: u64) -> ContractOutput {
    ContractOutput {
        recovery: vec![],
        ..owned_output(store, nonce, msats)
    }
}

fn point(index: u32) -> OutPoint {
    OutPoint {
        txid: TransactionId::from_raw_hash(sha256::Hash::hash(b"preparation-test")),
        out_idx: u64::from(index),
    }
}

/// Authenticated wallet records and one federation snapshot that agree.
struct Holdings {
    contracts: BTreeMap<OutPoint, WalletContract>,
    snapshot: PruningSnapshot,
}

impl Holdings {
    fn new() -> Self {
        Self {
            contracts: BTreeMap::new(),
            snapshot: PruningSnapshot {
                consensus_version: common::MODULE_CONSENSUS_VERSION,
                session_index: 3,
                block_count: 10,
                contracts: BTreeMap::new(),
            },
        }
    }

    fn with(mut self, index: u32, nonce: u8, output: ContractOutput) -> Self {
        let descriptor = ContractDescriptor::owner([nonce; 32]);
        self.snapshot.contracts.insert(
            point(index),
            StoredContract {
                output: output.clone(),
                creation_session: 1,
                creation_block_count: 5,
            },
        );
        self.contracts.insert(
            point(index),
            WalletContract {
                output,
                descriptor,
                creation_session: 1,
                spent_by: None,
            },
        );
        self
    }
}

fn plan(spends: &[u32], outputs: Vec<ContractOutput>) -> TransactionPlan {
    TransactionPlan {
        spends: spends
            .iter()
            .map(|index| SpendIntent::owner(point(*index)))
            .collect(),
        outputs,
        ..Default::default()
    }
}

fn prepare(
    store: &WalletStore,
    plan: &TransactionPlan,
    holdings: &Holdings,
) -> anyhow::Result<PreparedTransaction> {
    store.prepare_transaction(plan, &holdings.contracts, &holdings.snapshot)
}

fn error(result: anyhow::Result<PreparedTransaction>) -> String {
    match result {
        Ok(_) => panic!("expected preparation to fail"),
        Err(error) => format!("{error:#}"),
    }
}

fn transaction(prepared: &PreparedTransaction, nonce: [u8; 8]) -> Transaction {
    Transaction {
        inputs: prepared
            .inputs
            .iter()
            .map(|input| DynInput::from_typed(MODULE, input.input.clone()))
            .collect(),
        outputs: prepared
            .outputs
            .iter()
            .cloned()
            .map(|output| DynOutput::from_typed(MODULE, output))
            .collect(),
        nonce,
        signatures: TransactionSignature::NaiveMultisig(vec![]),
    }
}

fn amounts(msats: u64) -> Amounts {
    Amounts::new_bitcoin(Amount::from_msats(msats))
}

#[tokio::test]
async fn an_empty_plan_is_not_a_transaction() {
    let store = store().await;
    let holdings = Holdings::new();
    assert!(
        error(prepare(&store, &TransactionPlan::default(), &holdings))
            .contains("empty contract operation")
    );
}

#[tokio::test]
async fn output_only_quotes_need_no_spend_and_price_every_output() {
    let store = store().await;
    let holdings = Holdings::new();
    let output = owned_output(&store, 1, 25_000);
    let prepared = prepare(&store, &plan(&[], vec![output.clone()]), &holdings).unwrap();
    assert!(prepared.inputs.is_empty());
    assert!(prepared.authorization.spends.is_empty());
    // An owned output already makes the transaction recoverable.
    assert_eq!(prepared.outputs, vec![output.clone()]);
    assert!(prepared.authorization.receipt.is_none());
    let request = prepared.fee_request().unwrap();
    assert_eq!(request.input_amount, amounts(0));
    assert_eq!(request.input_fee, amounts(0));
    assert_eq!(request.output_amount, amounts(25_000));
    assert_eq!(
        request.output_fee,
        Amounts::new_bitcoin(common::output_fee(&output))
    );
}

#[tokio::test]
async fn direct_sends_to_unowned_outputs_include_the_automatic_receipt_in_the_quote() {
    let store = store().await;
    let holdings = Holdings::new();
    let output = watched_output(&store, 1, 25_000);
    let prepared = prepare(&store, &plan(&[], vec![output.clone()]), &holdings).unwrap();
    let receipt = prepared.authorization.receipt.as_ref().unwrap();
    assert_eq!(prepared.outputs.len(), 2);
    assert_eq!(prepared.outputs[0], output);
    assert_eq!(receipt.output_index, 1);
    assert!(prepared.outputs[1].actions().is_some());
    assert_eq!(prepared.outputs[1].recovery, receipt.placeholder().unwrap());
    let request = prepared.fee_request().unwrap();
    // The receipt output carries no value but pays for its reserved bytes.
    assert_eq!(request.output_amount, amounts(25_000));
    assert_eq!(
        request.output_fee,
        Amounts::new_bitcoin(
            prepared
                .outputs
                .iter()
                .map(common::output_fee)
                .sum::<Amount>()
        )
    );
    assert!(common::output_fee(&prepared.outputs[1]).msats > 100);
}

#[tokio::test]
async fn a_requested_receipt_is_quoted_even_when_outputs_are_recoverable() {
    let store = store().await;
    let holdings = Holdings::new();
    let output = owned_output(&store, 1, 25_000);
    let bare = plan(&[], vec![output.clone()]);
    let requested = TransactionPlan {
        receipt: Some(SenderReceipt {
            context: Some(ReceiptContext {
                application: "test".to_owned(),
                version: 1,
                data: vec![7; 200],
            }),
        }),
        ..bare.clone()
    };
    let bare = prepare(&store, &bare, &holdings).unwrap();
    let requested = prepare(&store, &requested, &holdings).unwrap();
    assert!(bare.authorization.receipt.is_none());
    assert!(requested.authorization.receipt.is_some());
    assert_eq!(requested.outputs.len(), 2);
    assert!(
        requested.fee_request().unwrap().output_fee.get_bitcoin()
            > bare.fee_request().unwrap().output_fee.get_bitcoin(),
        "the receipt context is paid for in the quote, as in submission"
    );
}

#[tokio::test]
async fn the_quoted_receipt_fee_equals_the_fee_of_the_finalized_receipt() {
    let store = store().await;
    let holdings = Holdings::new();
    let prepared = prepare(
        &store,
        &plan(&[], vec![watched_output(&store, 1, 25_000)]),
        &holdings,
    )
    .unwrap();
    let quoted = prepared.fee_request().unwrap().output_fee;
    // Late funding fixes the nonce and inputs only after the quote.
    let mut tx = transaction(&prepared, [5; 8]);
    for (index, output) in prepared.authorization.prepare_outputs(&tx).unwrap() {
        tx.outputs[index] = output;
    }
    prepared.authorization.verify_finalized(&tx).unwrap();
    let finalized: Amount = tx
        .outputs
        .iter()
        .map(|output| common::output_fee(output.as_any().downcast_ref().unwrap()))
        .sum();
    assert_eq!(quoted, Amounts::new_bitcoin(finalized));
    // The receipt commits to the nonce, so it cannot move to another payer.
    tx.nonce = [6; 8];
    assert!(prepared.authorization.verify_finalized(&tx).is_err());
}

#[tokio::test]
async fn spends_are_priced_from_the_pruned_draft_and_never_authorize_the_final_nonce() {
    let store = store().await;
    let holdings = Holdings::new()
        .with(0, 10, owned_output(&store, 10, 40_000))
        .with(1, 11, owned_output(&store, 11, 60_000));
    let destination = owned_output(&store, 12, 90_000);
    let prepared = prepare(&store, &plan(&[0, 1], vec![destination]), &holdings).unwrap();
    let request = prepared.fee_request().unwrap();
    assert_eq!(request.input_amount, amounts(100_000));
    assert_eq!(request.output_amount, amounts(90_000));
    let fees = prepared
        .inputs
        .iter()
        .map(|input| common::runtime::input_fee(&input.input).unwrap())
        .sum::<Amount>();
    assert!(fees.msats > 0);
    assert_eq!(request.input_fee, Amounts::new_bitcoin(fees));
    for (input, expected) in prepared.inputs.iter().zip([40_000, 60_000]) {
        assert_eq!(input.amounts, amounts(expected));
        assert_eq!(input.keys.len(), 1);
    }
    assert_eq!(
        prepared
            .authorization
            .spends
            .iter()
            .map(|spend| spend.outpoint)
            .collect::<Vec<_>>(),
        vec![point(0), point(1)]
    );

    // Funding adds another output and fixes the nonce. Finalization signs again
    // from the original template and must reach the quoted fee exactly.
    let mut tx = transaction(&prepared, [9; 8]);
    tx.outputs.push(DynOutput::from_typed(
        7,
        ContractOutput::action_output(Default::default()),
    ));
    let finalized = prepared.authorization.finalize_inputs(&tx).unwrap();
    let draft_inputs = tx.inputs.clone();
    for (index, input) in finalized {
        tx.inputs[index] = input;
    }
    for (index, input) in tx.inputs.iter().enumerate() {
        let final_input = input.as_any().downcast_ref::<ContractInput>().unwrap();
        let draft = draft_inputs[index]
            .as_any()
            .downcast_ref::<ContractInput>()
            .unwrap();
        let environment = prepared
            .authorization
            .snapshot
            .environment(federation(), MODULE, &tx, index)
            .unwrap();
        assert!(common::runtime::execute(final_input, &environment).is_ok());
        assert_eq!(
            common::runtime::input_fee(final_input).unwrap(),
            common::runtime::input_fee(draft).unwrap()
        );
        assert!(
            common::runtime::execute(draft, &environment).is_err(),
            "a quote's draft signature must not authorize the funded transaction"
        );
    }
}

#[tokio::test]
async fn a_watched_input_still_gets_an_automatic_receipt() {
    let store = store().await;
    let holdings = Holdings::new().with(0, 10, watched_output(&store, 10, 40_000));
    let prepared = prepare(
        &store,
        &plan(&[0], vec![watched_output(&store, 12, 30_000)]),
        &holdings,
    )
    .unwrap();
    assert_eq!(prepared.outputs.len(), 2);
    assert!(prepared.authorization.receipt.is_some());
    // Owning the input's recovery descriptor makes receipts unnecessary.
    let holdings = Holdings::new().with(0, 10, owned_output(&store, 10, 40_000));
    let prepared = prepare(
        &store,
        &plan(&[0], vec![watched_output(&store, 12, 30_000)]),
        &holdings,
    )
    .unwrap();
    assert_eq!(prepared.outputs.len(), 1);
    assert!(prepared.authorization.receipt.is_none());
}

#[tokio::test]
async fn wallet_records_must_be_unspent_known_and_not_repeated() {
    let store = store().await;
    let base = || Holdings::new().with(0, 10, owned_output(&store, 10, 40_000));
    let destination = owned_output(&store, 12, 30_000);
    let spend = plan(&[0], vec![destination.clone()]);
    prepare(&store, &spend, &base()).unwrap();

    let mut holdings = base();
    holdings.contracts.clear();
    assert!(error(prepare(&store, &spend, &holdings)).contains("unknown contract"));

    let mut holdings = base();
    holdings.contracts.get_mut(&point(0)).unwrap().spent_by =
        Some(TransactionId::from_raw_hash(sha256::Hash::hash(b"spender")));
    assert!(error(prepare(&store, &spend, &holdings)).contains("already been spent"));

    assert!(
        error(prepare(&store, &plan(&[0, 0], vec![destination]), &base())).contains("spent twice")
    );
}

#[tokio::test]
async fn snapshot_drift_from_authenticated_history_is_rejected() {
    let store = store().await;
    let base = || Holdings::new().with(0, 10, owned_output(&store, 10, 40_000));
    let spend = plan(&[0], vec![owned_output(&store, 12, 30_000)]);
    prepare(&store, &spend, &base()).unwrap();

    let mut holdings = base();
    holdings.snapshot.contracts.clear();
    assert!(error(prepare(&store, &spend, &holdings)).contains("missing pruning input context"));

    // The federation reports another output at this outpoint.
    let mut holdings = base();
    holdings
        .snapshot
        .contracts
        .get_mut(&point(0))
        .unwrap()
        .output
        .state[0] ^= 1;
    assert!(error(prepare(&store, &spend, &holdings)).contains("pruning context differs"));

    let mut holdings = base();
    holdings
        .snapshot
        .contracts
        .get_mut(&point(0))
        .unwrap()
        .creation_session += 1;
    assert!(error(prepare(&store, &spend, &holdings)).contains("pruning context differs"));

    // Clock observations are not part of the comparison: they only move.
    let mut holdings = base();
    holdings.snapshot.block_count += 100;
    holdings.snapshot.session_index += 1;
    prepare(&store, &spend, &holdings).unwrap();
}

#[tokio::test]
async fn execution_versions_must_be_active_for_outputs_and_spent_contracts() {
    let store = store().await;
    let base = || Holdings::new().with(0, 10, owned_output(&store, 10, 40_000));
    let output = owned_output(&store, 12, 30_000);
    let unsupported = ContractOutput {
        version: 2,
        ..output.clone()
    };
    for spend in [
        plan(&[], vec![unsupported.clone()]),
        plan(&[0], vec![unsupported]),
    ] {
        assert!(error(prepare(&store, &spend, &base())).contains("unsupported execution version"));
    }
    // The federation has not activated the rules this output requires.
    let mut holdings = base();
    holdings.snapshot.consensus_version = ModuleConsensusVersion::new(0, 0);
    for spend in [
        plan(&[], vec![output.clone()]),
        plan(&[0], vec![output.clone()]),
    ] {
        assert!(
            error(prepare(&store, &spend, &holdings)).contains("unsupported execution version")
        );
    }
    // A spent contract is checked even when its wallet record and the
    // federation agree.
    let mut holdings = base();
    for version in [
        &mut holdings
            .contracts
            .get_mut(&point(0))
            .unwrap()
            .output
            .version,
        &mut holdings
            .snapshot
            .contracts
            .get_mut(&point(0))
            .unwrap()
            .output
            .version,
    ] {
        *version = 2;
    }
    assert!(
        error(prepare(&store, &plan(&[0], vec![output]), &holdings))
            .contains("unsupported execution version")
    );
}

#[tokio::test]
async fn a_shared_snapshot_only_constrains_the_contracts_a_plan_spends() {
    let store = store().await;
    // One snapshot reused for many route quotes may describe unrelated
    // contracts, including ones this wallet's rules cannot execute.
    let mut holdings = Holdings::new().with(0, 10, owned_output(&store, 10, 40_000));
    holdings.snapshot.contracts.insert(
        point(9),
        StoredContract {
            output: ContractOutput {
                version: 2,
                ..owned_output(&store, 13, 1)
            },
            creation_session: 1,
            creation_block_count: 5,
        },
    );
    prepare(
        &store,
        &plan(&[0], vec![owned_output(&store, 12, 30_000)]),
        &holdings,
    )
    .unwrap();
    prepare(
        &store,
        &plan(&[], vec![owned_output(&store, 12, 30_000)]),
        &holdings,
    )
    .unwrap();
}

#[tokio::test]
async fn the_shared_resource_limit_rejects_oversized_drafts_before_funding() {
    let store = store().await;
    let holdings = Holdings::new();
    for count in [common::MAX_CONTRACTS, common::MAX_CONTRACTS + 1] {
        let outputs = vec![owned_output(&store, 1, 1_000); count];
        let result = prepare(&store, &plan(&[], outputs), &holdings);
        if count == common::MAX_CONTRACTS {
            result.unwrap().fee_request().unwrap();
        } else {
            assert!(error(result).contains("resource limit"));
        }
    }
}

#[tokio::test]
async fn the_fee_ceiling_matches_the_finalizers_boundary() {
    let store = store().await;
    let holdings = Holdings::new();
    let limited = TransactionPlan {
        max_fee: Some(Amount::from_msats(317)),
        ..plan(&[], vec![owned_output(&store, 1, 25_000)])
    };
    let prepared = prepare(&store, &limited, &holdings).unwrap();
    assert_eq!(prepared.authorization.max_fee, limited.max_fee);
    for fee in [0, 316, 317, 318, 10_000] {
        let amount = Amount::from_msats(fee);
        let quote = limited.check_fee_ceiling(amount);
        let finalizer = prepared.authorization.verify_fees(&amounts(fee));
        assert_eq!(quote.is_ok(), fee <= 317, "fee {fee}");
        assert_eq!(quote.is_ok(), finalizer.is_ok(), "fee {fee}");
    }
    let rejection = limited
        .check_fee_ceiling(Amount::from_msats(318))
        .unwrap_err();
    assert!(rejection.to_string().contains("fee ceiling"), "{rejection}");
    // Without a ceiling, only funding decides.
    TransactionPlan::default()
        .check_fee_ceiling(Amount::from_msats(u64::MAX))
        .unwrap();
}

#[tokio::test]
async fn preparation_leaves_creation_keys_with_the_authorization_for_finalization() {
    let store = store().await;
    let holdings = Holdings::new();
    let key = Keypair::from_secret_key(SECP256K1, &SecretKey::from_slice(&[0x42; 32]).unwrap());
    let with_creation = TransactionPlan {
        creations: vec![key],
        ..plan(&[], vec![owned_output(&store, 1, 25_000)])
    };
    let prepared = prepare(&store, &with_creation, &holdings).unwrap();
    assert_eq!(prepared.authorization.creations, vec![key]);
    let secret = key
        .secret_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let shown = format!("{with_creation:?}");
    assert!(shown.contains("creations: 1"), "{shown}");
    assert!(!shown.contains(&secret), "{shown}");
}
