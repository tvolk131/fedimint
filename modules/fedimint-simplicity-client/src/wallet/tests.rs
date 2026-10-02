use bitcoin::hashes::{Hash, sha256};
use fedimint_core::core::{DynInput, DynOutput};
use fedimint_core::db::mem_impl::MemDatabase;
use fedimint_core::module::CommonModuleInit;
use fedimint_core::session_outcome::AcceptedItem;
use fedimint_core::transaction::TransactionSignature;
use fedimint_core::{Amount, PeerId};

use super::*;
use crate::common::assets::{AssetBundle, AssetId};
use crate::descriptor::BuiltinTemplates;

const MODULE: u16 = 7;

/// Simulates a software release that changed its current owner template while
/// retaining the previous definition for historical descriptors.
#[derive(Debug)]
struct UpgradedTemplates;
impl ContractTemplates for UpgradedTemplates {
    fn compile(
        &self,
        descriptor: &ContractDescriptor,
        owner: fedimint_core::secp256k1::XOnlyPublicKey,
    ) -> anyhow::Result<(u32, crate::ContractProgram)> {
        if descriptor.template == "owner" && descriptor.template_version == 2 {
            BuiltinTemplates.compile(
                &ContractDescriptor::top_up(descriptor.key_nonce, 0, 0),
                owner,
            )
        } else {
            BuiltinTemplates.compile(descriptor, owner)
        }
    }
}

#[tokio::test]
async fn compatible_wallet_software_restores_historical_template_versions() {
    let keys = WalletKeys::new(&root(), federation(), MODULE);
    let old = ContractDescriptor::owner([3; 32]);
    let current = ContractDescriptor {
        template_version: 2,
        ..old.clone()
    };
    let old_output = keys
        .program(&old, &BuiltinTemplates)
        .unwrap()
        .1
        .asset_output(
            Amount::from_sats(10),
            [0; 32],
            keys.encrypt(&old).unwrap(),
            AssetBundle::default(),
        )
        .unwrap();
    let current_output = keys
        .program(&current, &UpgradedTemplates)
        .unwrap()
        .1
        .output(
            Amount::from_sats(20),
            [0; 32],
            keys.encrypt(&current).unwrap(),
        )
        .unwrap();
    assert_ne!(old_output.cmr, current_output.cmr);
    let store = WalletStore::open(
        database(),
        &root(),
        federation(),
        MODULE,
        Arc::new(UpgradedTemplates),
    )
    .await
    .unwrap();
    let creation = tx(0, &[], vec![old_output, current_output]);
    store
        .apply_session(0, &session(&[creation]), true)
        .await
        .unwrap();
    let recovered = store.contracts().await;
    assert_eq!(recovered.len(), 2);
    assert_eq!(recovered[0].1.descriptor, old);
    assert_eq!(recovered[1].1.descriptor, current);
    for (_, contract) in recovered {
        let (version, program) = keys
            .program(&contract.descriptor, &UpgradedTemplates)
            .unwrap();
        assert_eq!(version, contract.output.version);
        assert_eq!(program.cmr(), contract.output.cmr);
    }
}
fn federation() -> FederationId {
    FederationId(sha256::Hash::from_byte_array([2; 32]))
}
fn root() -> DerivableSecret {
    DerivableSecret::new_root(&[1; 32], b"recovery-test")
}
fn database() -> Database {
    Database::new(
        MemDatabase::new(),
        ModuleDecoderRegistry::from_iter([(
            MODULE,
            crate::common::KIND,
            crate::common::SimplicityCommonInit::decoder(),
        )]),
    )
}
async fn wallet(db: Database) -> WalletStore {
    WalletStore::open(
        db,
        &root(),
        federation(),
        MODULE,
        Arc::new(BuiltinTemplates),
    )
    .await
    .unwrap()
}
fn output(store: &WalletStore, descriptor: &ContractDescriptor) -> ContractOutput {
    let (_, program) = store.keys.program(descriptor, &BuiltinTemplates).unwrap();
    program
        .asset_output(
            Amount::from_sats(10),
            [0; 32],
            store.keys.encrypt(descriptor).unwrap(),
            AssetBundle::default(),
        )
        .unwrap()
}
fn tx(nonce: u8, inputs: &[OutPoint], outputs: Vec<ContractOutput>) -> Transaction {
    Transaction {
        nonce: [nonce; 8],
        inputs: inputs
            .iter()
            .map(|point| {
                DynInput::from_typed(
                    MODULE,
                    ContractInput {
                        outpoint: *point,
                        claim_key: WalletKeys::new(&root(), federation(), MODULE)
                            .signing_key(&ContractDescriptor::owner([1; 32]))
                            .public_key(),
                        program: vec![],
                        witness: vec![],
                    },
                )
            })
            .collect(),
        outputs: outputs
            .into_iter()
            .map(|output| DynOutput::from_typed(MODULE, output))
            .collect(),
        signatures: TransactionSignature::NaiveMultisig(vec![]),
    }
}
fn session(txs: &[Transaction]) -> SessionOutcome {
    SessionOutcome {
        items: txs
            .iter()
            .map(|tx| AcceptedItem {
                peer: PeerId::from(0),
                item: ConsensusItem::Transaction(tx.clone()),
            })
            .collect(),
    }
}
fn point(tx: &Transaction) -> OutPoint {
    OutPoint {
        txid: tx.tx_hash(),
        out_idx: 0,
    }
}

#[tokio::test]
async fn stored_history_preserves_foreign_modules_unknown_to_this_wallet() {
    use fedimint_core::core::DynUnknown;
    let store = wallet(database()).await;
    let mut receive = tx(
        0,
        &[],
        vec![output(&store, &ContractDescriptor::owner([3; 32]))],
    );
    receive
        .inputs
        .push(DynInput::from_typed(1234, DynUnknown(vec![17, 42])));
    receive
        .outputs
        .push(DynOutput::from_typed(1234, DynUnknown(vec![53, 91])));
    store
        .apply_session(0, &session(std::slice::from_ref(&receive)), true)
        .await
        .unwrap();
    let reopened = wallet(store.db.clone()).await;
    let history = reopened.history().await;
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].transaction, receive);
    assert_eq!(
        history[0].transaction.consensus_encode_to_vec(),
        receive.consensus_encode_to_vec()
    );
}

#[tokio::test]
async fn ordered_scan_restores_descriptors_holdings_and_zero_balance_history() {
    let original = wallet(database()).await;
    let mut descriptor = ContractDescriptor::owner([3; 32]);
    descriptor.application_data = b"application secret and contract context".to_vec();
    let deposit = tx(0, &[], vec![output(&original, &descriptor)]);
    let transfer = tx(1, &[point(&deposit)], vec![output(&original, &descriptor)]);
    let withdrawal = tx(2, &[point(&transfer)], vec![]);
    let history = [
        session(&[deposit]),
        session(&[transfer]),
        session(&[withdrawal]),
    ];
    for (index, session) in history.iter().enumerate() {
        original
            .apply_session(index as u64, session, true)
            .await
            .unwrap();
    }
    let recovered = wallet(database()).await;
    for (index, session) in history.iter().enumerate() {
        recovered
            .apply_session(index as u64, session, true)
            .await
            .unwrap();
    }
    assert_eq!(recovered.contracts().await, original.contracts().await);
    assert_eq!(recovered.history().await, original.history().await);
    assert_eq!(recovered.history().await.len(), 3);
    assert!(
        recovered
            .contracts()
            .await
            .iter()
            .all(|(_, contract)| contract.spent_by.is_some() && contract.descriptor == descriptor)
    );
    assert_eq!(recovered.next_session().await, 3);
    // Completed sessions can be replayed after a crash without duplicating rows.
    recovered.apply_session(2, &history[2], true).await.unwrap();
    assert_eq!(recovered.history().await.len(), 3);
}

#[tokio::test]
async fn pending_prefix_resumes_after_reopening_and_rejects_history_gaps_or_changes() {
    let db = database();
    let store = wallet(db.clone()).await;
    let deposit = tx(
        0,
        &[],
        vec![output(&store, &ContractDescriptor::owner([3; 32]))],
    );
    let withdrawal = tx(1, &[point(&deposit)], vec![]);
    store
        .apply_session(0, &session(std::slice::from_ref(&deposit)), false)
        .await
        .unwrap();
    assert_eq!(store.next_session().await, 0);
    drop(store);
    let store = wallet(db).await;
    assert!(store.apply_session(1, &session(&[]), true).await.is_err());
    assert!(store.apply_session(0, &session(&[]), false).await.is_err());
    assert!(
        store
            .apply_session(0, &session(std::slice::from_ref(&withdrawal)), true)
            .await
            .is_err()
    );
    assert_eq!(store.history().await.len(), 1);
    store
        .apply_session(0, &session(&[deposit, withdrawal]), false)
        .await
        .unwrap();
    assert_eq!(store.history().await.len(), 2);
    let complete = store
        .db
        .begin_transaction_nc()
        .await
        .get_value(&db::OpenSessionKey)
        .await
        .unwrap();
    assert_eq!(complete.0, 2);
    // Reconstruct the exact accepted prefix from saved transactions.
    let txs: Vec<_> = store
        .history()
        .await
        .into_iter()
        .map(|entry| entry.transaction)
        .collect();
    store.apply_session(0, &session(&txs), true).await.unwrap();
    assert_eq!(store.next_session().await, 1);
    assert!(store.contracts().await[0].1.spent_by.is_some());
}

#[tokio::test]
async fn recovery_ignores_foreign_and_copied_records_but_fails_atomically_on_unsupported_owned_templates()
 {
    let store = wallet(database()).await;
    let descriptor = ContractDescriptor::owner([3; 32]);
    let real = output(&store, &descriptor);
    let mut copied = real.clone();
    copied.cmr = [42; 32];
    let mut foreign = real.clone();
    foreign.recovery = vec![7; 50];
    let mut unsupported = descriptor.clone();
    unsupported.template_version = 2;
    let mut future = real.clone();
    future.recovery = store.keys.encrypt(&unsupported).unwrap();
    let invalid = session(&[tx(
        0,
        &[],
        vec![real.clone(), copied.clone(), foreign.clone(), future],
    )]);
    assert!(store.apply_session(0, &invalid, true).await.is_err());
    assert!(store.contracts().await.is_empty());
    assert!(store.history().await.is_empty());
    assert_eq!(store.next_session().await, 0);
    store
        .apply_session(
            0,
            &session(&[tx(1, &[], vec![real, copied, foreign])]),
            true,
        )
        .await
        .unwrap();
    assert_eq!(store.contracts().await.len(), 1);
    assert!(
        WalletStore::open(
            store.db.clone(),
            &DerivableSecret::new_root(&[9; 32], b"recovery-test"),
            federation(),
            MODULE,
            Arc::new(BuiltinTemplates)
        )
        .await
        .is_err()
    );
}

#[tokio::test]
async fn recovery_follows_public_market_successor_without_its_original_annotation() {
    let store = wallet(database()).await;
    let market = crate::market::BinaryMarket {
        federation: federation(),
        module: MODULE,
        yes: AssetId([1; 32]),
        no: AssetId([2; 32]),
        event: [3; 32],
        rules: [4; 32],
        oracle: store
            .keys
            .signing_key(&ContractDescriptor::owner([1; 32]))
            .x_only_public_key()
            .0,
        resolution_start: 5,
        deadline: 10,
    };
    let descriptor = ContractDescriptor::binary_market([3; 32], &market);
    let mut vault = output(&store, &descriptor);
    vault.extension = Some(crate::common::assets::AssetExtension::Bundle(AssetBundle {
        balances: vec![],
        authorities: vec![market.yes, market.no],
    }));
    let creation = tx(0, &[], vec![vault.clone()]);
    vault.recovery.clear();
    vault.amount = Amount::from_sats(20);
    let successor = tx(1, &[point(&creation)], vec![vault]);
    store
        .apply_session(0, &session(&[creation, successor.clone()]), true)
        .await
        .unwrap();
    let holdings: Vec<_> = store
        .contracts()
        .await
        .into_iter()
        .filter(|(_, value)| value.spent_by.is_none())
        .collect();
    assert_eq!(holdings.len(), 1);
    assert_eq!(holdings[0].0, point(&successor));
    assert_eq!(holdings[0].1.descriptor, descriptor);
    assert!(!BuiltinTemplates.owns_balance(&descriptor));
}
