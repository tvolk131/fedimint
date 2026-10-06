//! Exercise the real authenticated query/cache layer over a controlled
//! transport.
use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use fedimint_api_client::api::global_api::with_cache::GlobalFederationApiWithCache;
use fedimint_api_client::api::{
    DynGlobalApi, DynModuleApi, IRawFederationApi, VERSION_THAT_INTRODUCED_GET_SESSION_STATUS_V2,
};
use fedimint_connectors::error::ServerError;
use fedimint_connectors::{DynGuaridianConnection, PeerStatus, ServerResult};
use fedimint_core::core::DynUnknown;
use fedimint_core::endpoint_constants::SESSION_STATUS_V2_ENDPOINT;
use fedimint_core::module::{
    ApiRequestErased, ApiVersion, SerdeModuleEncoding, SerdeModuleEncodingBase64,
};
use fedimint_core::secp256k1::{Keypair, Message, PublicKey, SECP256K1, SecretKey};
use fedimint_core::session_outcome::{SessionStatusV2, SignedSessionOutcome};
use futures::stream::BoxStream;

use super::*;

#[derive(Clone, Copy, Debug)]
enum Fault {
    None,
    Signature,
    Index,
    Body,
    Malformed,
    Unavailable,
}

#[derive(Debug)]
struct Api {
    peers: BTreeSet<PeerId>,
    complete: SessionOutcome,
    pending: SessionOutcome,
    fault: Fault,
    fail_all: AtomicBool,
    v2: AtomicUsize,
    v1: AtomicUsize,
}
fn keys() -> BTreeMap<PeerId, Keypair> {
    (0..4u8)
        .map(|n| {
            (
                u16::from(n).into(),
                Keypair::from_secret_key(SECP256K1, &SecretKey::from_slice(&[n + 10; 32]).unwrap()),
            )
        })
        .collect()
}
fn public_keys() -> BTreeMap<PeerId, PublicKey> {
    keys()
        .into_iter()
        .map(|(peer, key)| (peer, key.public_key()))
        .collect()
}
fn signed(session_outcome: SessionOutcome, index: u64) -> SignedSessionOutcome {
    let mut engine = sha256::Hash::engine();
    engine
        .write_all(public_keys().consensus_hash_sha256().as_ref())
        .unwrap();
    engine.write_all(&session_outcome.header(index)).unwrap();
    let message = Message::from_digest(sha256::Hash::from_engine(engine).to_byte_array());
    SignedSessionOutcome {
        session_outcome,
        signatures: keys()
            .iter()
            .take(3)
            .map(|(peer, key)| (*peer, SECP256K1.sign_schnorr_no_aux_rand(&message, key)))
            .collect(),
    }
}
impl Api {
    fn history(
        self: &Arc<Self>,
        version: ApiVersion,
        keys: Option<BTreeMap<PeerId, PublicKey>>,
    ) -> SessionHistory {
        let global: DynGlobalApi =
            GlobalFederationApiWithCache::new(Transport(self.clone())).into();
        SessionHistory::new(
            global,
            ModuleDecoderRegistry::from_iter([(
                MODULE,
                crate::common::KIND,
                crate::common::SimplicityCommonInit::decoder(),
            )]),
            version,
            keys,
        )
    }
}
#[derive(Debug)]
struct Transport(Arc<Api>);
#[async_trait::async_trait]
impl IRawFederationApi for Transport {
    fn all_peers(&self) -> &BTreeSet<PeerId> {
        &self.0.peers
    }
    fn self_peer(&self) -> Option<PeerId> {
        None
    }
    fn with_module(&self, _: u16) -> DynModuleApi {
        panic!("unexpected module query")
    }
    async fn request_raw(
        &self,
        _: PeerId,
        method: &str,
        params: &ApiRequestErased,
    ) -> ServerResult<serde_json::Value> {
        if method == "session_count" {
            return Ok(serde_json::json!(1));
        }
        let index: u64 = serde_json::from_value(params.params.clone()).unwrap();
        assert!(index <= 1);
        match method {
            "session_status" => {
                self.0.v1.fetch_add(1, Ordering::Relaxed);
                let status = if index == 0 {
                    SessionStatus::Complete(self.0.complete.clone())
                } else {
                    SessionStatus::Pending(self.0.pending.items.clone())
                };
                Ok(serde_json::to_value(SerdeModuleEncoding::from(&status)).unwrap())
            }
            SESSION_STATUS_V2_ENDPOINT => {
                let attempt = self.0.v2.fetch_add(1, Ordering::Relaxed);
                if index == 1 {
                    // Unsigned data from one peer must be discarded in favor of
                    // quorum agreement, even when it omits actual pending items.
                    return Ok(serde_json::to_value(SerdeModuleEncodingBase64::from(
                        &SessionStatusV2::Pending(vec![]),
                    ))
                    .unwrap());
                }
                let fault = if attempt == 0 || self.0.fail_all.load(Ordering::Relaxed) {
                    self.0.fault
                } else {
                    Fault::None
                };
                let mut signed = signed(
                    self.0.complete.clone(),
                    u64::from(matches!(fault, Fault::Index)),
                );
                match fault {
                    Fault::None | Fault::Index => {}
                    Fault::Signature => {
                        signed.signatures.pop_first();
                    }
                    Fault::Body => {
                        signed.session_outcome.items.clear();
                    }
                    Fault::Malformed => return Ok(serde_json::json!("invalid base64")),
                    Fault::Unavailable => return Err(ServerError::InvalidRpcId(method.to_owned())),
                }
                Ok(serde_json::to_value(SerdeModuleEncodingBase64::from(
                    &SessionStatusV2::Complete(signed),
                ))
                .unwrap())
            }
            _ => panic!("unexpected endpoint {method}"),
        }
    }
    fn connection_status_stream(&self) -> BoxStream<'static, BTreeMap<PeerId, PeerStatus>> {
        Box::pin(futures::stream::empty())
    }
    async fn wait_for_initialized_connections(&self) {}
    async fn get_peer_connection(&self, _: PeerId) -> ServerResult<DynGuaridianConnection> {
        panic!("unexpected connection")
    }
}
async fn fixture(fault: Fault) -> (WalletStore, Arc<Api>, Vec<Transaction>) {
    let store = wallet(database()).await;
    let mut receive = tx(
        1,
        &[],
        vec![output(&store, &ContractDescriptor::owner([3; 32]))],
    );
    receive
        .inputs
        .push(DynInput::from_typed(1234, DynUnknown(vec![17, 42])));
    receive
        .outputs
        .push(DynOutput::from_typed(1234, DynUnknown(vec![53, 91])));
    let spend = tx(2, &[point(&receive)], vec![]);
    let api = Arc::new(Api {
        peers: public_keys().into_keys().collect(),
        complete: session(std::slice::from_ref(&receive)),
        pending: session(std::slice::from_ref(&spend)),
        fault,
        fail_all: AtomicBool::new(false),
        v1: AtomicUsize::new(0),
        v2: AtomicUsize::new(0),
    });
    (store, api, vec![receive, spend])
}
async fn assert_recovered(store: &WalletStore, transactions: &[Transaction]) {
    let history = store.history().await;
    assert_eq!(
        history.iter().map(|h| &h.transaction).collect::<Vec<_>>(),
        transactions.iter().collect::<Vec<_>>()
    );
    for (entry, tx) in history.iter().zip(transactions) {
        assert_eq!(
            entry.transaction.consensus_encode_to_vec(),
            tx.consensus_encode_to_vec()
        );
    }
    assert_eq!(
        store.contracts().await[0].1.spent_by,
        Some(transactions[1].tx_hash())
    );
    assert_eq!(store.next_session().await, 1);
    assert!(!store.is_recovering().await);
}
#[tokio::test]
async fn signed_history_preserves_unknown_modules_and_quorum_open_prefix() {
    let (store, api, txs) = fixture(Fault::None).await;
    let source = api.history(
        VERSION_THAT_INTRODUCED_GET_SESSION_STATUS_V2,
        Some(public_keys()),
    );
    store.sync(&source, |_, _| {}).await.unwrap();
    assert_recovered(&store, &txs).await;
    assert_eq!(api.v2.load(Ordering::Relaxed), 2); // one signed session, one open probe
    assert_eq!(api.v1.load(Ordering::Relaxed), 3); // only the open session needs quorum
    store.sync(&source, |_, _| {}).await.unwrap();
    assert_recovered(&store, &txs).await;
}
#[tokio::test]
async fn old_api_or_missing_keys_uses_quorum_history() {
    for (version, keys) in [
        (ApiVersion::new(0, 0), Some(public_keys())),
        (VERSION_THAT_INTRODUCED_GET_SESSION_STATUS_V2, None),
    ] {
        let (store, api, txs) = fixture(Fault::None).await;
        store
            .sync(&api.history(version, keys), |_, _| {})
            .await
            .unwrap();
        assert_recovered(&store, &txs).await;
        assert_eq!(api.v2.load(Ordering::Relaxed), 0);
        assert_eq!(api.v1.load(Ordering::Relaxed), 6);
    }
}
#[tokio::test]
async fn invalid_signed_responses_fail_over_without_unauthenticated_downgrade() {
    for fault in [
        Fault::Signature,
        Fault::Index,
        Fault::Body,
        Fault::Malformed,
        Fault::Unavailable,
    ] {
        let (store, api, txs) = fixture(fault).await;
        store
            .sync(
                &api.history(
                    VERSION_THAT_INTRODUCED_GET_SESSION_STATUS_V2,
                    Some(public_keys()),
                ),
                |_, _| {},
            )
            .await
            .unwrap();
        assert_recovered(&store, &txs).await;
        assert_eq!(api.v2.load(Ordering::Relaxed), 3);
        assert_eq!(api.v1.load(Ordering::Relaxed), 3);
    }
}
#[tokio::test]
async fn authentication_failure_keeps_recovery_pending_and_retryable() {
    let (store, api, txs) = fixture(Fault::Signature).await;
    api.fail_all.store(true, Ordering::Relaxed);
    let source = api.history(
        VERSION_THAT_INTRODUCED_GET_SESSION_STATUS_V2,
        Some(public_keys()),
    );
    assert!(store.sync(&source, |_, _| {}).await.is_err());
    assert_eq!(api.v2.load(Ordering::Relaxed), 4);
    assert_eq!(api.v1.load(Ordering::Relaxed), 0);
    assert!(store.is_recovering().await);
    assert_eq!(store.next_session().await, 0);
    assert!(store.history().await.is_empty());
    assert!(store.contracts().await.is_empty());
    api.fail_all.store(false, Ordering::Relaxed);
    // Failed authentication must not poison the shared API cache.
    wallet(store.db.clone())
        .await
        .sync(&source, |_, _| {})
        .await
        .unwrap();
    assert_recovered(&store, &txs).await;
}

// Use the same position-bound public-order template as the recovery tests.
#[tokio::test]
async fn batch_watch_matches_sequential_imports_across_the_open_prefix() {
    use crate::exchange::{OrderState, PartialLimitOrder};

    let make_store = || async {
        WalletStore::open(
            database(),
            &root(),
            federation(),
            MODULE,
            Arc::new(super::partial::PartialTemplates),
        )
        .await
        .unwrap()
    };
    let batch = make_store().await;
    let sequential = make_store().await;
    let mut descriptor = ContractDescriptor::owner([51; 32]);
    let order = PartialLimitOrder {
        module: MODULE,
        maker: batch.keys.signing_key(&descriptor).x_only_public_key().0,
        asset: AssetId([5; 32]),
        unit_price: Amount::from_msats(400),
        buy: false,
        close_block: 100,
    };
    descriptor.template = "partial".into();
    descriptor.parameters = order.consensus_encode_to_vec();
    let program = order.program().unwrap();
    let output = |quantity| {
        let (amount, bundle) = order.balances(OrderState::new(quantity)).unwrap();
        program
            .asset_output(amount, [0; 32], vec![], bundle)
            .unwrap()
    };
    let creation = tx(40, &[], vec![output(10), output(20)]);
    let origins = [
        point(&creation),
        OutPoint {
            txid: creation.tx_hash(),
            out_idx: 1,
        },
    ];
    let mut fill = tx(41, &origins, vec![output(7), output(16)]);
    fill.inputs
        .insert(0, DynInput::from_typed(1234, DynUnknown(vec![7])));
    let successors = [
        point(&fill),
        OutPoint {
            txid: fill.tx_hash(),
            out_idx: 1,
        },
    ];
    let cancel = tx(42, &successors[..1], vec![]);
    let api = Arc::new(Api {
        peers: public_keys().into_keys().collect(),
        complete: session(&[creation]),
        pending: session(&[fill, cancel]),
        fault: Fault::None,
        fail_all: AtomicBool::new(false),
        v1: AtomicUsize::new(0),
        v2: AtomicUsize::new(0),
    });
    let source = api.history(
        VERSION_THAT_INTRODUCED_GET_SESSION_STATUS_V2,
        Some(public_keys()),
    );
    for store in [&batch, &sequential] {
        store.sync(&source, |_, _| {}).await.unwrap();
        assert!(store.contracts().await.is_empty()); // public, not wallet annotations
    }
    let requests = origins
        .into_iter()
        .map(|p| (p, descriptor.clone()))
        .collect::<Vec<_>>();
    let mut invalid = requests.clone();
    invalid.push((
        OutPoint {
            txid: origins[0].txid,
            out_idx: 99,
        },
        descriptor.clone(),
    ));
    assert!(batch.watch_contracts(&source, invalid).await.is_err());
    assert!(batch.contracts().await.is_empty());
    assert!(batch.history().await.is_empty()); // no partial merge on failure
    let before = api.v1.load(Ordering::Relaxed);
    let actual = batch
        .watch_contracts(&source, requests.clone())
        .await
        .unwrap();
    assert_eq!(api.v1.load(Ordering::Relaxed) - before, 3); // one open-prefix quorum
    let mut expected = BTreeMap::new();
    for request in requests.clone() {
        expected.extend(
            sequential
                .watch_contracts(&source, vec![request])
                .await
                .unwrap(),
        );
    }
    assert_eq!(actual, expected);
    assert_eq!(
        actual,
        BTreeMap::from([(origins[0], None), (origins[1], Some(successors[1]))])
    );
    assert_eq!(batch.contracts().await, sequential.contracts().await);
    assert_eq!(batch.history().await, sequential.history().await);
    // A valid announcement can name an already announced order's successor.
    // Batch import must coalesce it just as independent imports do.
    let overlapping = make_store().await;
    overlapping.sync(&source, |_, _| {}).await.unwrap();
    let mut wrong = requests.clone();
    wrong.push((successors[1], ContractDescriptor::owner([52; 32])));
    assert!(overlapping.watch_contracts(&source, wrong).await.is_err());
    assert!(overlapping.contracts().await.is_empty());
    assert!(overlapping.history().await.is_empty());
    let mut aliases = requests.clone();
    aliases.push((successors[1], descriptor.clone()));
    let alias_results = overlapping.watch_contracts(&source, aliases).await.unwrap();
    assert_eq!(alias_results[&origins[1]], Some(successors[1]));
    assert_eq!(alias_results[&successors[1]], Some(successors[1]));
    assert_eq!(overlapping.contracts().await, batch.contracts().await);
    assert_eq!(overlapping.history().await, batch.history().await);
    // Reimport is idempotent and cannot reopen a spent predecessor.
    assert_eq!(
        batch
            .watch_contracts(&source, requests.clone())
            .await
            .unwrap(),
        actual
    );
    assert_eq!(batch.history().await, sequential.history().await);
    let mut duplicate = requests;
    duplicate.push((origins[0], descriptor));
    assert!(batch.watch_contracts(&source, duplicate).await.is_err());
    assert_eq!(batch.history().await, sequential.history().await);
}

#[tokio::test]
async fn watch_rejects_a_changed_prefix_without_committing() {
    let (store, api, _) = fixture(Fault::None).await;
    let source = api.history(
        VERSION_THAT_INTRODUCED_GET_SESSION_STATUS_V2,
        Some(public_keys()),
    );
    store.sync(&source, |_, _| {}).await.unwrap();
    let before = store.history().await;
    let mut dbtx = store.db.begin_transaction().await;
    // Model a previously saved prefix different from the supplied quorum body.
    dbtx.insert_entry(&db::OpenSessionKey, &(1, Some(sha256::Hash::all_zeros())))
        .await;
    dbtx.commit_tx().await;
    let origin = point(&before[0].transaction);
    let error = store
        .watch_contracts(&source, vec![(origin, ContractDescriptor::owner([3; 32]))])
        .await
        .unwrap_err();
    assert!(error.to_string().contains("prefix changed"));
    assert_eq!(store.history().await, before);
}
