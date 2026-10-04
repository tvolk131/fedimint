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
