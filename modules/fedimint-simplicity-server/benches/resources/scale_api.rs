//! Controlled four-peer raw transport, using the real quorum query/cache layer.
use std::collections::BTreeSet;
use std::sync::atomic::{AtomicU64, Ordering};

use fedimint_api_client::api::global_api::with_cache::GlobalFederationApiWithCache;
use fedimint_api_client::api::{DynGlobalApi, DynModuleApi, IRawFederationApi};
use fedimint_connectors::{DynGuaridianConnection, PeerStatus, ServerResult};
use fedimint_core::PeerId;
use fedimint_core::module::{ApiRequestErased, SerdeModuleEncoding};
use fedimint_core::session_outcome::SessionStatus;
use fedimint_server::consensus::db::{SignedSessionOutcomeKey, SignedSessionOutcomePrefix};
use futures::StreamExt;
use futures::stream::BoxStream;

use super::*;

#[derive(Debug, Default)]
pub(super) struct Stats {
    pub bytes: AtomicU64,
    pub requests: AtomicU64,
    pub min_index: AtomicU64,
}
#[derive(Debug)]
pub(super) struct HistoryApi {
    db: Database,
    peers: BTreeSet<PeerId>,
    target: u64,
    pub stats: Arc<Stats>,
}
impl HistoryApi {
    pub async fn new(db: Database) -> Self {
        let target = db
            .begin_transaction_nc()
            .await
            .find_by_prefix_sorted_descending(&SignedSessionOutcomePrefix)
            .await
            .next()
            .await
            .expect("nonempty history")
            .0
            .0
            + 1;
        Self {
            db,
            peers: (0..4u16).map(PeerId::from).collect(),
            target,
            stats: Arc::new(Stats {
                min_index: AtomicU64::new(u64::MAX),
                ..Default::default()
            }),
        }
    }
    pub fn into_global(self) -> DynGlobalApi {
        GlobalFederationApiWithCache::new(self).into()
    }
}
#[async_trait::async_trait]
impl IRawFederationApi for HistoryApi {
    fn all_peers(&self) -> &BTreeSet<PeerId> {
        &self.peers
    }
    fn self_peer(&self) -> Option<PeerId> {
        None
    }
    fn with_module(&self, _: u16) -> DynModuleApi {
        panic!("unexpected module API during recovery")
    }
    async fn request_raw(
        &self,
        peer: PeerId,
        method: &str,
        params: &ApiRequestErased,
    ) -> ServerResult<serde_json::Value> {
        assert!(self.peers.contains(&peer));
        let response = match method {
            "session_count" => serde_json::json!(self.target),
            "session_status" => {
                let index: u64 =
                    serde_json::from_value(params.params.clone()).expect("session index");
                self.stats.min_index.fetch_min(index, Ordering::Relaxed);
                assert!(index <= self.target);
                let status = if index == self.target {
                    SessionStatus::Initial
                } else {
                    let signed = self
                        .db
                        .begin_transaction_nc()
                        .await
                        .get_value(&SignedSessionOutcomeKey(index))
                        .await
                        .expect("retained history");
                    SessionStatus::Complete(signed.session_outcome)
                };
                serde_json::to_value(SerdeModuleEncoding::from(&status)).expect("wire status")
            }
            _ => panic!("unexpected recovery endpoint {method}"),
        };
        self.stats.requests.fetch_add(1, Ordering::Relaxed);
        self.stats.bytes.fetch_add(
            serde_json::to_vec(&response).expect("JSON").len() as u64,
            Ordering::Relaxed,
        );
        Ok(response)
    }
    fn connection_status_stream(&self) -> BoxStream<'static, BTreeMap<PeerId, PeerStatus>> {
        Box::pin(futures::stream::empty())
    }
    async fn wait_for_initialized_connections(&self) {}
    async fn get_peer_connection(&self, _: PeerId) -> ServerResult<DynGuaridianConnection> {
        panic!("unexpected transport connection")
    }
}
