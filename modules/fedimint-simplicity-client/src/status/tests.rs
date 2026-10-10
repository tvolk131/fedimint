use std::collections::BTreeSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use fedimint_api_client::api::global_api::with_cache::GlobalFederationApiWithCache;
use fedimint_api_client::api::{DynModuleApi, IModuleFederationApi};
use fedimint_connectors::error::ServerError;
use fedimint_connectors::{DynGuaridianConnection, PeerStatus, ServerResult};
use futures::stream::BoxStream;
use serde_json::{Value, json};

use super::*;

#[derive(Debug)]
struct State {
    peers: BTreeSet<PeerId>,
    calls: Mutex<Vec<(Option<u16>, PeerId, String)>>,
    split: bool,
    unavailable: AtomicBool,
}
#[derive(Debug)]
struct Transport {
    state: Arc<State>,
    module: Option<u16>,
}
impl IModuleFederationApi for Transport {}

#[async_trait::async_trait]
impl IRawFederationApi for Transport {
    fn all_peers(&self) -> &BTreeSet<PeerId> {
        &self.state.peers
    }
    fn self_peer(&self) -> Option<PeerId> {
        None
    }
    fn with_module(&self, module: u16) -> DynModuleApi {
        Self {
            state: self.state.clone(),
            module: Some(module),
        }
        .into()
    }
    async fn request_raw(
        &self,
        peer: PeerId,
        method: &str,
        params: &ApiRequestErased,
    ) -> ServerResult<Value> {
        assert_eq!(params.params, Value::Null);
        assert!(params.auth.is_none());
        self.state
            .calls
            .lock()
            .unwrap()
            .push((self.module, peer, method.to_owned()));
        // Assert the complete read-only endpoint allowlist, including its scope.
        match (self.module, method) {
            (
                Some(4),
                ACTIVE_CONSENSUS_VERSION_ENDPOINT
                | SUPPORTED_CONSENSUS_VERSION_ENDPOINT
                | "block_count",
            )
            | (None, STATUS_ENDPOINT) => {}
            _ => panic!("unexpected endpoint/scope"),
        }
        if self.state.unavailable.load(Ordering::Relaxed) {
            return Err(ServerError::InvalidRpcId(anyhow::anyhow!("unavailable")));
        }
        if peer == PeerId::from(3) {
            return futures::future::pending().await;
        }
        if peer == PeerId::from(2) && method == SUPPORTED_CONSENSUS_VERSION_ENDPOINT {
            return Err(ServerError::InvalidRpcId(anyhow::anyhow!(
                "secret endpoint credential"
            )));
        }
        Ok(match method {
            ACTIVE_CONSENSUS_VERSION_ENDPOINT | SUPPORTED_CONSENSUS_VERSION_ENDPOINT => {
                // Future versions must be shown rather than rejected by the SDK.
                let minor = if self.state.split && peer == PeerId::from(2) {
                    98
                } else {
                    99
                };
                json!(ModuleConsensusVersion::new(0, minor))
            }
            "block_count" => json!(100 + u64::from(u16::from(peer))),
            STATUS_ENDPOINT => json!({ "server": "consensus_running", "federation": null }),
            _ => unreachable!(),
        })
    }
    fn connection_status_stream(&self) -> BoxStream<'static, BTreeMap<PeerId, PeerStatus>> {
        Box::pin(stream::empty())
    }
    async fn wait_for_initialized_connections(&self) {}
    async fn get_peer_connection(&self, _: PeerId) -> ServerResult<DynGuaridianConnection> {
        panic!("unexpected connection")
    }
}

fn fixture(split: bool) -> (DynGlobalApi, Arc<State>) {
    let state = Arc::new(State {
        peers: (0..4u16).map(PeerId::from).collect(),
        calls: Mutex::new(vec![]),
        split,
        unavailable: AtomicBool::new(false),
    });
    let api = GlobalFederationApiWithCache::new(Transport {
        state: state.clone(),
        module: None,
    })
    .into();
    (api, state)
}

#[tokio::test]
async fn one_shot_status_preserves_partial_results_and_never_sends_authorization() {
    let (api, state) = fixture(false);
    let report = query(&api, 4, Duration::from_millis(10)).await.unwrap();
    assert_eq!(report.quorum_size, 3);
    assert_eq!(
        report.quorum_active_version,
        Some(ModuleConsensusVersion::new(0, 99))
    );
    assert_eq!(report.guardians.len(), 4);
    assert!(matches!(
        report.guardians[&PeerId::from(3)].active_version,
        Query::TimedOut
    ));
    assert!(matches!(
        report.guardians[&PeerId::from(2)].supported_version,
        Query::Unavailable
    ));
    assert_eq!(
        report.guardians[&PeerId::from(2)].block_count.value(),
        Some(&102)
    );
    assert!(report.guardians[&PeerId::from(0)].core.value().is_some());
    assert_eq!(state.calls.lock().unwrap().len(), 16);
    assert!(
        !serde_json::to_string(&report)
            .unwrap()
            .contains("secret endpoint credential")
    );
}

#[tokio::test]
async fn split_responses_do_not_invent_quorum_or_reuse_previous_observations() {
    let (api, state) = fixture(true);
    let report = query(&api, 4, Duration::from_millis(10)).await.unwrap();
    assert_eq!(report.quorum_active_version, None);
    state.unavailable.store(true, Ordering::Relaxed);
    let report = query(&api, 4, Duration::from_millis(10)).await.unwrap();
    assert_eq!(report.quorum_active_version, None);
    assert!(
        report
            .guardians
            .values()
            .all(|guardian| matches!(guardian.active_version, Query::Unavailable))
    );
}
