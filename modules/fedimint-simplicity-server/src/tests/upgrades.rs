//! Exercise production vote, proposal, persistence and transaction hooks with a
//! test successor that retains the same execution environments as the baseline.
use std::collections::BTreeSet;
use std::panic::AssertUnwindSafe;

use fedimint_api_client::api::{
    DynModuleApi, IModuleFederationApi, IRawFederationApi, ServerError, ServerResult,
};
use fedimint_core::config::TypedServerModuleConfig as _;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::module::{ApiEndpointContext, ApiRequestErased, ModuleConsensusVersion};
use fedimint_simplicity_common::MODULE_CONSENSUS_VERSION as BASE;
use fedimint_simplicity_common::consensus::{
    ACTIVE_CONSENSUS_VERSION_ENDPOINT, SUPPORTED_CONSENSUS_VERSION_ENDPOINT,
};
use futures::FutureExt;
use tokio::sync::watch;

use super::*;
use crate::db::VersionVoteKey;

const NEXT: ModuleConsensusVersion = ModuleConsensusVersion::new(0, 3);

fn module(supported: ModuleConsensusVersion) -> Simplicity {
    let mut module = Simplicity::new_for_testing((0..4).map(PeerId::from).collect()).unwrap();
    module.upgrades.supported = supported;
    module
}

fn database() -> Database {
    Database::new(MemDatabase::new(), ModuleDecoderRegistry::default())
}

async fn vote(module: &Simplicity, db: &Database, peer: u16, version: ModuleConsensusVersion) {
    // Use the actual stable envelope, including unknown future version numbers.
    let item = SimplicityConsensusItem::ModuleConsensusVersion(version);
    let bytes = item.consensus_encode_to_vec();
    let item =
        SimplicityConsensusItem::consensus_decode_whole(&bytes, &ModuleDecoderRegistry::default())
            .unwrap();
    let mut dbtx = db.begin_transaction().await;
    module
        .process_consensus_item(&mut dbtx.to_ref_nc(), item, peer.into())
        .await
        .unwrap();
    dbtx.commit_tx_result().await.unwrap();
}

#[tokio::test]
async fn advertisements_only_enable_proposals_and_ordered_threshold_activates() {
    let mut upgraded = module(NEXT);
    let db = database();
    let (sender, receiver) = watch::channel(None);
    upgraded.upgrades.readiness = Some(receiver);
    let active = || async {
        upgraded
            .active_consensus_version(&mut db.begin_transaction_nc().await)
            .await
    };
    for ready in [None, Some(BASE), Some(NEXT)] {
        sender.send_replace(ready);
        let proposals = upgraded
            .consensus_proposal(&mut db.begin_transaction_nc().await)
            .await;
        assert_eq!(
            proposals,
            if ready == Some(NEXT) {
                vec![SimplicityConsensusItem::ModuleConsensusVersion(NEXT)]
            } else {
                vec![]
            }
        );
        assert_eq!(
            active().await,
            BASE,
            "local support cannot activate anything"
        );
    }
    vote(&upgraded, &db, 0, NEXT).await;
    assert!(
        upgraded
            .consensus_proposal(&mut db.begin_transaction_nc().await)
            .await
            .is_empty(),
        "do not keep proposing a recorded vote"
    );
    vote(&upgraded, &db, 1, NEXT).await;
    assert_eq!(active().await, BASE);
    vote(&upgraded, &db, 2, NEXT).await;
    assert_eq!(active().await, NEXT);
    sender.send_replace(None);
    assert_eq!(
        active().await,
        NEXT,
        "lost readiness cannot undo activation"
    );
    // A later minority vote must not advance the activated version either.
    vote(&upgraded, &db, 3, ModuleConsensusVersion::new(99, 0)).await;
    assert_eq!(active().await, NEXT);
}

#[tokio::test]
async fn old_binary_accepts_minority_votes_but_stops_at_activation() {
    let old = module(BASE);
    let db = database();
    vote(&old, &db, 0, NEXT).await;
    vote(&old, &db, 1, NEXT).await;
    let mut dbtx = db.begin_transaction().await;
    let failed = AssertUnwindSafe(old.process_consensus_item(
        &mut dbtx.to_ref_nc(),
        SimplicityConsensusItem::ModuleConsensusVersion(NEXT),
        2.into(),
    ))
    .catch_unwind()
    .await;
    assert!(
        failed.is_err(),
        "unsupported activation must stop, not return item rejection"
    );
    dbtx.ignore_uncommitted();
    drop(dbtx);
    assert_eq!(
        old.active_consensus_version(&mut db.begin_transaction_nc().await)
            .await,
        BASE
    );
    // Retrying history after restarting the old binary reaches the same stop.
    let restarted = module(BASE);
    let mut dbtx = db.begin_transaction().await;
    assert!(
        AssertUnwindSafe(restarted.process_consensus_item(
            &mut dbtx.to_ref_nc(),
            SimplicityConsensusItem::ModuleConsensusVersion(NEXT),
            2.into(),
        ))
        .catch_unwind()
        .await
        .is_err()
    );
    dbtx.ignore_uncommitted();
}

#[tokio::test]
async fn invalid_votes_and_unknown_items_do_not_change_state() {
    let upgraded = module(NEXT);
    let db = database();
    vote(&upgraded, &db, 0, NEXT).await;
    for (peer, item) in [
        (0, SimplicityConsensusItem::ModuleConsensusVersion(NEXT)),
        (0, SimplicityConsensusItem::ModuleConsensusVersion(BASE)),
        (1, SimplicityConsensusItem::ModuleConsensusVersion(BASE)),
        (99, SimplicityConsensusItem::ModuleConsensusVersion(NEXT)),
        (
            1,
            SimplicityConsensusItem::Default {
                variant: 42,
                bytes: vec![1, 2, 3],
            },
        ),
    ] {
        let mut dbtx = db.begin_transaction().await;
        assert!(
            upgraded
                .process_consensus_item(&mut dbtx.to_ref_nc(), item, peer.into())
                .await
                .is_err()
        );
        dbtx.commit_tx_result().await.unwrap();
    }
    let mut dbtx = db.begin_transaction_nc().await;
    assert_eq!(dbtx.get_value(&VersionVoteKey(0.into())).await, Some(NEXT));
    for peer in [1, 99] {
        assert!(dbtx.get_value(&VersionVoteKey(peer.into())).await.is_none());
    }
    assert_eq!(upgraded.active_consensus_version(&mut dbtx).await, BASE);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn checkpoint_restart_replay_and_downgrade_preserve_activation() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("db");
    let backup = dir.path().join("checkpoint");
    let open = |path| async {
        Database::new(
            fedimint_rocksdb::RocksDb::build(path).open().await.unwrap(),
            ModuleDecoderRegistry::default(),
        )
    };
    let db = open(path.clone()).await;
    let upgraded = module(NEXT);
    vote(&upgraded, &db, 0, NEXT).await;
    vote(&upgraded, &db, 1, NEXT).await;
    db.checkpoint(&backup).unwrap();
    vote(&upgraded, &db, 2, NEXT).await;
    drop(db);
    let reopened = open(path).await;
    assert_eq!(
        upgraded
            .active_consensus_version(&mut reopened.begin_transaction_nc().await)
            .await,
        NEXT
    );
    upgraded
        .ensure_supported(&mut reopened.begin_transaction_nc().await)
        .await
        .unwrap();
    let old = module(BASE);
    let error = old
        .ensure_supported(&mut reopened.begin_transaction_nc().await)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("upgrade required"));
    assert!(
        AssertUnwindSafe(old.consensus_proposal(&mut reopened.begin_transaction_nc().await))
            .catch_unwind()
            .await
            .is_err()
    );
    let restored = open(backup).await;
    assert_eq!(
        upgraded
            .active_consensus_version(&mut restored.begin_transaction_nc().await)
            .await,
        BASE
    );
    vote(&upgraded, &restored, 2, NEXT).await;
    assert_eq!(
        upgraded
            .active_consensus_version(&mut restored.begin_transaction_nc().await)
            .await,
        NEXT
    );
    // Original configurations remain the baseline after activation.
    let cfg = crate::config(vec![0.into()]).to_erased();
    assert_eq!(cfg.consensus.version, BASE);
    crate::load_config(&cfg).unwrap();
}

#[derive(Debug, Clone)]
enum Reply {
    Version(ModuleConsensusVersion),
    Offline,
    Malformed,
    Silent,
}

#[derive(Debug)]
struct SupportApi {
    peers: BTreeSet<PeerId>,
    replies: Vec<Reply>,
}

#[async_trait::async_trait]
impl IRawFederationApi for SupportApi {
    fn connection_status_stream(
        &self,
    ) -> futures::stream::BoxStream<'static, BTreeMap<PeerId, fedimint_connectors::PeerStatus>>
    {
        Box::pin(futures::stream::empty())
    }
    async fn wait_for_initialized_connections(&self) {}
    async fn get_peer_connection(
        &self,
        _: PeerId,
    ) -> ServerResult<fedimint_connectors::DynGuaridianConnection> {
        panic!("unused transport method")
    }

    fn all_peers(&self) -> &BTreeSet<PeerId> {
        &self.peers
    }
    fn self_peer(&self) -> Option<PeerId> {
        Some(0.into())
    }
    fn with_module(&self, _: u16) -> DynModuleApi {
        panic!("already a module API")
    }
    async fn request_raw(
        &self,
        peer: PeerId,
        method: &str,
        _: &ApiRequestErased,
    ) -> ServerResult<serde_json::Value> {
        assert_eq!(method, SUPPORTED_CONSENSUS_VERSION_ENDPOINT);
        assert_ne!(peer, PeerId::from(0));
        match &self.replies[usize::from(u16::from(peer))] {
            Reply::Version(v) => Ok(serde_json::to_value(v).unwrap()),
            Reply::Offline => Err(ServerError::Connection(anyhow::anyhow!("offline"))),
            Reply::Malformed => Ok(serde_json::json!("invalid")),
            Reply::Silent => futures::future::pending().await,
        }
    }
}
impl IModuleFederationApi for SupportApi {}

#[tokio::test(start_paused = true)]
async fn readiness_requires_every_peer_and_bounds_silent_requests() {
    for (last, expected) in [
        (Reply::Version(BASE), Some(BASE)),
        (Reply::Offline, None),
        (Reply::Malformed, None),
        (Reply::Silent, None),
        (Reply::Version(NEXT), Some(NEXT)),
        (
            Reply::Version(ModuleConsensusVersion::new(99, 0)),
            Some(NEXT),
        ),
    ] {
        let api = DynModuleApi::from(SupportApi {
            peers: (0..4).map(PeerId::from).collect(),
            replies: vec![
                Reply::Offline,
                Reply::Version(NEXT),
                Reply::Version(NEXT),
                last,
            ],
        });
        assert_eq!(
            crate::upgrades::readiness(&api, 0.into(), NEXT).await,
            expected
        );
    }
}

#[tokio::test]
async fn version_endpoints_distinguish_support_from_activation() {
    let upgraded = module(NEXT);
    let db = database();
    for activated in [false, true] {
        if activated {
            for peer in 0..3 {
                vote(&upgraded, &db, peer, NEXT).await;
            }
        }
        for (path, expected) in [
            (
                ACTIVE_CONSENSUS_VERSION_ENDPOINT,
                if activated { NEXT } else { BASE },
            ),
            (SUPPORTED_CONSENSUS_VERSION_ENDPOINT, NEXT),
        ] {
            let endpoint = upgraded
                .api_endpoints()
                .into_iter()
                .find(|e| e.path == path)
                .unwrap();
            let value = (endpoint.handler)(
                &upgraded,
                ApiEndpointContext::new(db.clone(), false),
                ApiRequestErased::default(),
            )
            .await
            .unwrap();
            assert_eq!(
                serde_json::from_value::<ModuleConsensusVersion>(value).unwrap(),
                expected
            );
        }
    }
}

#[tokio::test]
async fn existing_contracts_keep_their_commitments_and_fees_after_activation() {
    let mut fed = Harness::new();
    // Same transaction processor as production, with a future binary that
    // keeps supporting the two original contract execution environments.
    fed.modules =
        ServerModuleRegistry::new(fed.modules.iter_modules().map(|(id, kind, existing)| {
            (
                id,
                kind.clone(),
                if id == SIMP {
                    DynServerModule::from(module(NEXT))
                } else {
                    existing.clone()
                },
            )
        }));
    let program = ContractProgram::compile("fn main() {}", arguments([])).unwrap();
    let initial = fed
        .fund(vec![
            DynOutput::from_typed(
                SIMP,
                program
                    .output(Amount::from_sats(100), [0; 32], vec![])
                    .unwrap(),
            ),
            DynOutput::from_typed(
                SIMP,
                program
                    .asset_output(Amount::from_sats(100), [0; 32], vec![], Default::default())
                    .unwrap(),
            ),
        ])
        .await;
    let points: Vec<_> = (0..2)
        .map(|out_idx| OutPoint {
            txid: initial.tx_hash(),
            out_idx,
        })
        .collect();
    let owner = key();
    let inputs: Vec<_> = points
        .iter()
        .map(|point| {
            program
                .input(*point, owner.public_key(), witnesses([]))
                .unwrap()
        })
        .collect();
    let old_fees: Vec<_> = inputs
        .iter()
        .map(|input| fedimint_simplicity_common::runtime::input_fee(input).unwrap())
        .collect();
    let db = fed.db.with_prefix_module_id(SIMP).0;
    let upgraded = fed
        .modules
        .get_expect(SIMP)
        .as_any()
        .downcast_ref::<Simplicity>()
        .unwrap();
    for peer in 0..3 {
        vote(upgraded, &db, peer, NEXT).await;
    }
    for (index, (point, input)) in points.iter().zip(inputs).enumerate() {
        let stored = fed.contract(*point).await.unwrap();
        assert_eq!(stored.output.version, index as u32);
        assert_eq!(stored.output.cmr, program.cmr());
        assert_eq!(
            fedimint_simplicity_common::runtime::input_fee(&input).unwrap(),
            old_fees[index]
        );
        let mut spend = transaction(vec![DynInput::from_typed(SIMP, input)], vec![]);
        fed.sign(&mut spend, &[owner]).await.unwrap();
        fed.process(&spend, 1).await.unwrap();
        assert!(fed.contract(*point).await.is_none());
    }
}
