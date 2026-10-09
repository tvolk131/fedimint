//! Follow the wallet module's all-peer readiness / ordered-vote activation.
use std::time::Duration;

use anyhow::ensure;
use fedimint_api_client::api::{DynModuleApi, FederationApiExt};
use fedimint_core::db::{DatabaseTransaction, IDatabaseTransactionOpsCoreTyped};
use fedimint_core::module::{ApiRequestErased, ModuleConsensusVersion};
use fedimint_core::task::TaskGroup;
use fedimint_core::{NumPeersExt, PeerId};
use fedimint_simplicity_common::MODULE_CONSENSUS_VERSION;
use fedimint_simplicity_common::consensus::{
    SUPPORTED_CONSENSUS_VERSION, SUPPORTED_CONSENSUS_VERSION_ENDPOINT,
};
use futures::future::join_all;
use tokio::sync::watch;

use crate::Simplicity;
use crate::db::VersionVoteKey;

#[derive(Debug)]
pub(crate) struct Upgrades {
    pub peer: PeerId,
    pub supported: ModuleConsensusVersion,
    pub readiness: Option<watch::Receiver<Option<ModuleConsensusVersion>>>,
}

impl Upgrades {
    pub fn new(peer: PeerId) -> Self {
        Self {
            peer,
            supported: SUPPORTED_CONSENSUS_VERSION,
            readiness: None,
        }
    }
}

impl Simplicity {
    pub async fn active_consensus_version(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
    ) -> ModuleConsensusVersion {
        let mut votes = Vec::with_capacity(self.cfg.consensus.peers.len());
        for peer in &self.cfg.consensus.peers {
            votes.push(
                dbtx.get_value(&VersionVoteKey(*peer))
                    .await
                    .unwrap_or(MODULE_CONSENSUS_VERSION),
            );
        }
        votes.sort_unstable();
        votes[self.cfg.consensus.peers.to_num_peers().max_evil()]
    }

    pub(crate) async fn ensure_supported(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
    ) -> anyhow::Result<()> {
        let active = self.active_consensus_version(dbtx).await;
        ensure!(
            active <= self.upgrades.supported,
            "Simplicity active consensus version {active} exceeds this binary's support {}; upgrade required",
            self.upgrades.supported
        );
        Ok(())
    }

    pub(crate) async fn assert_supported(&self, dbtx: &mut DatabaseTransaction<'_>) {
        // Returning a consensus-item error would reject an activation accepted
        // by upgraded peers and let this guardian continue under obsolete rules.
        // Like the wallet module, fail-stop instead, including during replay.
        if let Err(error) = self.ensure_supported(dbtx).await {
            panic!("{error}");
        }
    }

    pub(crate) async fn upgrade_proposal(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
    ) -> Option<ModuleConsensusVersion> {
        let ready = (*self.upgrades.readiness.as_ref()?.borrow())?;
        let previous = dbtx
            .get_value(&VersionVoteKey(self.upgrades.peer))
            .await
            .unwrap_or(MODULE_CONSENSUS_VERSION);
        (ready <= self.upgrades.supported
            && ready > previous
            && ready > self.active_consensus_version(dbtx).await)
            .then_some(ready)
    }

    pub(crate) async fn process_version_vote(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        peer: PeerId,
        version: ModuleConsensusVersion,
    ) -> anyhow::Result<()> {
        let previous = dbtx
            .get_value(&VersionVoteKey(peer))
            .await
            .unwrap_or(MODULE_CONSENSUS_VERSION);
        ensure!(
            version > previous,
            "redundant Simplicity consensus version vote"
        );
        // Unknown future version numbers must be recorded too: the old binary
        // stops at activation, not on the first minority vote for an upgrade.
        dbtx.insert_entry(&VersionVoteKey(peer), &version).await;
        self.assert_supported(dbtx).await;
        Ok(())
    }
}

pub(crate) async fn readiness(
    api: &DynModuleApi,
    our_peer: PeerId,
    supported: ModuleConsensusVersion,
) -> Option<ModuleConsensusVersion> {
    let replies = join_all(api.all_peers().iter().map(|&peer| async move {
        if peer == our_peer {
            return Some(supported);
        }
        // A silent peer must neither block refresh forever nor leave a stale
        // readiness value in use indefinitely.
        tokio::time::timeout(
            Duration::from_secs(10),
            api.request_single_peer::<ModuleConsensusVersion>(
                SUPPORTED_CONSENSUS_VERSION_ENDPOINT.to_owned(),
                ApiRequestErased::default(),
                peer,
            ),
        )
        .await
        .ok()?
        .ok()
    }))
    .await;
    replies
        .into_iter()
        .collect::<Option<Vec<_>>>()?
        .into_iter()
        .min()
}

pub(crate) fn spawn_readiness(
    api: DynModuleApi,
    tasks: &TaskGroup,
    our_peer: PeerId,
) -> watch::Receiver<Option<ModuleConsensusVersion>> {
    let (sender, receiver) = watch::channel(None);
    tasks.spawn_cancellable("simplicity upgrade readiness", async move {
        loop {
            sender.send_replace(None);
            let ready = readiness(&api, our_peer, SUPPORTED_CONSENSUS_VERSION).await;
            sender.send_replace(ready);
            tokio::time::sleep(Duration::from_secs(30)).await;
        }
    });
    receiver
}
