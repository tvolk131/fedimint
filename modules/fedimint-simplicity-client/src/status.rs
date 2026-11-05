//! Bounded, read-only observations using existing module and core endpoints.
//! No wallet is opened. Results are collected over an interval, not atomically;
//! reachability from this observer is not the federation's consensus health.
use std::collections::BTreeMap;
use std::time::{Duration, SystemTime};

use fedimint_api_client::api::{
    DynGlobalApi, FederationApiExt as _, IRawFederationApi, StatusResponse,
};
use fedimint_core::core::ModuleInstanceId;
use fedimint_core::endpoint_constants::STATUS_ENDPOINT;
use fedimint_core::module::{ApiRequestErased, ModuleConsensusVersion};
use fedimint_core::runtime::timeout;
use fedimint_core::{NumPeersExt as _, PeerId};
use futures::{StreamExt as _, stream};
use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::common::consensus::{
    ACTIVE_CONSENSUS_VERSION_ENDPOINT, SUPPORTED_CONSENSUS_VERSION_ENDPOINT,
};

#[cfg(test)]
mod tests;

#[derive(Debug, Serialize)]
pub struct Report {
    pub module_id: ModuleInstanceId,
    pub collection_started: SystemTime,
    pub collection_finished: SystemTime,
    pub quorum_size: usize,
    /// A threshold of identical active-version replies from distinct configured
    /// peers. None means this observation did not establish a version, not that
    /// the federation has no active version or has stopped consensus.
    pub quorum_active_version: Option<ModuleConsensusVersion>,
    pub guardians: BTreeMap<PeerId, Guardian>,
}

#[derive(Debug, Serialize)]
pub struct Guardian {
    pub supported_version: Query<ModuleConsensusVersion>,
    pub active_version: Query<ModuleConsensusVersion>,
    /// This module's consensus clock, not the guardian's Bitcoin RPC tip.
    pub block_count: Query<u64>,
    /// Reuse core status: session count, peer connections/contributions and
    /// attention flags are this guardian's view, not this observer's inference.
    pub core: Query<StatusResponse>,
}

#[derive(Debug, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum Query<T> {
    Available {
        value: T,
    },
    TimedOut,
    /// Includes transport, unsupported endpoint and malformed-response errors.
    /// Raw errors may contain endpoint credentials, so they are never echoed.
    Unavailable,
}

impl<T> Query<T> {
    pub fn value(&self) -> Option<&T> {
        match self {
            Self::Available { value } => Some(value),
            _ => None,
        }
    }
}

/// One observation per endpoint per guardian, without retries. At most four
/// guardians are queried concurrently, with four bounded requests per guardian.
/// The caller supplies a trusted federation API/configuration and module ID.
/// Unknown future version numbers remain displayable; this is not execution.
/// No readiness votes, activation predictions, or full-sync claims are
/// inferred.
pub async fn query(
    api: &DynGlobalApi,
    module: ModuleInstanceId,
    request_timeout: Duration,
) -> anyhow::Result<Report> {
    anyhow::ensure!(
        !api.all_peers().is_empty(),
        "status requires a nonempty peer set"
    );
    anyhow::ensure!(
        !request_timeout.is_zero(),
        "status timeout must be positive"
    );
    let collection_started = fedimint_core::time::now();
    let module_api = api.with_module(module);
    let guardians = stream::iter(api.all_peers().iter().copied())
        .map(|peer| {
            let module_api = &module_api;
            async move {
                let (supported_version, active_version, block_count, core) = futures::join!(
                    request(
                        &**module_api,
                        peer,
                        SUPPORTED_CONSENSUS_VERSION_ENDPOINT,
                        request_timeout
                    ),
                    request(
                        &**module_api,
                        peer,
                        ACTIVE_CONSENSUS_VERSION_ENDPOINT,
                        request_timeout
                    ),
                    request(&**module_api, peer, "block_count", request_timeout),
                    request(api.as_ref(), peer, STATUS_ENDPOINT, request_timeout),
                );
                (
                    peer,
                    Guardian {
                        supported_version,
                        active_version,
                        block_count,
                        core,
                    },
                )
            }
        })
        .buffered(4)
        .collect::<BTreeMap<_, _>>()
        .await;
    let quorum_size = api.all_peers().to_num_peers().threshold();
    let mut counts = BTreeMap::<ModuleConsensusVersion, usize>::new();
    for guardian in guardians.values() {
        if let Some(version) = guardian.active_version.value() {
            *counts.entry(*version).or_default() += 1;
        }
    }
    let quorum_active_version = counts
        .into_iter()
        .find_map(|(version, count)| (count >= quorum_size).then_some(version));
    Ok(Report {
        module_id: module,
        collection_started,
        collection_finished: fedimint_core::time::now(),
        quorum_size,
        quorum_active_version,
        guardians,
    })
}

async fn request<T: DeserializeOwned, A: IRawFederationApi + ?Sized>(
    api: &A,
    peer: PeerId,
    endpoint: &'static str,
    limit: Duration,
) -> Query<T> {
    match timeout(
        limit,
        api.request_single_peer(endpoint.to_owned(), ApiRequestErased::default(), peer),
    )
    .await
    {
        Ok(Ok(value)) => Query::Available { value },
        Ok(Err(_)) => Query::Unavailable,
        Err(_) => Query::TimedOut,
    }
}
