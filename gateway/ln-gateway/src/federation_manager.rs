use std::collections::BTreeMap;
use std::sync::Arc;

use fedimint_client::ClientHandleArc;
use fedimint_core::config::FederationId;
use fedimint_core::util::Spanned;
use tracing::error;

use crate::{GatewayError, Result};

/// The first SCID that the gateway will assign to a federation.
/// Note: This starts at 1 because an SCID of 0 is considered invalid by LND's
/// HTLC interceptor.
const INITIAL_SCID: u64 = 1;

pub struct FederationManager {
    /// Map of `FederationId` -> `Client`. Used for efficient retrieval of the
    /// client while handling incoming HTLCs.
    clients: BTreeMap<FederationId, Spanned<fedimint_client::ClientHandleArc>>,

    /// Map of short channel ids to `FederationId`. Use for efficient retrieval
    /// of the client while handling incoming HTLCs.
    scid_to_federation: BTreeMap<u64, FederationId>,

    /// Tracker for short channel ID assignments. When connecting a new
    /// federation, this value is incremented and assigned to the federation
    /// as the `mint_channel_id`
    next_scid: u64,
}

impl std::fmt::Debug for FederationManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FederationManager")
            .field("clients", &self.clients)
            .field("scid_to_federation", &self.scid_to_federation)
            .field("next_scid", &self.next_scid)
            .finish_non_exhaustive()
    }
}

impl FederationManager {
    pub fn new() -> Self {
        Self {
            clients: BTreeMap::new(),
            scid_to_federation: BTreeMap::new(),
            next_scid: INITIAL_SCID,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.clients.is_empty()
    }

    pub fn add_client(
        &mut self,
        scid: u64,
        federation_id: FederationId,
        client: Spanned<fedimint_client::ClientHandleArc>,
    ) {
        self.clients.insert(federation_id, client);
        self.scid_to_federation.insert(scid, federation_id);
    }

    /// Removes a federation client from the Gateway's in memory structures that
    /// keep track of available clients. Does not remove the persisted
    /// client configuration in the database.
    pub async fn remove_client(&mut self, federation_id: FederationId) -> Result<()> {
        let client = self
            .clients
            .remove(&federation_id)
            .ok_or(GatewayError::InvalidMetadata(format!(
                "No federation with id {federation_id}"
            )))?
            .into_value();

        if let Some(client) = Arc::into_inner(client) {
            client.shutdown().await;
        } else {
            error!("client is not unique, failed to remove client");
        }

        self.scid_to_federation
            .retain(|_, fid| *fid != federation_id);
        Ok(())
    }

    pub fn get_client_for_scid(&self, short_channel_id: u64) -> Option<Spanned<ClientHandleArc>> {
        let federation_id = self.scid_to_federation.get(&short_channel_id)?;
        // TODO(tvolk131): Cloning the client here could cause issues with client
        // shutdown (see `remove_client` above). Perhaps this function should take a
        // lambda and pass it into `client.with_sync`.
        self.clients.get(federation_id).cloned()
    }

    // TODO(tvolk131): Optimize this function by adding a reverse map from
    // federation_id to scid.
    pub fn get_scid_for_federation(&self, federation_id: FederationId) -> Option<u64> {
        self.scid_to_federation.iter().find_map(|(scid, fid)| {
            if *fid == federation_id {
                Some(*scid)
            } else {
                None
            }
        })
    }

    pub fn iter_clients(
        &self,
    ) -> impl Iterator<Item = (&FederationId, &Spanned<ClientHandleArc>)> + '_ {
        self.clients.iter()
    }

    pub fn clone_scid_map(&self) -> BTreeMap<u64, FederationId> {
        self.scid_to_federation.clone()
    }

    pub fn clone_client_map(&self) -> BTreeMap<FederationId, Spanned<ClientHandleArc>> {
        self.clients.clone()
    }

    pub fn get_client(&self, federation_id: FederationId) -> Option<Spanned<ClientHandleArc>> {
        self.clients.get(&federation_id).cloned()
    }

    pub fn has_federation(&self, federation_id: FederationId) -> bool {
        self.clients.contains_key(&federation_id)
    }

    pub fn set_next_scid(&mut self, next_scid: u64) {
        self.next_scid = next_scid;
    }

    pub fn pop_next_scid(&mut self) -> Result<u64> {
        let scid = self.next_scid;
        self.next_scid =
            self.next_scid
                .checked_add(1)
                .ok_or(GatewayError::GatewayConfigurationError(
                    "Too many connected federations".to_string(),
                ))?;
        Ok(scid)
    }
}
