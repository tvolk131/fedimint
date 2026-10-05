//! Authenticated session access shared by wallet replay and market discovery.
use std::collections::BTreeMap;

use fedimint_api_client::api::{DynGlobalApi, FederationResult};
use fedimint_core::PeerId;
use fedimint_core::module::ApiVersion;
use fedimint_core::module::registry::ModuleDecoderRegistry;
use fedimint_core::secp256k1::PublicKey;
use fedimint_core::session_outcome::SessionStatus;

#[derive(Debug, Clone)]
pub struct SessionHistory {
    pub(super) api: DynGlobalApi,
    decoders: ModuleDecoderRegistry,
    core_api_version: ApiVersion,
    broadcast_public_keys: Option<BTreeMap<PeerId, PublicKey>>,
}

impl SessionHistory {
    /// Use the negotiated core API version and broadcast keys from the trusted
    /// client config, never keys supplied by the history-serving peer. The core
    /// API verifies signed completed sessions and uses quorum queries for open
    /// sessions, older API versions, or configs without broadcast keys.
    pub fn new(
        api: DynGlobalApi,
        decoders: ModuleDecoderRegistry,
        core_api_version: ApiVersion,
        broadcast_public_keys: Option<BTreeMap<PeerId, PublicKey>>,
    ) -> Self {
        Self {
            api,
            // Both API versions must preserve foreign modules as opaque bytes.
            // Signature verification covers their original consensus encoding.
            decoders: decoders.with_fallback(),
            core_api_version,
            broadcast_public_keys,
        }
    }

    pub async fn session(&self, index: u64) -> FederationResult<SessionStatus> {
        self.api
            .get_session_status(
                index,
                &self.decoders,
                self.core_api_version,
                self.broadcast_public_keys.as_ref(),
            )
            .await
    }
}
