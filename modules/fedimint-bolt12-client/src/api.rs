use std::collections::{BTreeMap, BTreeSet};
use std::future::ready;

use fedimint_api_client::api::{
    FederationApiExt, FederationResult, IModuleFederationApi, ServerError, ServerResult,
};
use fedimint_api_client::query::FilterMapThreshold;
use fedimint_bolt12_common::endpoint_constants::{
    ADD_GATEWAY_ENDPOINT, AWAIT_RECEIVES_ENDPOINT, CONTRACT_ENDPOINT, DECRYPTION_SHARES_ENDPOINT,
    GATEWAY_APPROVED_ENDPOINT, GATEWAYS_ENDPOINT, NEXT_STOCK_ENDPOINT, POOL_ITEMS_ENDPOINT,
    RECIPIENT_USED_ENDPOINT, REGISTRATION_BY_HANDLE_ENDPOINT, REGISTRATION_BY_RECIPIENT_ENDPOINT,
    REMOVE_GATEWAY_ENDPOINT, RESERVATION_ENDPOINT, SET_GATEWAY_VOTE_ENDPOINT,
};
use fedimint_bolt12_common::protocol::{
    ReceiveContract, Registration, RegistrationId, Reservation, ReservationId, StockItem,
    StreamedReceive,
};
use fedimint_core::module::{ApiAuth, ApiRequestErased};
use fedimint_core::secp256k1::PublicKey;
use fedimint_core::task::{MaybeSend, MaybeSync};
use fedimint_core::util::SafeUrl;
use fedimint_core::{NumPeersExt, OutPoint, PeerId, apply, async_trait_maybe_send};
use rand::seq::SliceRandom;
use tpe::{DecryptionKeyShare, PublicKeyShare};

#[apply(async_trait_maybe_send!)]
pub trait Bolt12FederationApi {
    async fn gateways(&self) -> FederationResult<Vec<SafeUrl>>;

    async fn gateways_from_peer(&self, peer: PeerId) -> ServerResult<Vec<SafeUrl>>;

    async fn add_gateway(&self, auth: ApiAuth, gateway: SafeUrl) -> FederationResult<bool>;

    async fn remove_gateway(&self, auth: ApiAuth, gateway: SafeUrl) -> FederationResult<bool>;

    async fn bolt12_registration_by_handle(
        &self,
        handle: [u8; 32],
    ) -> FederationResult<Option<(RegistrationId, Registration)>>;

    async fn bolt12_registration_by_recipient(
        &self,
        claim_pk: PublicKey,
    ) -> FederationResult<Option<(RegistrationId, Registration)>>;

    /// Whether `claim_pk` was ever registered, even if its registration has
    /// since expired and been pruned.
    async fn bolt12_recipient_used(&self, claim_pk: PublicKey) -> FederationResult<bool>;

    /// The lowest-indexed unused stock item of a registration.
    async fn bolt12_next_stock(
        &self,
        registration: RegistrationId,
    ) -> FederationResult<Option<(u64, StockItem)>>;

    /// An unfunded reservation.
    async fn bolt12_reservation(
        &self,
        reservation: ReservationId,
    ) -> FederationResult<Option<Reservation>>;

    /// A funded receive that has not been claimed or refunded yet.
    async fn bolt12_contract(
        &self,
        outpoint: OutPoint,
    ) -> FederationResult<Option<ReceiveContract>>;

    async fn await_bolt12_receives(&self, start: u64, n: usize) -> (Vec<StreamedReceive>, u64);

    async fn bolt12_gateway_approved(&self, gateway: PublicKey) -> FederationResult<bool>;

    /// Ready federation-generated preimage hashes in the pool starting at
    /// `min_index` (up to 32 entries per page).
    async fn bolt12_pool_items(&self, min_index: u64) -> FederationResult<Vec<(u64, [u8; 32])>>;

    /// A threshold of guardians' decryption shares for a funded receive,
    /// each set verified against the contract. Retries until it has them.
    async fn bolt12_decryption_shares(
        &self,
        outpoint: OutPoint,
        contract: ReceiveContract,
        tpe_pks: BTreeMap<PeerId, PublicKeyShare>,
    ) -> BTreeMap<PeerId, Vec<DecryptionKeyShare>>;

    async fn bolt12_set_gateway_vote(
        &self,
        auth: ApiAuth,
        gateway: PublicKey,
        approve: bool,
    ) -> FederationResult<()>;
}

#[apply(async_trait_maybe_send!)]
impl<T: ?Sized> Bolt12FederationApi for T
where
    T: IModuleFederationApi + MaybeSend + MaybeSync + 'static,
{
    async fn gateways(&self) -> FederationResult<Vec<SafeUrl>> {
        let gateways: BTreeMap<PeerId, Vec<SafeUrl>> = self
            .request_with_strategy(
                FilterMapThreshold::new(
                    |_, gateways| ready(Ok(gateways)),
                    self.all_peers().to_num_peers(),
                ),
                GATEWAYS_ENDPOINT.to_string(),
                ApiRequestErased::default(),
            )
            .await?;

        let mut union = gateways
            .values()
            .flatten()
            .cloned()
            .collect::<BTreeSet<SafeUrl>>()
            .into_iter()
            .collect::<Vec<SafeUrl>>();

        union.shuffle(&mut rand::thread_rng());

        union.sort_by_cached_key(|r| {
            gateways
                .values()
                .filter(|response| !response.contains(r))
                .count()
        });

        Ok(union)
    }

    async fn gateways_from_peer(&self, peer: PeerId) -> ServerResult<Vec<SafeUrl>> {
        self.request_single_peer::<Vec<SafeUrl>>(
            GATEWAYS_ENDPOINT.to_string(),
            ApiRequestErased::default(),
            peer,
        )
        .await
    }

    async fn add_gateway(&self, auth: ApiAuth, gateway: SafeUrl) -> FederationResult<bool> {
        self.request_admin(ADD_GATEWAY_ENDPOINT, ApiRequestErased::new(gateway), auth)
            .await
    }

    async fn remove_gateway(&self, auth: ApiAuth, gateway: SafeUrl) -> FederationResult<bool> {
        self.request_admin(
            REMOVE_GATEWAY_ENDPOINT,
            ApiRequestErased::new(gateway),
            auth,
        )
        .await
    }

    async fn bolt12_registration_by_handle(
        &self,
        handle: [u8; 32],
    ) -> FederationResult<Option<(RegistrationId, Registration)>> {
        self.request_current_consensus(
            REGISTRATION_BY_HANDLE_ENDPOINT.to_string(),
            ApiRequestErased::new(handle),
        )
        .await
    }

    async fn bolt12_registration_by_recipient(
        &self,
        claim_pk: PublicKey,
    ) -> FederationResult<Option<(RegistrationId, Registration)>> {
        self.request_current_consensus(
            REGISTRATION_BY_RECIPIENT_ENDPOINT.to_string(),
            ApiRequestErased::new(claim_pk),
        )
        .await
    }

    async fn bolt12_recipient_used(&self, claim_pk: PublicKey) -> FederationResult<bool> {
        self.request_current_consensus(
            RECIPIENT_USED_ENDPOINT.to_string(),
            ApiRequestErased::new(claim_pk),
        )
        .await
    }

    async fn bolt12_next_stock(
        &self,
        registration: RegistrationId,
    ) -> FederationResult<Option<(u64, StockItem)>> {
        self.request_current_consensus(
            NEXT_STOCK_ENDPOINT.to_string(),
            ApiRequestErased::new(registration),
        )
        .await
    }

    async fn bolt12_reservation(
        &self,
        reservation: ReservationId,
    ) -> FederationResult<Option<Reservation>> {
        self.request_current_consensus(
            RESERVATION_ENDPOINT.to_string(),
            ApiRequestErased::new(reservation),
        )
        .await
    }

    async fn bolt12_contract(
        &self,
        outpoint: OutPoint,
    ) -> FederationResult<Option<ReceiveContract>> {
        self.request_current_consensus(
            CONTRACT_ENDPOINT.to_string(),
            ApiRequestErased::new(outpoint),
        )
        .await
    }

    async fn await_bolt12_receives(&self, start: u64, n: usize) -> (Vec<StreamedReceive>, u64) {
        self.request_current_consensus_retry(
            AWAIT_RECEIVES_ENDPOINT.to_string(),
            ApiRequestErased::new((start, n)),
        )
        .await
    }

    async fn bolt12_gateway_approved(&self, gateway: PublicKey) -> FederationResult<bool> {
        self.request_current_consensus(
            GATEWAY_APPROVED_ENDPOINT.to_string(),
            ApiRequestErased::new(gateway),
        )
        .await
    }

    async fn bolt12_pool_items(&self, min_index: u64) -> FederationResult<Vec<(u64, [u8; 32])>> {
        self.request_current_consensus(
            POOL_ITEMS_ENDPOINT.to_string(),
            ApiRequestErased::new(min_index),
        )
        .await
    }

    async fn bolt12_decryption_shares(
        &self,
        outpoint: OutPoint,
        contract: ReceiveContract,
        tpe_pks: BTreeMap<PeerId, PublicKeyShare>,
    ) -> BTreeMap<PeerId, Vec<DecryptionKeyShare>> {
        let contract = std::sync::Arc::new(contract);
        let tpe_pks = std::sync::Arc::new(tpe_pks);

        self.request_with_strategy_retry(
            FilterMapThreshold::new(
                move |peer, shares: Vec<DecryptionKeyShare>| {
                    let contract = contract.clone();
                    let tpe_pks = tpe_pks.clone();

                    // Pairing verification is CPU-intensive; keep it off the async workers.
                    fedimint_core::runtime::spawn_blocking(move || {
                        let valid = tpe_pks
                            .get(&peer)
                            .is_some_and(|pk| contract.verify_decryption_shares(pk, &shares));

                        if valid {
                            Ok(shares)
                        } else {
                            Err(ServerError::InvalidResponse(
                                "Invalid decryption shares".to_string(),
                            ))
                        }
                    })
                },
                self.all_peers().to_num_peers(),
            ),
            DECRYPTION_SHARES_ENDPOINT.to_string(),
            ApiRequestErased::new(outpoint),
        )
        .await
    }

    async fn bolt12_set_gateway_vote(
        &self,
        auth: ApiAuth,
        gateway: PublicKey,
        approve: bool,
    ) -> FederationResult<()> {
        self.request_admin(
            SET_GATEWAY_VOTE_ENDPOINT,
            ApiRequestErased::new((gateway, approve)),
            auth,
        )
        .await
    }
}
