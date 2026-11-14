use fedimint_api_client::api::{FederationApiExt, FederationResult, IModuleFederationApi};
use fedimint_core::module::ApiRequestErased;
use fedimint_core::task::{MaybeSend, MaybeSync};
use fedimint_core::{OutPoint, apply, async_trait_maybe_send};
use fedimint_lnv2_common::ContractId;
use fedimint_lnv2_common::bolt12::{
    Registration, RegistrationId, Reservation, ReservationId, StockItem,
};
use fedimint_lnv2_common::endpoint_constants::{
    BOLT12_NEXT_POOL_ENDPOINT, BOLT12_NEXT_STOCK_ENDPOINT, BOLT12_REGISTRATION_BY_HANDLE_ENDPOINT,
    BOLT12_RESERVATION_ENDPOINT, CONSENSUS_BLOCK_COUNT_ENDPOINT,
    OUTGOING_CONTRACT_EXPIRATION_ENDPOINT,
};

#[apply(async_trait_maybe_send!)]
pub trait GatewayFederationApi {
    async fn outgoing_contract_expiration(
        &self,
        outpoint: OutPoint,
    ) -> FederationResult<Option<(ContractId, u64)>>;

    /// The consensus block count, answered once a threshold of guardians
    /// report the same value.
    async fn consensus_block_count(&self) -> FederationResult<u64>;

    async fn bolt12_registration_by_handle(
        &self,
        handle: [u8; 32],
    ) -> FederationResult<Option<(RegistrationId, Registration)>>;

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

    /// The lowest-indexed generated preimage not yet reserved.
    async fn bolt12_next_pool(&self) -> FederationResult<Option<(u64, [u8; 32])>>;
}

#[apply(async_trait_maybe_send!)]
impl<T: ?Sized> GatewayFederationApi for T
where
    T: IModuleFederationApi + MaybeSend + MaybeSync + 'static,
{
    async fn outgoing_contract_expiration(
        &self,
        outpoint: OutPoint,
    ) -> FederationResult<Option<(ContractId, u64)>> {
        self.request_current_consensus(
            OUTGOING_CONTRACT_EXPIRATION_ENDPOINT.to_string(),
            ApiRequestErased::new(outpoint),
        )
        .await
    }

    async fn consensus_block_count(&self) -> FederationResult<u64> {
        self.request_current_consensus(
            CONSENSUS_BLOCK_COUNT_ENDPOINT.to_string(),
            ApiRequestErased::new(()),
        )
        .await
    }

    async fn bolt12_registration_by_handle(
        &self,
        handle: [u8; 32],
    ) -> FederationResult<Option<(RegistrationId, Registration)>> {
        self.request_current_consensus(
            BOLT12_REGISTRATION_BY_HANDLE_ENDPOINT.to_string(),
            ApiRequestErased::new(handle),
        )
        .await
    }

    async fn bolt12_next_stock(
        &self,
        registration: RegistrationId,
    ) -> FederationResult<Option<(u64, StockItem)>> {
        self.request_current_consensus(
            BOLT12_NEXT_STOCK_ENDPOINT.to_string(),
            ApiRequestErased::new(registration),
        )
        .await
    }

    async fn bolt12_reservation(
        &self,
        reservation: ReservationId,
    ) -> FederationResult<Option<Reservation>> {
        self.request_current_consensus(
            BOLT12_RESERVATION_ENDPOINT.to_string(),
            ApiRequestErased::new(reservation),
        )
        .await
    }

    async fn bolt12_next_pool(&self) -> FederationResult<Option<(u64, [u8; 32])>> {
        self.request_current_consensus(
            BOLT12_NEXT_POOL_ENDPOINT.to_string(),
            ApiRequestErased::new(()),
        )
        .await
    }
}
