use fedimint_api_client::api::{FederationApiExt, FederationResult, IModuleFederationApi};
use fedimint_bolt12_common::bolt12::{
    Registration, RegistrationId, Reservation, ReservationId, StockItem,
};
use fedimint_bolt12_common::endpoint_constants::{
    BOLT12_GATEWAY_APPROVED_ENDPOINT, BOLT12_NEXT_STOCK_ENDPOINT, BOLT12_POOL_ITEMS_ENDPOINT,
    BOLT12_REGISTRATION_BY_HANDLE_ENDPOINT, BOLT12_RESERVATION_ENDPOINT,
    BOLT12_STOCK_ITEMS_ENDPOINT,
};
use fedimint_core::module::ApiRequestErased;
use fedimint_core::secp256k1::PublicKey;
use fedimint_core::task::{MaybeSend, MaybeSync};
use fedimint_core::{apply, async_trait_maybe_send};

#[apply(async_trait_maybe_send!)]
pub trait GatewayBolt12FederationApi {
    async fn bolt12_gateway_approved(&self, gateway: PublicKey) -> FederationResult<bool>;

    async fn bolt12_registration_by_handle(
        &self,
        handle: [u8; 32],
    ) -> FederationResult<Option<(RegistrationId, Registration)>>;

    async fn bolt12_next_stock(
        &self,
        registration: RegistrationId,
    ) -> FederationResult<Option<(u64, StockItem)>>;

    async fn bolt12_stock_items(
        &self,
        registration: RegistrationId,
        min_index: u64,
    ) -> FederationResult<Vec<(u64, StockItem)>>;

    async fn bolt12_reservation(
        &self,
        reservation: ReservationId,
    ) -> FederationResult<Option<Reservation>>;

    async fn bolt12_pool_items(&self, min_index: u64) -> FederationResult<Vec<(u64, [u8; 32])>>;
}

#[apply(async_trait_maybe_send!)]
impl<T: ?Sized> GatewayBolt12FederationApi for T
where
    T: IModuleFederationApi + MaybeSend + MaybeSync + 'static,
{
    async fn bolt12_gateway_approved(&self, gateway: PublicKey) -> FederationResult<bool> {
        self.request_current_consensus(
            BOLT12_GATEWAY_APPROVED_ENDPOINT.to_string(),
            ApiRequestErased::new(gateway),
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

    async fn bolt12_stock_items(
        &self,
        registration: RegistrationId,
        min_index: u64,
    ) -> FederationResult<Vec<(u64, StockItem)>> {
        self.request_current_consensus(
            BOLT12_STOCK_ITEMS_ENDPOINT.to_string(),
            ApiRequestErased::new((registration, min_index)),
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

    async fn bolt12_pool_items(&self, min_index: u64) -> FederationResult<Vec<(u64, [u8; 32])>> {
        self.request_current_consensus(
            BOLT12_POOL_ITEMS_ENDPOINT.to_string(),
            ApiRequestErased::new(min_index),
        )
        .await
    }
}
