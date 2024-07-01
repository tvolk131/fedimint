use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use bitcoin::address::NetworkUnchecked;
use bitcoin::{Address, Txid};
use fedimint_client::ClientHandleArc;
use fedimint_core::config::{FederationId, JsonClientConfig};
use fedimint_core::secp256k1::schnorr::Signature;
use fedimint_core::secp256k1::PublicKey;
use fedimint_core::util::Spanned;
use fedimint_core::{Amount, BitcoinAmountOrAll};
use fedimint_lnv2_client::{PaymentFee, RoutingInfo, SendPaymentPayload};
use fedimint_wallet_client::{WalletClientModule, WithdrawState};
use futures::stream::StreamExt;
use tracing::{error, info};

use crate::gateway_module_v2::GatewayClientModuleV2;
use crate::{GatewayError, Result, EXPIRATION_DELTA_MINIMUM_V2};

/// The first SCID that the gateway will assign to a federation.
/// Note: This starts at 1 because an SCID of 0 is considered invalid by LND's
/// HTLC interceptor.
const INITIAL_SCID: u64 = 1;

#[derive(Debug)]
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
    next_scid: AtomicU64,
}

impl FederationManager {
    pub fn new() -> Self {
        Self {
            clients: BTreeMap::new(),
            scid_to_federation: BTreeMap::new(),
            next_scid: AtomicU64::new(INITIAL_SCID),
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
        if let Some(client) = self.clients.get(federation_id).cloned() {
            Some(client)
        } else {
            error!("`FederationManager.scid_to_federation` is out of sync with `FederationManager.clients`! This is a bug.");
            None
        }
    }

    pub fn clone_scid_map(&self) -> BTreeMap<u64, FederationId> {
        self.scid_to_federation.clone()
    }

    pub fn has_federation(&self, federation_id: FederationId) -> bool {
        self.clients.contains_key(&federation_id)
    }

    // TODO(tvolk131): Replace this function with more granular accessors.
    pub fn borrow_clients(
        &self,
    ) -> &BTreeMap<FederationId, Spanned<fedimint_client::ClientHandleArc>> {
        &self.clients
    }

    pub fn set_next_scid(&self, next_scid: u64) {
        self.next_scid.store(next_scid, Ordering::SeqCst);
    }

    pub fn pop_next_scid(&self) -> Result<u64> {
        let next_scid = self.next_scid.fetch_add(1, Ordering::Relaxed);

        // Check for overflow.
        if next_scid == INITIAL_SCID.wrapping_sub(1) {
            return Err(GatewayError::GatewayConfigurationError(
                "Short channel ID overflow".to_string(),
            ));
        }

        Ok(next_scid)
    }

    /// Retrieves a `ClientHandleArc` for a given `federation_id`.
    pub fn select_client(
        &self,
        federation_id: FederationId,
    ) -> Result<Spanned<fedimint_client::ClientHandleArc>> {
        self.clients
            .get(&federation_id)
            .cloned()
            .ok_or(GatewayError::InvalidMetadata(format!(
                "No federation with id {federation_id}"
            )))
    }

    pub fn get_config_for_federation(
        &self,
        federation_id: FederationId,
    ) -> Result<JsonClientConfig> {
        Ok(self
            .select_client(federation_id)?
            .borrow()
            .with_sync(|client| client.get_config_json()))
    }

    pub fn get_all_federation_configs(&self) -> Vec<(FederationId, JsonClientConfig)> {
        self.clients
            .iter()
            .map(|(federation_id, client)| {
                (
                    *federation_id,
                    client.borrow().with_sync(|client| client.get_config_json()),
                )
            })
            .collect()
    }

    /// Returns the balance of the requested federation that the Gateway is
    /// connected to.
    pub async fn get_balance_for_federation(&self, federation_id: FederationId) -> Result<Amount> {
        Ok(self
            .select_client(federation_id)?
            .value()
            .get_balance()
            .await)
    }

    pub async fn pegout_from_federation(
        &self,
        federation_id: FederationId,
        amount: BitcoinAmountOrAll,
        address: Address<NetworkUnchecked>,
    ) -> Result<Txid> {
        let client = self.select_client(federation_id)?;
        let wallet_module = client.value().get_first_module::<WalletClientModule>();

        // TODO: Fees should probably be passed in as a parameter
        let (amount, fees) = match amount {
            // If the amount is "all", then we need to subtract the fees from
            // the amount we are withdrawing
            BitcoinAmountOrAll::All => {
                let balance =
                    bitcoin::Amount::from_sat(client.value().get_balance().await.msats / 1000);
                let fees = wallet_module
                    .get_withdraw_fees(address.clone(), balance)
                    .await?;
                let withdraw_amount = balance.checked_sub(fees.amount());
                if withdraw_amount.is_none() {
                    return Err(GatewayError::InsufficientFunds);
                }
                (withdraw_amount.unwrap(), fees)
            }
            BitcoinAmountOrAll::Amount(amount) => (
                amount,
                wallet_module
                    .get_withdraw_fees(address.clone(), amount)
                    .await?,
            ),
        };

        let operation_id = wallet_module
            .withdraw(address.clone(), amount, fees, ())
            .await?;
        let mut updates = wallet_module
            .subscribe_withdraw_updates(operation_id)
            .await?
            .into_stream();

        while let Some(update) = updates.next().await {
            match update {
                WithdrawState::Succeeded(txid) => {
                    info!(
                        "Sent {amount} funds to address {}",
                        address.assume_checked()
                    );
                    return Ok(txid);
                }
                WithdrawState::Failed(e) => {
                    return Err(GatewayError::UnexpectedState(e));
                }
                WithdrawState::Created => {}
            }
        }

        Err(GatewayError::UnexpectedState(
            "Ran out of state updates while withdrawing".to_string(),
        ))
    }

    /// Retrieves the `PublicKey` of the Gateway module for a given federation
    /// for LNv2. This is NOT the same as the `gateway_id`, it is different
    /// per-connected federation.
    fn public_key_lnv2(&self, federation_id: &FederationId) -> Option<PublicKey> {
        self.borrow_clients().get(federation_id).map(|client| {
            client
                .value()
                .get_first_module::<GatewayClientModuleV2>()
                .keypair
                .public_key()
        })
    }

    /// Returns payment information that LNv2 clients can use to instruct this
    /// Gateway to pay an invoice or receive a payment.
    pub fn routing_info_lnv2(&self, federation_id: &FederationId) -> Option<RoutingInfo> {
        Some(RoutingInfo {
            public_key: self.public_key_lnv2(federation_id)?,
            send_fee_default: PaymentFee::one_percent(),
            send_fee_minimum: PaymentFee::half_of_one_percent(),
            receive_fee: PaymentFee::half_of_one_percent(),
            expiration_delta_default: 500,
            expiration_delta_minimum: EXPIRATION_DELTA_MINIMUM_V2,
        })
    }

    /// Instructs this gateway to pay a Lightning network invoice via the LNv2
    /// protocol.
    pub async fn send_payment_lnv2(
        &self,
        payload: SendPaymentPayload,
    ) -> anyhow::Result<std::result::Result<[u8; 32], Signature>> {
        self.borrow_clients()
            .get(&payload.federation_id)
            .ok_or(anyhow::anyhow!("Federation client not available"))?
            .value()
            .get_first_module::<GatewayClientModuleV2>()
            .send_payment(payload)
            .await
    }
}
