//! Experimental federated BOLT12 receives: reusable offers that keep working
//! while this wallet is offline. See `docs/federated_bolt12.md`.
//!
//! Everything secret about an offer is derived from the module secret and the
//! offer's index, so a wallet restored from its seed can find and claim its
//! receives and extend its stock without any local state.

mod sm;
#[cfg(test)]
mod tests;

use std::collections::BTreeMap;
use std::time::Duration;

use anyhow::{Context, Result, ensure};
use fedimint_client_module::OperationAlreadyExistsError;
use fedimint_client_module::transaction::{ClientOutput, ClientOutputBundle, TransactionBuilder};
use fedimint_core::bitcoin::hashes::sha256;
use fedimint_core::core::OperationId;
use fedimint_core::db::IDatabaseTransactionOpsCoreTyped;
use fedimint_core::module::{Amounts, CommonModuleInit};
use fedimint_core::secp256k1::{Keypair, PublicKey, SECP256K1};
use fedimint_core::util::{FmtCompact as _, SafeUrl};
use fedimint_core::{Amount, runtime};
use fedimint_derive_secret::{ChildId, DerivableSecret};
use fedimint_lnv2_common::bolt12::invoice::{offer_hash, routing_metadata};
use fedimint_lnv2_common::bolt12::{
    AddStock, Bolt12Output, Bolt12Unlock, MAX_STOCK, MAX_STOCK_BATCH, ReceivePolicy, Register,
    Registration, RegistrationId, Source, StockItem, StreamedReceive,
};
use fedimint_lnv2_common::gateway_api::{Bolt12Ingress, PaymentFee};
use fedimint_lnv2_common::{LightningCommonInit, LightningOutput, LightningOutputV0};
use fedimint_logging::LOG_CLIENT_MODULE_LNV2;
use futures::StreamExt;
use lightning::blinded_path::message::BlindedMessagePath;
use lightning::offers::offer::{Offer, OfferBuilder};
use serde::{Deserialize, Serialize};
use tpe::{aggregate_dk_shares, derive_agg_dk};
use tracing::warn;

pub use self::sm::{Bolt12ReceiveSMState, Bolt12ReceiveStateMachine};
use crate::api::LightningFederationApi;
use crate::db::{
    Bolt12NextOfferIndexKey, Bolt12OfferKey, Bolt12OfferPrefix, Bolt12OfferRecord,
    Bolt12ReceiveStreamIndexKey, Bolt12ReceiveStreamRewindGenKey,
};
use crate::{LightningClientModule, LightningClientStateMachines, LightningOperationMeta};

/// Offer indices past the last known one whose claim keys the wallet still
/// watches and probes, so offers created before a restore are found.
const OFFER_GAP_LIMIT: u64 = 20;

const CLAIM_KEY_CHILD: ChildId = ChildId(0);
const STOCK_CHILD: ChildId = ChildId(1);
const HANDLE_CHILD: ChildId = ChildId(2);
const PREIMAGE_CHILD: ChildId = ChildId(0);
const ENCRYPTION_SEED_CHILD: ChildId = ChildId(1);

/// The secrets of one offer, derived from the module's BOLT12 secret.
pub(crate) struct OfferSecrets {
    pub claim_key: Keypair,
    handle: [u8; 32],
    stock: DerivableSecret,
}

impl OfferSecrets {
    pub(crate) fn derive(bolt12_secret: &DerivableSecret, index: u64) -> Self {
        let offer = bolt12_secret.child_key(ChildId(index));

        Self {
            claim_key: offer.child_key(CLAIM_KEY_CHILD).to_secp_key(SECP256K1),
            handle: offer.child_key(HANDLE_CHILD).to_random_bytes(),
            stock: offer.child_key(STOCK_CHILD),
        }
    }

    fn preimage(&self, stock_index: u64) -> [u8; 32] {
        self.stock
            .child_key(ChildId(stock_index))
            .child_key(PREIMAGE_CHILD)
            .to_random_bytes()
    }

    fn encryption_seed(&self, stock_index: u64) -> [u8; 32] {
        self.stock
            .child_key(ChildId(stock_index))
            .child_key(ENCRYPTION_SEED_CHILD)
            .to_random_bytes()
    }
}

/// What a wallet chooses when creating an offer.
#[derive(Debug, Clone)]
pub struct Bolt12OfferParams {
    /// Onion-message paths through which payers reach a gateway. Include
    /// several gateways if available: the offer stops working when every
    /// listed one is gone.
    pub ingress: Vec<BlindedMessagePath>,
    pub description: String,
    /// Unix time after which the offer issues no more invoices.
    pub expires_at: u64,
    /// The most a gateway may keep from one payment.
    pub max_gateway_fee: PaymentFee,
    /// How many payments the offer can receive before the wallet has to come
    /// back online and add more stock.
    pub stock: u64,
    /// Whether, once the stock runs out, payments may use preimages the
    /// federation generated. Each such payment costs the federation's pool
    /// fee when claimed.
    pub allow_pool: bool,
}

/// An offer this wallet registered with the federation.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct Bolt12Offer {
    /// The wallet's derivation index for this offer.
    pub index: u64,
    pub registration: RegistrationId,
    /// The offer string to hand to payers. `None` if the offer was
    /// rediscovered after a restore.
    pub offer: Option<String>,
}

/// Why a setup transaction was submitted, for the operation log.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Bolt12SetupOperationMeta {
    pub registration: RegistrationId,
}

/// A claimed federated BOLT12 receive, for the operation log.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Bolt12ReceiveOperationMeta {
    pub offer_index: u64,
    pub receive: StreamedReceive,
}

impl LightningClientModule {
    /// Ask each of `gateways` how payers reach it for this federation's BOLT12
    /// offers. Gateways that do not answer, do not serve them, or are not
    /// approved by the federation are left out.
    ///
    /// Pass the returned message paths as [`Bolt12OfferParams::ingress`], and
    /// set [`Bolt12OfferParams::max_gateway_fee`] to at least the highest
    /// returned fee so that every listed gateway accepts the offer.
    pub async fn bolt12_gateways(&self, gateways: &[SafeUrl]) -> Vec<Bolt12Ingress> {
        let mut usable = Vec::new();

        for gateway in gateways {
            let Ok(Some(ingress)) = self
                .gateway_conn
                .bolt12_ingress(gateway.clone(), self.federation_id)
                .await
            else {
                continue;
            };

            if !ingress.verify(self.federation_id) || ingress.message_path().is_err() {
                continue;
            }

            if let Ok(true) = self
                .module_api
                .bolt12_gateway_approved(ingress.gateway_key)
                .await
            {
                usable.push(ingress);
            }
        }

        usable
    }

    /// Register a reusable BOLT12 offer and stock it with single-use
    /// preimages. The offer keeps receiving while this wallet is offline until
    /// it expires or its stock runs out.
    pub async fn create_bolt12_offer(
        &self,
        params: Bolt12OfferParams,
    ) -> Result<(Offer, Bolt12Offer)> {
        let bolt12 = self
            .cfg
            .bolt12
            .as_ref()
            .context("This federation does not support federated BOLT12 receives")?;

        ensure!(
            !params.ingress.is_empty(),
            "An offer needs at least one gateway to reach it through"
        );
        ensure!(
            (1..=MAX_STOCK).contains(&params.stock),
            "Stock must be between 1 and {MAX_STOCK}"
        );

        // Peek the next offer index and validate the offer locally before
        // committing the index increment, so local validation errors never burn
        // an offer index and create unnecessary recovery gaps.
        let index = self
            .client_ctx
            .module_db()
            .begin_transaction_nc()
            .await
            .get_value(&Bolt12NextOfferIndexKey)
            .await
            .unwrap_or(0);
        let secrets = OfferSecrets::derive(&self.bolt12_secret, index);

        let mut builder = OfferBuilder::new(bolt12.signing_key)
            .chain(self.cfg.network)
            .metadata(routing_metadata(self.federation_id, secrets.handle))
            .map_err(|e| anyhow::anyhow!("Invalid offer metadata: {e:?}"))?
            .description(params.description)
            .absolute_expiry(Duration::from_secs(params.expires_at));

        for path in params.ingress {
            builder = builder.path(path);
        }

        let offer = builder
            .build()
            .map_err(|e| anyhow::anyhow!("Invalid offer: {e:?}"))?;

        let allocated = self.allocate_bolt12_offer_index().await?;
        let (index, secrets, offer) = if allocated == index {
            (index, secrets, offer)
        } else {
            let secrets = OfferSecrets::derive(&self.bolt12_secret, allocated);
            let mut builder = OfferBuilder::new(bolt12.signing_key)
                .chain(self.cfg.network)
                .metadata(routing_metadata(self.federation_id, secrets.handle))
                .map_err(|e| anyhow::anyhow!("Invalid offer metadata: {e:?}"))?
                .description(offer.description().map_or_default(|d| d.0.to_owned()))
                .absolute_expiry(Duration::from_secs(params.expires_at));
            for path in offer.paths() {
                builder = builder.path(path.clone());
            }
            let offer = builder
                .build()
                .map_err(|e| anyhow::anyhow!("Invalid offer: {e:?}"))?;
            (allocated, secrets, offer)
        };

        let policy = ReceivePolicy {
            handle: secrets.handle,
            claim_pk: secrets.claim_key.public_key(),
            offer_hash: offer_hash(&offer),
            max_gateway_fee: params.max_gateway_fee,
            expires_at: params.expires_at,
            allow_pool: params.allow_pool,
        };
        let registration = policy.id();

        self.submit_bolt12_setup(
            registration,
            Bolt12Output::Register(Register::new(policy, &secrets.claim_key)),
        )
        .await?;

        let record = Bolt12OfferRecord {
            registration,
            claim_pk: secrets.claim_key.public_key(),
            offer: Some(offer.to_string()),
        };

        self.client_ctx
            .module_db()
            .autocommit(
                |dbtx, _| {
                    let record = record.clone();
                    Box::pin(async move {
                        dbtx.insert_entry(&Bolt12OfferKey(index), &record).await;
                        Ok::<_, anyhow::Error>(())
                    })
                },
                Some(16),
            )
            .await
            .map_err(|err| anyhow::anyhow!("failed to persist BOLT12 offer: {err}"))?;

        self.add_bolt12_stock(index, params.stock).await?;

        Ok((
            offer,
            Bolt12Offer {
                index,
                registration,
                offer: record.offer,
            },
        ))
    }

    /// Upload `count` more single-use preimages for an offer. Returns the
    /// offer's registration as the federation then sees it.
    pub async fn add_bolt12_stock(&self, offer_index: u64, count: u64) -> Result<Registration> {
        let secrets = OfferSecrets::derive(&self.bolt12_secret, offer_index);

        let (registration, state) = self
            .module_api
            .bolt12_registration_by_recipient(secrets.claim_key.public_key())
            .await?
            .context("The offer is not registered or has expired")?;

        ensure!(
            state.stock_len.saturating_add(count) <= MAX_STOCK,
            "An offer can hold at most {MAX_STOCK} stock items over its lifetime"
        );

        let mut start = state.stock_len;
        let end = start + count;

        while start < end {
            let batch_end = end.min(start + MAX_STOCK_BATCH as u64);
            let tpe_agg_pk = self.cfg.tpe_agg_pk;

            // Encryption is pairing arithmetic; keep it off the async executor.
            let items = runtime::spawn_blocking({
                let secrets = OfferSecrets::derive(&self.bolt12_secret, offer_index);

                move || {
                    (start..batch_end)
                        .map(|index| {
                            StockItem::new(
                                &tpe_agg_pk,
                                registration,
                                index,
                                &secrets.preimage(index),
                                &secrets.encryption_seed(index),
                            )
                        })
                        .collect::<Vec<_>>()
                }
            })
            .await;

            self.submit_bolt12_setup(
                registration,
                Bolt12Output::AddStock(AddStock::new(
                    registration,
                    start,
                    items,
                    &secrets.claim_key,
                )),
            )
            .await?;

            start = batch_end;
        }

        self.module_api
            .bolt12_registration_by_recipient(secrets.claim_key.public_key())
            .await?
            .map(|(_, state)| state)
            .context("The offer expired while stock was being added")
    }

    /// The federation's Lightning configuration, including the fees and the
    /// signing key of federated BOLT12 receives if they are enabled.
    pub fn lightning_config(&self) -> &fedimint_lnv2_common::config::LightningClientConfig {
        &self.cfg
    }

    /// The offers this wallet knows it registered.
    pub async fn bolt12_offers(&self) -> Vec<Bolt12Offer> {
        self.client_ctx
            .module_db()
            .begin_transaction_nc()
            .await
            .find_by_prefix(&Bolt12OfferPrefix)
            .await
            .map(|(key, record)| Bolt12Offer {
                index: key.0,
                registration: record.registration,
                offer: record.offer,
            })
            .collect()
            .await
    }

    /// The federation's current view of one of our offers, including how much
    /// unused stock it has left.
    pub async fn bolt12_offer_state(&self, offer_index: u64) -> Result<Option<Registration>> {
        let secrets = OfferSecrets::derive(&self.bolt12_secret, offer_index);

        Ok(self
            .module_api
            .bolt12_registration_by_recipient(secrets.claim_key.public_key())
            .await?
            .map(|(_, state)| state))
    }

    async fn allocate_bolt12_offer_index(&self) -> Result<u64> {
        self.client_ctx
            .module_db()
            .autocommit(
                |dbtx, _| {
                    Box::pin(async move {
                        let index = dbtx.get_value(&Bolt12NextOfferIndexKey).await.unwrap_or(0);

                        // Reserved before use: an index whose registration fails is skipped,
                        // never reused with different terms.
                        dbtx.insert_entry(&Bolt12NextOfferIndexKey, &(index + 1))
                            .await;
                        Ok::<_, anyhow::Error>(index)
                    })
                },
                Some(16),
            )
            .await
            .map_err(|err| anyhow::anyhow!("failed to allocate BOLT12 offer index: {err}"))
    }

    /// Submit a registration or stock upload and wait for the federation to
    /// accept it.
    async fn submit_bolt12_setup(
        &self,
        registration: RegistrationId,
        output: Bolt12Output,
    ) -> Result<()> {
        let operation_id = OperationId::new_random();

        let outputs = self
            .client_ctx
            .make_client_outputs(ClientOutputBundle::new_no_sm(vec![ClientOutput {
                output: LightningOutput::V0(LightningOutputV0::Bolt12(output)),
                amounts: Amounts::ZERO,
            }]));

        let range = self
            .client_ctx
            .finalize_and_submit_transaction(
                operation_id,
                LightningCommonInit::KIND.as_str(),
                move |_| {
                    LightningOperationMeta::Bolt12Setup(Bolt12SetupOperationMeta { registration })
                },
                TransactionBuilder::new().with_outputs(outputs),
            )
            .await?;

        self.client_ctx
            .transaction_updates(operation_id)
            .await
            .await_tx_accepted(range.txid())
            .await
            .map_err(|e| anyhow::anyhow!("The federation rejected the transaction: {e}"))
    }

    /// Find offers this wallet registered before its database was lost, by
    /// probing the federation for the claim keys of unused indices. The
    /// federation remembers every claim key ever registered, so offers that
    /// have since expired still mark their index as used and do not open a
    /// gap that would hide later ones.
    pub(crate) async fn recover_bolt12_offers(&self) -> Result<()> {
        let mut next = self
            .client_ctx
            .module_db()
            .begin_transaction_nc()
            .await
            .get_value(&Bolt12NextOfferIndexKey)
            .await
            .unwrap_or(0);

        let mut index = next;

        while index < next + OFFER_GAP_LIMIT {
            let claim_pk = OfferSecrets::derive(&self.bolt12_secret, index)
                .claim_key
                .public_key();

            if let Some((registration, _)) = self
                .module_api
                .bolt12_registration_by_recipient(claim_pk)
                .await?
            {
                record_rescanned_bolt12_offer(
                    self.client_ctx.module_db(),
                    index,
                    Some((registration, claim_pk)),
                    false,
                )
                .await?;

                next = next.max(index + 1);
            } else if self.module_api.bolt12_recipient_used(claim_pk).await? {
                record_rescanned_bolt12_offer(self.client_ctx.module_db(), index, None, false)
                    .await?;

                next = next.max(index + 1);
            }

            index += 1;
        }

        Ok(())
    }

    /// Extended recovery scan up to `max_index` (exclusive) for wallets that
    /// may have skipped more than `OFFER_GAP_LIMIT` offer indices. Resets the
    /// receive stream cursor (and bumps the rewind generation) if any
    /// previously unknown offer is found so the receive loop re-scans and
    /// claims its receives.
    pub async fn rescan_bolt12_offers_up_to(&self, max_index: u64) -> Result<u64> {
        let mut discovered = 0u64;

        for index in 0..max_index {
            let claim_pk = OfferSecrets::derive(&self.bolt12_secret, index)
                .claim_key
                .public_key();

            if let Some((registration, _)) = self
                .module_api
                .bolt12_registration_by_recipient(claim_pk)
                .await?
            {
                let newly_discovered = record_rescanned_bolt12_offer(
                    self.client_ctx.module_db(),
                    index,
                    Some((registration, claim_pk)),
                    false,
                )
                .await?;

                if newly_discovered {
                    discovered += 1;
                }
            } else if self.module_api.bolt12_recipient_used(claim_pk).await? {
                record_rescanned_bolt12_offer(self.client_ctx.module_db(), index, None, true)
                    .await?;
            }
        }

        Ok(discovered)
    }

    /// Claim keys of every offer index in use, plus a gap of unused ones,
    /// together with the offer index and rewind generation snapshot used to
    /// build them. Watching the gap catches receives for offers the federation
    /// has since pruned, which [`Self::recover_bolt12_offers`] cannot find.
    async fn bolt12_claim_keys(&self) -> (BTreeMap<PublicKey, u64>, u64, u64) {
        let mut dbtx = self.client_ctx.module_db().begin_transaction_nc().await;
        let next = dbtx.get_value(&Bolt12NextOfferIndexKey).await.unwrap_or(0);
        let rewind_gen = dbtx
            .get_value(&Bolt12ReceiveStreamRewindGenKey)
            .await
            .unwrap_or(0);

        let keys = (0..next + OFFER_GAP_LIMIT)
            .map(|index| {
                (
                    OfferSecrets::derive(&self.bolt12_secret, index)
                        .claim_key
                        .public_key(),
                    index,
                )
            })
            .collect();

        (keys, next, rewind_gen)
    }

    /// Process the next batch of the federation's receive stream, claiming
    /// the receives that are ours.
    pub(crate) async fn receive_bolt12(&self) {
        // Short-lived transactions on both sides of the long-poll; see
        // `receive_lnurl` for why none may stay open across it.
        let stream_index = self
            .client_ctx
            .module_db()
            .begin_transaction_nc()
            .await
            .get_value(&Bolt12ReceiveStreamIndexKey)
            .await
            .unwrap_or(0);

        let (receives, next_index) = self
            .module_api
            .await_bolt12_receives(stream_index, 128)
            .await;

        let (claim_keys, seen_next, seen_rewind_gen) = self.bolt12_claim_keys().await;
        let mut claims = vec![];

        for receive in receives {
            if let Some(offer_index) = claim_keys.get(&receive.contract.claim_pk)
                && let Some(claim) = self.prepare_bolt12_claim(*offer_index, receive).await
            {
                claims.push(claim);
            }
        }

        // The claims and the cursor move together: a receive is never passed
        // over without its claim operation being stored.
        let mut dbtx = self.client_ctx.module_db().begin_transaction().await;

        for (operation_id, meta, state_machine) in claims {
            // An existing operation means the batch was processed before.
            let _: Result<(), OperationAlreadyExistsError> = self
                .client_ctx
                .manual_operation_start_dbtx(
                    &mut dbtx.to_ref_nc(),
                    operation_id,
                    LightningCommonInit::KIND.as_str(),
                    meta,
                    vec![self.client_ctx.make_dyn_state(state_machine)],
                )
                .await;
        }

        advance_bolt12_stream_cursor(
            &mut dbtx.to_ref_nc(),
            stream_index,
            seen_next,
            seen_rewind_gen,
            next_index,
        )
        .await;

        if let Err(err) = dbtx.commit_tx_result().await {
            warn!(
                target: LOG_CLIENT_MODULE_LNV2,
                err = %err.fmt_compact(),
                "Could not store BOLT12 claims; retrying the batch"
            );
        }
    }

    /// The claim operation for a receive to one of our offers, or `None` if
    /// we cannot or should not claim it.
    async fn prepare_bolt12_claim(
        &self,
        offer_index: u64,
        receive: StreamedReceive,
    ) -> Option<(
        OperationId,
        LightningOperationMeta,
        LightningClientStateMachines,
    )> {
        let Some(unlock) = self.bolt12_unlock(offer_index, &receive).await else {
            warn!(
                target: LOG_CLIENT_MODULE_LNV2,
                outpoint = %receive.outpoint,
                "Ignoring BOLT12 receive whose preimage we cannot release"
            );

            return None;
        };

        let premium = self
            .cfg
            .bolt12
            .as_ref()
            .map_or(Amount::ZERO, |bolt12| bolt12.unlock_premium(&unlock));

        if !self
            .is_bolt12_worth_claiming(receive.contract.amount, premium)
            .await
        {
            warn!(
                target: LOG_CLIENT_MODULE_LNV2,
                amount = %receive.contract.amount,
                "Ignoring BOLT12 receive, its amount does not cover the claim fee"
            );

            return None;
        }

        let operation_id = bolt12_receive_operation_id(&receive);

        let state_machine =
            LightningClientStateMachines::Bolt12Receive(Bolt12ReceiveStateMachine {
                operation_id,
                receive: receive.clone(),
                claim_keypair: OfferSecrets::derive(&self.bolt12_secret, offer_index).claim_key,
                unlock,
                state: Bolt12ReceiveSMState::Pending,
            });

        Some((
            operation_id,
            LightningOperationMeta::Bolt12Receive(Bolt12ReceiveOperationMeta {
                offer_index,
                receive,
            }),
            state_machine,
        ))
    }
}

impl LightningClientModule {
    /// Whether claiming a BOLT12 receive of `amount` with extra input fee
    /// `premium` leaves the wallet with a positive net amount.
    async fn is_bolt12_worth_claiming(&self, amount: Amount, premium: Amount) -> bool {
        let Some(input_fee) = self.cfg.fee_consensus.fee(amount).checked_add(premium) else {
            return false;
        };

        match self
            .client_ctx
            .fee_quote(
                OperationId::new_random(),
                fedimint_client_module::transaction::FeeQuoteRequest {
                    input_amount: Amounts::new_bitcoin(amount),
                    output_amount: Amounts::ZERO,
                    input_fee: Amounts::new_bitcoin(input_fee),
                    output_fee: Amounts::ZERO,
                },
            )
            .await
        {
            Ok(quote) => quote.total().get_bitcoin() < amount,
            Err(_) => false,
        }
    }

    /// The keys that release a receive's preimage, if they do.
    ///
    /// For a stock item the wallet encrypted the preimage itself and derives
    /// the key; for a generated preimage it collects the guardians' shares.
    async fn bolt12_unlock(
        &self,
        offer_index: u64,
        receive: &StreamedReceive,
    ) -> Option<Bolt12Unlock> {
        let tpe_agg_pk = self.cfg.tpe_agg_pk;
        let contract = receive.contract.clone();

        let keys = match contract.source {
            Source::Stock { index } => {
                let seed =
                    OfferSecrets::derive(&self.bolt12_secret, offer_index).encryption_seed(index);

                vec![derive_agg_dk(&tpe_agg_pk, &seed)]
            }
            Source::Pool { .. } => {
                // The receive is funded, so every honest guardian has its
                // shares; skipping it here would skip it for good.
                let shares = self
                    .module_api
                    .bolt12_decryption_shares(
                        receive.outpoint,
                        contract.clone(),
                        self.cfg.tpe_pks.clone(),
                    )
                    .await;

                (0..contract.ciphertexts().len())
                    .map(|i| {
                        aggregate_dk_shares(
                            &shares
                                .iter()
                                .map(|(peer, shares)| (peer.to_usize() as u64, shares[i]))
                                .collect(),
                        )
                    })
                    .collect()
            }
        };

        runtime::spawn_blocking(move || {
            if !contract.verify_agg_decryption_keys(&tpe_agg_pk, &keys) {
                return None;
            }
            let released = contract.release_detailed(&keys, None)?;
            match contract.source {
                Source::Stock { .. } => Bolt12Unlock::new(contract.source, keys),
                Source::Pool { .. } => {
                    Some(Bolt12Unlock::new_pool(keys, Some(released.valid_subset)))
                }
            }
        })
        .await
    }
}

/// The operation that claims a streamed receive. Deterministic, so the same
/// receive never starts two claims.
pub fn bolt12_receive_operation_id(receive: &StreamedReceive) -> OperationId {
    OperationId::from_encodable(&("fedimint/bolt12/receive/v1", receive.outpoint))
}

/// The amount the payer sent for a receive, before the gateway's fee.
pub fn bolt12_invoice_amount(receive: &StreamedReceive) -> Amount {
    receive.contract.amount + receive.contract.gateway_fee
}

/// The hash a payer's proof of payment commits to.
pub fn bolt12_payment_hash(receive: &StreamedReceive) -> sha256::Hash {
    use fedimint_core::bitcoin::hashes::Hash;

    sha256::Hash::from_byte_array(receive.contract.payment_hash)
}

/// Record a recovered/rescanned offer (or pruned used offer index) atomically
/// with a monotonic `Bolt12NextOfferIndexKey` update, cursor rewind to `0`, and
/// monotonic `Bolt12ReceiveStreamRewindGenKey` increment, using bounded
/// conflict retries via `Database::autocommit`. Returns `true` if a new
/// `Bolt12OfferKey` row was inserted.
async fn record_rescanned_bolt12_offer(
    db: &fedimint_core::db::Database,
    index: u64,
    active_offer: Option<(RegistrationId, PublicKey)>,
    rewind_if_pruned: bool,
) -> Result<bool> {
    db.autocommit(
        |dbtx, _| {
            Box::pin(async move {
                let inserted = if let Some((registration, claim_pk)) = active_offer {
                    let existed = dbtx.get_value(&Bolt12OfferKey(index)).await.is_some();
                    if !existed {
                        dbtx.insert_entry(
                            &Bolt12OfferKey(index),
                            &Bolt12OfferRecord {
                                registration,
                                claim_pk,
                                offer: None,
                            },
                        )
                        .await;
                    }
                    !existed
                } else {
                    false
                };

                let current_next = dbtx.get_value(&Bolt12NextOfferIndexKey).await.unwrap_or(0);
                let new_next = current_next.max(index.saturating_add(1));
                let advanced = new_next > current_next;
                if advanced {
                    dbtx.insert_entry(&Bolt12NextOfferIndexKey, &new_next).await;
                }

                let should_rewind =
                    inserted || advanced || (active_offer.is_none() && rewind_if_pruned);
                if should_rewind {
                    // Atomically rewind the receive stream cursor and bump the
                    // monotonic rewind generation so concurrent `receive_bolt12`
                    // batches (even starting at cursor 0) cannot skip newly
                    // discovered or pruned offers.
                    let rewind_gen = dbtx
                        .get_value(&Bolt12ReceiveStreamRewindGenKey)
                        .await
                        .unwrap_or(0);
                    dbtx.insert_entry(&Bolt12ReceiveStreamIndexKey, &0u64).await;
                    dbtx.insert_entry(
                        &Bolt12ReceiveStreamRewindGenKey,
                        &rewind_gen.saturating_add(1),
                    )
                    .await;
                }

                Ok::<_, anyhow::Error>(inserted)
            })
        },
        Some(16),
    )
    .await
    .map_err(|err| anyhow::anyhow!("failed to persist recovered BOLT12 offer: {err}"))
}

/// Advance `Bolt12ReceiveStreamIndexKey` to `next_index` only if neither the
/// cursor, the monotonic rewind generation, nor `Bolt12NextOfferIndexKey`
/// changed since the batch's `claim_keys` snapshot.
///
/// Also writes the observed `Bolt12ReceiveStreamRewindGenKey` and
/// `Bolt12NextOfferIndexKey` into the transaction's write set so
/// value-comparing optimistic DB backends (`MemDatabase`, `redb`) always raise
/// a `WriteConflict` if a concurrent recovery/rescan commits a rewind (even
/// `0 -> 0`) while this transaction is open.
async fn advance_bolt12_stream_cursor(
    dbtx: &mut fedimint_core::db::DatabaseTransaction<'_>,
    stream_index: u64,
    seen_next: u64,
    seen_rewind_gen: u64,
    next_index: u64,
) {
    let current_cursor = dbtx
        .get_value(&Bolt12ReceiveStreamIndexKey)
        .await
        .unwrap_or(0);
    let current_rewind_gen = dbtx
        .get_value(&Bolt12ReceiveStreamRewindGenKey)
        .await
        .unwrap_or(0);
    let current_next = dbtx.get_value(&Bolt12NextOfferIndexKey).await.unwrap_or(0);

    if current_cursor == stream_index
        && current_rewind_gen == seen_rewind_gen
        && current_next == seen_next
    {
        dbtx.insert_entry(&Bolt12ReceiveStreamIndexKey, &next_index)
            .await;
        dbtx.insert_entry(&Bolt12ReceiveStreamRewindGenKey, &current_rewind_gen)
            .await;
        dbtx.insert_entry(&Bolt12NextOfferIndexKey, &current_next)
            .await;
    }
}
