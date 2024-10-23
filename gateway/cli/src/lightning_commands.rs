use std::time::Duration;

use bitcoin::address::NetworkUnchecked;
use clap::Subcommand;
use fedimint_core::bitcoin_migration::{
    bitcoin32_to_bitcoin30_secp256k1_pubkey, bitcoin32_to_bitcoin30_unchecked_address,
};
use fedimint_core::util::{backoff_util, retry};
use fedimint_core::{Amount, BitcoinAmountOrAll};
use lightning_invoice::Bolt11Invoice;
use ln_gateway::rpc::rpc_client::GatewayRpcClient;
use ln_gateway::rpc::{
    CloseChannelsWithPeerPayload, GetLnOnchainAddressPayload, OpenChannelPayload,
    SyncToChainPayload, WithdrawOnchainPayload,
};

use crate::print_response;

const DEFAULT_WAIT_FOR_CHAIN_SYNC_RETRIES: u32 = 60;
const DEFAULT_WAIT_FOR_CHAIN_SYNC_RETRY_DELAY_SECONDS: u64 = 2;

/// This API is intentionally kept very minimal, as its main purpose is to
/// provide a simple and consistent way to establish liquidity between gateways
/// in a test environment.
#[derive(Subcommand)]
pub enum LightningCommands {
    /// Create an invoice to receive lightning funds to the gateway.
    CreateInvoice {
        #[clap(long)]
        amount_msats: u64,

        #[clap(long, default_value_t = 300)]
        expiry_secs: u32,

        #[clap(long)]
        description: Option<String>,
    },
    /// Pay a lightning invoice as the gateway (i.e. no e-cash exchange).
    PayInvoice {
        invoice: Bolt11Invoice,

        #[clap(long, default_value_t = 144)]
        max_delay: u64,

        #[clap(long)]
        max_fee_msats: Amount,
    },
    /// Get a Bitcoin address from the gateway's lightning node's onchain
    /// wallet.
    GetLnOnchainAddress,
    /// Open a channel with another lightning node.
    OpenChannel {
        /// The public key of the node to open a channel with
        #[clap(long)]
        pubkey: bitcoin::secp256k1::PublicKey,

        #[clap(long)]
        host: String,

        /// The amount to fund the channel with
        #[clap(long)]
        channel_size_sats: u64,

        /// The amount to push to the other side of the channel
        #[clap(long)]
        push_amount_sats: Option<u64>,
    },
    /// Close all channels with a peer, claiming the funds to the lightning
    /// node's on-chain wallet.
    CloseChannelsWithPeer {
        // The public key of the node to close channels with
        #[clap(long)]
        pubkey: bitcoin::secp256k1::PublicKey,
    },
    /// List active channels.
    ListActiveChannels,
    /// Withdraw funds from the lightning node's on-chain wallet to a specified
    /// address.
    WithdrawOnchain {
        /// The address to withdraw funds to.
        #[clap(long)]
        address: bitcoin::Address<NetworkUnchecked>,

        /// The amount to withdraw.
        /// Can be "all" to withdraw all funds, an amount + unit (e.g. "1000
        /// sats"), or a raw amount (e.g. "1000") which is denominated in
        /// millisats.
        #[clap(long)]
        amount: BitcoinAmountOrAll,

        /// The fee rate to use in satoshis per vbyte.
        #[clap(long)]
        fee_rate_sats_per_vbyte: u64,
    },
    /// Wait for the lightning node to be synced with the blockchain.
    WaitForChainSync {
        /// The block height to wait for
        #[clap(long)]
        block_height: u32,

        /// The maximum number of retries
        #[clap(long)]
        max_retries: Option<u32>,

        /// The delay between retries
        #[clap(long)]
        retry_delay_seconds: Option<u64>,
    },
}

impl LightningCommands {
    #![allow(clippy::too_many_lines)]
    pub async fn handle(
        self,
        create_client: impl Fn() -> GatewayRpcClient + Send + Sync,
    ) -> anyhow::Result<()> {
        match self {
            Self::CreateInvoice {
                amount_msats,
                expiry_secs,
                description,
            } => {
                let response = create_client()
                    .create_invoice_for_self(ln_gateway::rpc::CreateInvoiceForSelfPayload {
                        amount_msats,
                        expiry_secs,
                        description,
                    })
                    .await?;
                println!("{response}");
            }
            Self::PayInvoice {
                invoice,
                max_delay,
                max_fee_msats,
            } => {
                let response = create_client()
                    .pay_invoice(ln_gateway::rpc::PayInvoicePayload {
                        invoice,
                        max_delay,
                        max_fee: max_fee_msats,
                    })
                    .await?;
                println!("{response}");
            }
            Self::GetLnOnchainAddress => {
                let response = create_client()
                    .get_ln_onchain_address(GetLnOnchainAddressPayload {})
                    .await?
                    .assume_checked();
                println!("{response}");
            }
            Self::OpenChannel {
                pubkey,
                host,
                channel_size_sats,
                push_amount_sats,
            } => {
                let pubkey = bitcoin32_to_bitcoin30_secp256k1_pubkey(&pubkey);

                let funding_txid = create_client()
                    .open_channel(OpenChannelPayload {
                        pubkey,
                        host,
                        channel_size_sats,
                        push_amount_sats: push_amount_sats.unwrap_or(0),
                    })
                    .await?;
                println!("{funding_txid}");
            }
            Self::CloseChannelsWithPeer { pubkey } => {
                let pubkey = bitcoin32_to_bitcoin30_secp256k1_pubkey(&pubkey);

                let response = create_client()
                    .close_channels_with_peer(CloseChannelsWithPeerPayload { pubkey })
                    .await?;
                print_response(response);
            }
            Self::ListActiveChannels => {
                let response = create_client().list_active_channels().await?;
                print_response(response);
            }
            Self::WithdrawOnchain {
                address,
                amount,
                fee_rate_sats_per_vbyte,
            } => {
                let address = bitcoin32_to_bitcoin30_unchecked_address(&address);

                let response = create_client()
                    .withdraw_onchain(WithdrawOnchainPayload {
                        address,
                        amount,
                        fee_rate_sats_per_vbyte,
                    })
                    .await?;
                println!("{response}");
            }
            Self::WaitForChainSync {
                block_height,
                max_retries,
                retry_delay_seconds,
            } => {
                create_client()
                    .sync_to_chain(SyncToChainPayload { block_height })
                    .await?;

                let retry_duration = Duration::from_secs(
                    retry_delay_seconds.unwrap_or(DEFAULT_WAIT_FOR_CHAIN_SYNC_RETRY_DELAY_SECONDS),
                );

                retry(
                    "Wait for chain sync",
                    backoff_util::custom_backoff(
                        retry_duration,
                        retry_duration,
                        Some(max_retries.unwrap_or(DEFAULT_WAIT_FOR_CHAIN_SYNC_RETRIES) as usize),
                    ),
                    || async {
                        let info = create_client().get_info().await?;
                        if info.block_height.unwrap_or(0) >= block_height && info.synced_to_chain {
                            Ok(())
                        } else {
                            Err(anyhow::anyhow!("Not synced yet"))
                        }
                    },
                )
                .await
                .map_err(|_| anyhow::anyhow!("Timed out waiting for chain sync"))?;
            }
        };

        Ok(())
    }
}
