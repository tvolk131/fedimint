use std::num::ParseIntError;
use std::str::FromStr;

use bitcoin::hashes::{Hash as _, sha256};
use bitcoin::secp256k1::schnorr::Signature;
use bitcoin::secp256k1::{Keypair, Message, PublicKey, SECP256K1};
use fedimint_connectors::error::ServerError;
use fedimint_core::config::FederationId;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::util::SafeUrl;
use fedimint_core::{Amount, ParseAmountError, apply, async_trait_maybe_send};
use fedimint_ln_common::client::GatewayApi;
use lightning::blinded_path::message::BlindedMessagePath;
use lightning::util::ser::{Readable, Writeable};
use lightning_invoice::RoutingFees;
use reqwest::Method;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::endpoint_constants::BOLT12_INGRESS_ENDPOINT;

#[apply(async_trait_maybe_send!)]
pub trait GatewayConnection: std::fmt::Debug {
    /// How payers reach the gateway for federated BOLT12 offers, or `None`
    /// if it does not serve them for this federation.
    async fn bolt12_ingress(
        &self,
        gateway_api: SafeUrl,
        federation_id: FederationId,
    ) -> Result<Option<Bolt12Ingress>, ServerError>;
}

#[derive(Debug, Clone)]
pub struct RealGatewayConnection {
    pub api: GatewayApi,
}

#[apply(async_trait_maybe_send!)]
impl GatewayConnection for RealGatewayConnection {
    async fn bolt12_ingress(
        &self,
        gateway_api: SafeUrl,
        federation_id: FederationId,
    ) -> Result<Option<Bolt12Ingress>, ServerError> {
        self.api
            .request(
                &gateway_api,
                Method::POST,
                BOLT12_INGRESS_ENDPOINT,
                Some(federation_id),
            )
            .await
    }
}

/// What a wallet needs to list a gateway in a federated BOLT12 offer.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct Bolt12Ingress {
    /// The gateway's blinded onion-message path, hex-encoded.
    pub message_path: String,
    /// The key the gateway reserves invoices with. Only keys the federation
    /// approved may reserve.
    pub gateway_key: PublicKey,
    /// What the gateway keeps from each payment.
    pub receive_fee: PaymentFee,
    /// Schnorr signature by `gateway_key` binding `(federation_id, message_path,
    /// receive_fee)` so an unapproved endpoint cannot spoof an approved key.
    pub signature: Signature,
}

impl Bolt12Ingress {
    fn digest(federation_id: FederationId, message_path: &str, receive_fee: PaymentFee) -> Message {
        let hash: sha256::Hash = (
            "fedimint/bolt12/ingress/v1",
            federation_id,
            message_path.as_bytes().to_vec(),
            receive_fee,
        )
            .consensus_hash();

        Message::from_digest(hash.to_byte_array())
    }

    pub fn new(
        federation_id: FederationId,
        message_path: &BlindedMessagePath,
        gateway_key: &Keypair,
        receive_fee: PaymentFee,
    ) -> Self {
        use bitcoin::hex::DisplayHex as _;

        let message_path = message_path.encode().to_lower_hex_string();
        let signature =
            gateway_key.sign_schnorr(Self::digest(federation_id, &message_path, receive_fee));

        Self {
            message_path,
            gateway_key: gateway_key.public_key(),
            receive_fee,
            signature,
        }
    }

    pub fn verify(&self, federation_id: FederationId) -> bool {
        SECP256K1
            .verify_schnorr(
                &self.signature,
                &Self::digest(federation_id, &self.message_path, self.receive_fee),
                &self.gateway_key.x_only_public_key().0,
            )
            .is_ok()
    }

    pub fn message_path(&self) -> anyhow::Result<BlindedMessagePath> {
        use bitcoin::hex::FromHex as _;

        let bytes = Vec::<u8>::from_hex(&self.message_path)?;
        let mut reader = std::io::Cursor::new(&bytes);
        let path = BlindedMessagePath::read(&mut reader)
            .map_err(|e| anyhow::anyhow!("Invalid message path: {e:?}"))?;

        anyhow::ensure!(
            usize::try_from(reader.position())? == bytes.len(),
            "Trailing message path data"
        );

        Ok(path)
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub struct PaymentFee {
    pub base: Amount,
    pub parts_per_million: u64,
}

impl PaymentFee {
    pub const RECEIVE_FEE_LIMIT: PaymentFee = PaymentFee {
        base: Amount::from_sats(50),
        parts_per_million: 5_000,
    };

    pub const TRANSACTION_FEE_DEFAULT: PaymentFee = PaymentFee {
        base: Amount::from_sats(2),
        parts_per_million: 3_000,
    };

    pub fn is_within(&self, limit: &PaymentFee) -> bool {
        self.base <= limit.base && self.parts_per_million <= limit.parts_per_million
    }

    pub fn checked_add(self, rhs: Self) -> Option<PaymentFee> {
        Some(PaymentFee {
            base: self.base.checked_add(rhs.base)?,
            parts_per_million: self.parts_per_million.checked_add(rhs.parts_per_million)?,
        })
    }

    pub fn add_to(&self, msats: u64) -> Amount {
        Amount::from_msats(msats.saturating_add(self.absolute_fee(msats)))
    }

    pub fn subtract_from(&self, msats: u64) -> Amount {
        Amount::from_msats(msats.saturating_sub(self.absolute_fee(msats)))
    }

    pub fn fee(&self, msats: u64) -> Amount {
        Amount::from_msats(self.absolute_fee(msats))
    }

    fn absolute_fee(&self, msats: u64) -> u64 {
        msats
            .saturating_mul(self.parts_per_million)
            .saturating_div(1_000_000)
            .saturating_add(self.base.msats)
    }
}

#[derive(Debug, Error)]
#[error("Payment fee {0} exceeds the range of RoutingFees")]
pub struct FeeOutOfRangeError(PaymentFee);

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ParsePaymentFeeError {
    #[error("Expected the format <base>,<ppm>")]
    Format,
    #[error("The base fee is not an amount: {0}")]
    Base(#[from] ParseAmountError),
    #[error("The relative fee is not a number of parts per million: {0}")]
    PartsPerMillion(#[from] ParseIntError),
}

impl From<RoutingFees> for PaymentFee {
    fn from(value: RoutingFees) -> Self {
        PaymentFee {
            base: Amount::from_msats(u64::from(value.base_msat)),
            parts_per_million: u64::from(value.proportional_millionths),
        }
    }
}

impl TryFrom<PaymentFee> for RoutingFees {
    type Error = FeeOutOfRangeError;

    fn try_from(value: PaymentFee) -> Result<Self, Self::Error> {
        Ok(RoutingFees {
            base_msat: u32::try_from(value.base.msats).map_err(|_| FeeOutOfRangeError(value))?,
            proportional_millionths: u32::try_from(value.parts_per_million)
                .map_err(|_| FeeOutOfRangeError(value))?,
        })
    }
}

impl std::fmt::Display for PaymentFee {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{},{}", self.base, self.parts_per_million)
    }
}

impl FromStr for PaymentFee {
    type Err = ParsePaymentFeeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (base_str, ppm_str) = s.split_once(',').ok_or(ParsePaymentFeeError::Format)?;

        if ppm_str.contains(',') {
            return Err(ParsePaymentFeeError::Format);
        }

        Ok(PaymentFee {
            base: Amount::from_str(base_str)?,
            parts_per_million: ppm_str.parse::<u64>()?,
        })
    }
}
