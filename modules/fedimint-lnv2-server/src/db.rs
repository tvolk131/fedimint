use std::collections::BTreeMap;

use fedimint_core::db::{DbMigrationError, IDatabaseTransactionOpsCoreTyped};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::secp256k1::PublicKey;
use fedimint_core::util::SafeUrl;
use fedimint_core::{OutPoint, PeerId, impl_db_lookup, impl_db_record};
use fedimint_lnv2_common::bolt12::{
    Pending, ReceiveContract, Registration, RegistrationId, Reservation, ReservationId, StockItem,
    StreamedReceive,
};
use fedimint_lnv2_common::contracts::{IncomingContract, OutgoingContract};
use fedimint_lnv2_common::{ContractId, LightningInputV0, LightningOutputV0};
use fedimint_server_core::migration::{
    ModuleHistoryItem, ServerModuleDbMigrationFnContext, ServerModuleDbMigrationFnContextExt,
};
use futures::StreamExt;
use serde::{Deserialize, Serialize};
use strum_macros::EnumIter;
use tpe::DecryptionKeyShare;

use crate::Lightning;

#[repr(u8)]
#[derive(Clone, EnumIter, Debug)]
pub enum DbKeyPrefix {
    BlockCountVote = 0x01,
    UnixTimeVote = 0x02,
    IncomingContract = 0x03,
    IncomingContractOutpoint = 0x04,
    OutgoingContract = 0x05,
    DecryptionKeyShare = 0x06,
    Preimage = 0x07,
    Gateway = 0x08,
    IncomingContractStreamIndex = 0x09,
    IncomingContractStream = 0x10,
    IncomingContractIndex = 0x11,
    Bolt12Registration = 0x20,
    Bolt12RegistrationCount = 0x21,
    Bolt12Handle = 0x22,
    Bolt12Recipient = 0x23,
    Bolt12Expiry = 0x24,
    Bolt12Stock = 0x25,
    Bolt12PaymentHash = 0x26,
    Bolt12Reservation = 0x27,
    Bolt12OfferPending = 0x28,
    Bolt12GatewayPending = 0x29,
    Bolt12GatewayVote = 0x2a,
    Bolt12GatewayDesiredVote = 0x2b,
    Bolt12Contract = 0x2c,
    Bolt12StreamIndex = 0x2d,
    Bolt12Stream = 0x2e,
    Bolt12ContractIndex = 0x2f,
    Bolt12Nonce = 0x30,
    Bolt12NonceCount = 0x31,
}

impl std::fmt::Display for DbKeyPrefix {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

#[derive(Debug, Encodable, Decodable, Serialize)]
pub struct BlockCountVoteKey(pub PeerId);

#[derive(Clone, Debug, Encodable, Decodable)]
pub struct BlockCountVotePrefix;

impl_db_record!(
    key = BlockCountVoteKey,
    value = u64,
    db_prefix = DbKeyPrefix::BlockCountVote,
);

impl_db_lookup!(key = BlockCountVoteKey, query_prefix = BlockCountVotePrefix);

#[derive(Debug, Encodable, Decodable, Serialize)]
pub struct UnixTimeVoteKey(pub PeerId);

#[derive(Clone, Debug, Encodable, Decodable)]
pub struct UnixTimeVotePrefix;

impl_db_record!(
    key = UnixTimeVoteKey,
    value = u64,
    db_prefix = DbKeyPrefix::UnixTimeVote,
);

impl_db_lookup!(key = UnixTimeVoteKey, query_prefix = UnixTimeVotePrefix);

#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub struct IncomingContractKey(pub OutPoint);

#[derive(Clone, Debug, Encodable, Decodable)]
pub struct IncomingContractPrefix;

impl_db_record!(
    key = IncomingContractKey,
    value = IncomingContract,
    db_prefix = DbKeyPrefix::IncomingContract,
    notify_on_modify = true
);

impl_db_lookup!(
    key = IncomingContractKey,
    query_prefix = IncomingContractPrefix
);

#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub struct IncomingContractOutpointKey(pub ContractId);

#[derive(Clone, Debug, Encodable, Decodable)]
pub struct IncomingContractOutpointPrefix;

impl_db_record!(
    key = IncomingContractOutpointKey,
    value = OutPoint,
    db_prefix = DbKeyPrefix::IncomingContractOutpoint,
    notify_on_modify = true
);

impl_db_lookup!(
    key = IncomingContractOutpointKey,
    query_prefix = IncomingContractOutpointPrefix
);

#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub struct OutgoingContractKey(pub OutPoint);

#[derive(Clone, Debug, Encodable, Decodable)]
pub struct OutgoingContractPrefix;

impl_db_record!(
    key = OutgoingContractKey,
    value = OutgoingContract,
    db_prefix = DbKeyPrefix::OutgoingContract,
    notify_on_modify = true
);

impl_db_lookup!(
    key = OutgoingContractKey,
    query_prefix = OutgoingContractPrefix
);

#[derive(Debug, Encodable, Decodable, Serialize)]
pub struct DecryptionKeyShareKey(pub OutPoint);

#[derive(Clone, Debug, Encodable, Decodable)]
pub struct DecryptionKeySharePrefix;

impl_db_record!(
    key = DecryptionKeyShareKey,
    value = DecryptionKeyShare,
    db_prefix = DbKeyPrefix::DecryptionKeyShare,
    notify_on_modify = true
);

impl_db_lookup!(
    key = DecryptionKeyShareKey,
    query_prefix = DecryptionKeySharePrefix
);

#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub struct PreimageKey(pub OutPoint);

#[derive(Debug, Encodable, Decodable)]
pub struct PreimagePrefix;

impl_db_record!(
    key = PreimageKey,
    value = [u8; 32],
    db_prefix = DbKeyPrefix::Preimage,
    notify_on_modify = true
);

impl_db_lookup!(key = PreimageKey, query_prefix = PreimagePrefix);

#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub struct GatewayKey(pub SafeUrl);

#[derive(Debug, Encodable, Decodable)]
pub struct GatewayPrefix;

impl_db_record!(
    key = GatewayKey,
    value = (),
    db_prefix = DbKeyPrefix::Gateway,
);

impl_db_lookup!(key = GatewayKey, query_prefix = GatewayPrefix);

/// Incoming contracts are indexed in three ways:
/// 1) A sequential stream mapping: `stream_index (u64)` -> `IncomingContract`
///    This enables efficient streaming reads using
///    `IncomingContractStreamPrefix(start)`.
/// 2) A global monotonically increasing index: `IncomingContractStreamIndexKey`
///    -> `u64` This stores the next stream index to be assigned and is used to
///    wait for new icoming contracts to arrive.
/// 3) A reverse lookup from `OutPoint` -> `stream_index` (via
///    `IncomingContractIndexKey`) This allows finding a specific incoming
///    contract's stream position by its `OutPoint`, while still supporting
///    sequential reads via the stream prefix. This is used to remove the
///    contract from the stream once it has been spent.
///
/// The combination allows both random access (by `OutPoint`) and ordered
/// iteration over all unspent incoming contracts (by `stream_index`).

#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub struct IncomingContractStreamIndexKey;

impl_db_record!(
    key = IncomingContractStreamIndexKey,
    value = u64,
    db_prefix = DbKeyPrefix::IncomingContractStreamIndex,
    notify_on_modify = true
);

#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub struct IncomingContractStreamKey(pub u64);

#[derive(Debug, Encodable, Decodable)]
pub struct IncomingContractStreamPrefix(pub u64);

impl_db_record!(
    key = IncomingContractStreamKey,
    value = IncomingContract,
    db_prefix = DbKeyPrefix::IncomingContractStream,
);

impl_db_lookup!(
    key = IncomingContractStreamKey,
    query_prefix = IncomingContractStreamPrefix
);

#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub struct IncomingContractIndexKey(pub OutPoint);

#[derive(Debug, Encodable, Decodable)]
pub struct IncomingContractIndexPrefix;

impl_db_record!(
    key = IncomingContractIndexKey,
    value = u64,
    db_prefix = DbKeyPrefix::IncomingContractIndex,
);

impl_db_lookup!(
    key = IncomingContractIndexKey,
    query_prefix = IncomingContractIndexPrefix
);

pub(crate) async fn migrate_to_v1(
    mut ctx: ServerModuleDbMigrationFnContext<'_, Lightning>,
) -> Result<(), DbMigrationError> {
    let mut contracts = BTreeMap::new();
    let mut stream_index = 0;

    let mut stream = ctx.get_typed_module_history_stream().await;

    while let Some(item) = stream.next().await {
        match item {
            ModuleHistoryItem::Output(output, outpoint) => {
                if let Some(LightningOutputV0::Incoming(contract)) = output.maybe_v0_ref() {
                    contracts.insert(outpoint, (stream_index, contract.clone()));
                    stream_index += 1;
                }
            }
            ModuleHistoryItem::Input(input) => {
                if let Some(LightningInputV0::Incoming(outpoint, _)) = input.maybe_v0_ref() {
                    contracts.remove(outpoint);
                }
            }
            ModuleHistoryItem::ConsensusItem(_) => {}
        }
    }

    drop(stream);

    for (outpoint, (index, contract)) in contracts {
        ctx.dbtx()
            .insert_new_entry(&IncomingContractStreamKey(index), &contract)
            .await;

        ctx.dbtx()
            .insert_new_entry(&IncomingContractIndexKey(outpoint), &index)
            .await;
    }

    ctx.dbtx()
        .insert_new_entry(&IncomingContractStreamIndexKey, &stream_index)
        .await;

    Ok(())
}

// Federated BOLT12 receives. See `docs/federated_bolt12.md` for the tables.

#[derive(Debug, Clone, Encodable, Decodable)]
pub struct Bolt12RegistrationKey(pub RegistrationId);

#[derive(Debug, Encodable, Decodable)]
pub struct Bolt12RegistrationPrefix;

impl_db_record!(
    key = Bolt12RegistrationKey,
    value = Registration,
    db_prefix = DbKeyPrefix::Bolt12Registration,
);

impl_db_lookup!(
    key = Bolt12RegistrationKey,
    query_prefix = Bolt12RegistrationPrefix
);

/// Number of live registrations.
#[derive(Debug, Encodable, Decodable)]
pub struct Bolt12RegistrationCountKey;

impl_db_record!(
    key = Bolt12RegistrationCountKey,
    value = u64,
    db_prefix = DbKeyPrefix::Bolt12RegistrationCount,
);

#[derive(Debug, Encodable, Decodable)]
pub struct Bolt12HandleKey(pub [u8; 32]);

impl_db_record!(
    key = Bolt12HandleKey,
    value = RegistrationId,
    db_prefix = DbKeyPrefix::Bolt12Handle,
);

#[derive(Debug, Encodable, Decodable)]
pub struct Bolt12RecipientKey(pub PublicKey);

impl_db_record!(
    key = Bolt12RecipientKey,
    value = RegistrationId,
    db_prefix = DbKeyPrefix::Bolt12Recipient,
);

/// Registrations ordered by expiry, so expired ones can be pruned without a
/// full scan.
#[derive(Debug, Clone, Encodable, Decodable)]
pub struct Bolt12ExpiryKey(pub u64, pub RegistrationId);

#[derive(Debug, Encodable, Decodable)]
pub struct Bolt12ExpiryPrefix;

impl_db_record!(
    key = Bolt12ExpiryKey,
    value = (),
    db_prefix = DbKeyPrefix::Bolt12Expiry,
);

impl_db_lookup!(key = Bolt12ExpiryKey, query_prefix = Bolt12ExpiryPrefix);

/// Unused stock only: a row is removed when a reservation consumes it.
#[derive(Debug, Clone, Encodable, Decodable)]
pub struct Bolt12StockKey(pub RegistrationId, pub u64);

#[derive(Debug, Encodable, Decodable)]
pub struct Bolt12StockRegistrationPrefix(pub RegistrationId);

impl_db_record!(
    key = Bolt12StockKey,
    value = StockItem,
    db_prefix = DbKeyPrefix::Bolt12Stock,
);

impl_db_lookup!(
    key = Bolt12StockKey,
    query_prefix = Bolt12StockRegistrationPrefix
);

/// Payment hashes that are in stock or have ever been reserved. A hash that
/// has appeared in a reservation is never removed.
#[derive(Debug, Encodable, Decodable)]
pub struct Bolt12PaymentHashKey(pub [u8; 32]);

impl_db_record!(
    key = Bolt12PaymentHashKey,
    value = (),
    db_prefix = DbKeyPrefix::Bolt12PaymentHash,
);

/// Unfunded reservations only: funding removes the row.
#[derive(Debug, Encodable, Decodable)]
pub struct Bolt12ReservationKey(pub ReservationId);

impl_db_record!(
    key = Bolt12ReservationKey,
    value = Reservation,
    db_prefix = DbKeyPrefix::Bolt12Reservation,
    notify_on_modify = true
);

#[derive(Debug, Encodable, Decodable)]
pub struct Bolt12OfferPendingKey(pub RegistrationId);

impl_db_record!(
    key = Bolt12OfferPendingKey,
    value = Vec<Pending>,
    db_prefix = DbKeyPrefix::Bolt12OfferPending,
);

#[derive(Debug, Encodable, Decodable)]
pub struct Bolt12GatewayPendingKey(pub PublicKey);

impl_db_record!(
    key = Bolt12GatewayPendingKey,
    value = Vec<Pending>,
    db_prefix = DbKeyPrefix::Bolt12GatewayPending,
);

/// A guardian's latest consensus vote on a gateway.
#[derive(Debug, Clone, Encodable, Decodable)]
pub struct Bolt12GatewayVoteKey(pub PublicKey, pub PeerId);

#[derive(Debug, Encodable, Decodable)]
pub struct Bolt12GatewayVoteGatewayPrefix(pub PublicKey);

impl_db_record!(
    key = Bolt12GatewayVoteKey,
    value = bool,
    db_prefix = DbKeyPrefix::Bolt12GatewayVote,
);

impl_db_lookup!(
    key = Bolt12GatewayVoteKey,
    query_prefix = Bolt12GatewayVoteGatewayPrefix
);

/// The vote this guardian's operator asked for. Local, not consensus state.
#[derive(Debug, Clone, Encodable, Decodable)]
pub struct Bolt12GatewayDesiredVoteKey(pub PublicKey);

#[derive(Debug, Encodable, Decodable)]
pub struct Bolt12GatewayDesiredVotePrefix;

impl_db_record!(
    key = Bolt12GatewayDesiredVoteKey,
    value = bool,
    db_prefix = DbKeyPrefix::Bolt12GatewayDesiredVote,
);

impl_db_lookup!(
    key = Bolt12GatewayDesiredVoteKey,
    query_prefix = Bolt12GatewayDesiredVotePrefix
);

#[derive(Debug, Clone, Encodable, Decodable)]
pub struct Bolt12ContractKey(pub OutPoint);

#[derive(Debug, Encodable, Decodable)]
pub struct Bolt12ContractPrefix;

impl_db_record!(
    key = Bolt12ContractKey,
    value = ReceiveContract,
    db_prefix = DbKeyPrefix::Bolt12Contract,
    notify_on_modify = true
);

impl_db_lookup!(key = Bolt12ContractKey, query_prefix = Bolt12ContractPrefix);

/// Next index of the receive stream; see the incoming contract stream above
/// for the indexing scheme this mirrors.
#[derive(Debug, Encodable, Decodable)]
pub struct Bolt12StreamIndexKey;

impl_db_record!(
    key = Bolt12StreamIndexKey,
    value = u64,
    db_prefix = DbKeyPrefix::Bolt12StreamIndex,
    notify_on_modify = true
);

#[derive(Debug, Clone, Encodable, Decodable)]
pub struct Bolt12StreamKey(pub u64);

#[derive(Debug, Encodable, Decodable)]
pub struct Bolt12StreamPrefix(pub u64);

impl_db_record!(
    key = Bolt12StreamKey,
    value = StreamedReceive,
    db_prefix = DbKeyPrefix::Bolt12Stream,
);

impl_db_lookup!(key = Bolt12StreamKey, query_prefix = Bolt12StreamPrefix);

#[derive(Debug, Encodable, Decodable)]
pub struct Bolt12ContractIndexKey(pub OutPoint);

impl_db_record!(
    key = Bolt12ContractIndexKey,
    value = u64,
    db_prefix = DbKeyPrefix::Bolt12ContractIndex,
);

/// Whether the nonce of a signing attempt has been spent. Local to this
/// guardian, not consensus state.
#[derive(Debug, Encodable, Decodable)]
pub struct Bolt12NonceKey(pub ReservationId, pub [u8; 32]);

impl_db_record!(
    key = Bolt12NonceKey,
    value = bool,
    db_prefix = DbKeyPrefix::Bolt12Nonce,
);

/// Signing attempts this guardian has started for a reservation.
#[derive(Debug, Encodable, Decodable)]
pub struct Bolt12NonceCountKey(pub ReservationId);

impl_db_record!(
    key = Bolt12NonceCountKey,
    value = u16,
    db_prefix = DbKeyPrefix::Bolt12NonceCount,
);
