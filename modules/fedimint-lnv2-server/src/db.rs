use std::collections::BTreeMap;

use fedimint_core::db::{DbMigrationError, IDatabaseTransactionOpsCoreTyped};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::secp256k1::PublicKey;
use fedimint_core::util::SafeUrl;
use fedimint_core::{OutPoint, PeerId, impl_db_lookup, impl_db_record};
use fedimint_lnv2_common::bolt12::{
    AbandonedRun, Blame, Pending, PoolItem, PoolRun, PoolShare, PoolVerdict, ReceiveContract,
    Registration, RegistrationId, Reservation, ReservationId, StickyCommittee, StockItem,
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
    Bolt12DecryptionShares = 0x32,
    Bolt12PoolItem = 0x33,
    Bolt12PoolNext = 0x34,
    Bolt12PoolPending = 0x35,
    Bolt12PoolRun = 0x36,
    Bolt12PoolRunCount = 0x37,
    Bolt12PoolSubmission = 0x38,
    Bolt12PoolLocalRun = 0x39,
    Bolt12PoolAbandoned = 0x3a,
    Bolt12PoolVerdict = 0x3b,
    Bolt12Blame = 0x3c,
    Bolt12Dispute = 0x3d,
    Bolt12PoolTranscript = 0x3e,
    Bolt12PoolLocalVerdict = 0x3f,
    Bolt12GatewayApprovalCount = 0x40,
    Bolt12PoolStickyCommittee = 0x41,
    Bolt12PoolAbort = 0x42,
    Bolt12PoolRelayEvidence = 0x43,
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

/// A guardian's approval of a gateway. Only approvals are stored.
#[derive(Debug, Clone, Encodable, Decodable)]
pub struct Bolt12GatewayVoteKey(pub PublicKey, pub PeerId);

#[derive(Debug, Encodable, Decodable)]
pub struct Bolt12GatewayVoteGatewayPrefix(pub PublicKey);

#[derive(Debug, Encodable, Decodable)]
pub struct Bolt12GatewayVotePrefix;

impl_db_record!(
    key = Bolt12GatewayVoteKey,
    value = bool,
    db_prefix = DbKeyPrefix::Bolt12GatewayVote,
);

impl_db_lookup!(
    key = Bolt12GatewayVoteKey,
    query_prefix = Bolt12GatewayVoteGatewayPrefix,
    query_prefix = Bolt12GatewayVotePrefix
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

/// This guardian's decryption shares for a funded BOLT12 receive, one per
/// ciphertext of its contract. Written atomically with the funding.
#[derive(Debug, Encodable, Decodable)]
pub struct Bolt12DecryptionSharesKey(pub OutPoint);

impl_db_record!(
    key = Bolt12DecryptionSharesKey,
    value = Vec<DecryptionKeyShare>,
    db_prefix = DbKeyPrefix::Bolt12DecryptionShares,
    notify_on_modify = true
);

/// Generated preimages not yet reserved, by pool index.
#[derive(Debug, Encodable, Decodable)]
pub struct Bolt12PoolItemKey(pub u64);

#[derive(Debug, Encodable, Decodable)]
pub struct Bolt12PoolItemPrefix;

impl_db_record!(
    key = Bolt12PoolItemKey,
    value = PoolItem,
    db_prefix = DbKeyPrefix::Bolt12PoolItem,
);
impl_db_lookup!(key = Bolt12PoolItemKey, query_prefix = Bolt12PoolItemPrefix);

/// The index the next generated preimage is stored at.
#[derive(Debug, Encodable, Decodable)]
pub struct Bolt12PoolNextKey;

impl_db_record!(
    key = Bolt12PoolNextKey,
    value = u64,
    db_prefix = DbKeyPrefix::Bolt12PoolNext,
);

/// Unpaid, unexpired reservations backed by the pool.
#[derive(Debug, Encodable, Decodable)]
pub struct Bolt12PoolPendingKey;

impl_db_record!(
    key = Bolt12PoolPendingKey,
    value = Vec<Pending>,
    db_prefix = DbKeyPrefix::Bolt12PoolPending,
);

/// The generation run in progress, if any.
#[derive(Debug, Encodable, Decodable)]
pub struct Bolt12PoolRunKey;

impl_db_record!(
    key = Bolt12PoolRunKey,
    value = PoolRun,
    db_prefix = DbKeyPrefix::Bolt12PoolRun,
    notify_on_modify = true
);

/// The number the next generation run gets.
#[derive(Debug, Encodable, Decodable)]
pub struct Bolt12PoolRunCountKey;

impl_db_record!(
    key = Bolt12PoolRunCountKey,
    value = u64,
    db_prefix = DbKeyPrefix::Bolt12PoolRunCount,
);

/// A committee member's encrypted shares for the run in progress.
#[derive(Debug, Encodable, Decodable)]
pub struct Bolt12PoolSubmissionKey(pub u64, pub PeerId);

#[derive(Debug, Encodable, Decodable)]
pub struct Bolt12PoolSubmissionRunPrefix(pub u64);

impl_db_record!(
    key = Bolt12PoolSubmissionKey,
    value = Vec<PoolShare>,
    db_prefix = DbKeyPrefix::Bolt12PoolSubmission,
);
impl_db_lookup!(
    key = Bolt12PoolSubmissionKey,
    query_prefix = Bolt12PoolSubmissionRunPrefix
);

/// This guardian's part in a generation run. Local, not consensus state.
#[derive(Debug, Clone, Encodable, Decodable)]
pub struct LocalRun {
    /// All of this guardian's randomness in the run. Kept until the run ends
    /// so an aborted run can be replayed.
    pub seed: [u8; 32],
    /// The encrypted shares to submit once the run succeeded.
    pub submission: Option<Vec<PoolShare>>,
    /// Commitment to this guardian's evidence, once its part has ended.
    pub evidence: Option<fedimint_core::bitcoin::hashes::sha256::Hash>,
}

/// Written before this guardian sends anything in a run, so a restarted
/// guardian never runs it twice.
#[derive(Debug, Encodable, Decodable)]
pub struct Bolt12PoolLocalRunKey(pub u64);

#[derive(Debug, Encodable, Decodable)]
pub struct Bolt12PoolLocalRunPrefix;

impl_db_record!(
    key = Bolt12PoolLocalRunKey,
    value = LocalRun,
    db_prefix = DbKeyPrefix::Bolt12PoolLocalRun,
);
impl_db_lookup!(
    key = Bolt12PoolLocalRunKey,
    query_prefix = Bolt12PoolLocalRunPrefix
);

/// Abandoned runs being judged.
#[derive(Debug, Encodable, Decodable)]
pub struct Bolt12PoolAbandonedKey(pub u64);

#[derive(Debug, Encodable, Decodable)]
pub struct Bolt12PoolAbandonedPrefix;

impl_db_record!(
    key = Bolt12PoolAbandonedKey,
    value = AbandonedRun,
    db_prefix = DbKeyPrefix::Bolt12PoolAbandoned,
);
impl_db_lookup!(
    key = Bolt12PoolAbandonedKey,
    query_prefix = Bolt12PoolAbandonedPrefix
);

/// Guardians' verdicts on an abandoned run.
#[derive(Debug, Encodable, Decodable)]
pub struct Bolt12PoolVerdictKey(pub u64, pub PeerId);

#[derive(Debug, Encodable, Decodable)]
pub struct Bolt12PoolVerdictRunPrefix(pub u64);

impl_db_record!(
    key = Bolt12PoolVerdictKey,
    value = PoolVerdict,
    db_prefix = DbKeyPrefix::Bolt12PoolVerdict,
);
impl_db_lookup!(
    key = Bolt12PoolVerdictKey,
    query_prefix = Bolt12PoolVerdictRunPrefix
);

/// Guardians kept off committees.
#[derive(Debug, Encodable, Decodable)]
pub struct Bolt12BlameKey(pub PeerId);

#[derive(Debug, Encodable, Decodable)]
pub struct Bolt12BlamePrefix;

impl_db_record!(
    key = Bolt12BlameKey,
    value = Blame,
    db_prefix = DbKeyPrefix::Bolt12Blame,
);
impl_db_lookup!(key = Bolt12BlameKey, query_prefix = Bolt12BlamePrefix);

/// Pairs of guardians, lower first, kept off the same committee.
#[derive(Debug, Encodable, Decodable)]
pub struct Bolt12DisputeKey(pub PeerId, pub PeerId);

#[derive(Debug, Encodable, Decodable)]
pub struct Bolt12DisputePrefix;

impl_db_record!(
    key = Bolt12DisputeKey,
    value = Blame,
    db_prefix = DbKeyPrefix::Bolt12Dispute,
);
impl_db_lookup!(key = Bolt12DisputeKey, query_prefix = Bolt12DisputePrefix);

/// A message received in a run, with its sender's signature.
#[derive(Debug, Clone, Eq, PartialEq, Encodable, Decodable)]
pub struct SignedMessage {
    pub message: Vec<u8>,
    pub signature: fedimint_core::secp256k1::schnorr::Signature,
}

/// What this guardian received in one round of a run, by committee position.
/// Local; kept as evidence until the run is over.
#[derive(Debug, Encodable, Decodable)]
pub struct Bolt12PoolTranscriptKey(pub u64, pub u64);

#[derive(Debug, Encodable, Decodable)]
pub struct Bolt12PoolTranscriptRunPrefix(pub u64);

#[derive(Debug, Encodable, Decodable)]
pub struct Bolt12PoolTranscriptPrefix;

impl_db_record!(
    key = Bolt12PoolTranscriptKey,
    value = Vec<Option<SignedMessage>>,
    db_prefix = DbKeyPrefix::Bolt12PoolTranscript,
);
impl_db_lookup!(
    key = Bolt12PoolTranscriptKey,
    query_prefix = Bolt12PoolTranscriptRunPrefix,
    query_prefix = Bolt12PoolTranscriptPrefix
);

/// This guardian's finding about an abandoned run, until consensus has it.
#[derive(Debug, Encodable, Decodable)]
pub struct Bolt12PoolLocalVerdictKey(pub u64);

#[derive(Debug, Encodable, Decodable)]
pub struct Bolt12PoolLocalVerdictPrefix;

impl_db_record!(
    key = Bolt12PoolLocalVerdictKey,
    value = PoolVerdict,
    db_prefix = DbKeyPrefix::Bolt12PoolLocalVerdict,
);
impl_db_lookup!(
    key = Bolt12PoolLocalVerdictKey,
    query_prefix = Bolt12PoolLocalVerdictPrefix
);

/// How many gateways each guardian currently approves.
#[derive(Debug, Encodable, Decodable)]
pub struct Bolt12GatewayApprovalCountKey(pub PeerId);

impl_db_record!(
    key = Bolt12GatewayApprovalCountKey,
    value = u64,
    db_prefix = DbKeyPrefix::Bolt12GatewayApprovalCount,
);

/// Proven-good committee reused across consecutive generation runs.
#[derive(Debug, Encodable, Decodable)]
pub struct Bolt12PoolStickyCommitteeKey;

impl_db_record!(
    key = Bolt12PoolStickyCommitteeKey,
    value = StickyCommittee,
    db_prefix = DbKeyPrefix::Bolt12PoolStickyCommittee,
);

/// A committee member's report that its local execution of a run aborted.
#[derive(Debug, Encodable, Decodable)]
pub struct Bolt12PoolAbortKey(pub u64, pub PeerId);

#[derive(Debug, Encodable, Decodable)]
pub struct Bolt12PoolAbortRunPrefix(pub u64);

impl_db_record!(
    key = Bolt12PoolAbortKey,
    value = (),
    db_prefix = DbKeyPrefix::Bolt12PoolAbort,
);
impl_db_lookup!(
    key = Bolt12PoolAbortKey,
    query_prefix = Bolt12PoolAbortRunPrefix
);

/// An envelope-signed MPC packet recorded as local evidence so judges can
/// verify it against the sender's revealed seed.
#[derive(Debug, Clone, Eq, PartialEq, Encodable, Decodable)]
pub struct BadPacket {
    pub sender: PeerId,
    pub round: u64,
    pub chunk: u32,
    pub chunks: u32,
    pub ephemeral_pk: PublicKey,
    pub ciphertext: Vec<u8>,
    pub envelope_sig: fedimint_core::secp256k1::schnorr::Signature,
}

/// Cryptographically verifiable transport misbehavior by a sender, saved as
/// local evidence so judges can convict the sender against its revealed seed.
#[derive(Debug, Clone, Eq, PartialEq, Encodable, Decodable)]
pub enum TransportFault {
    /// A single envelope-signed packet that failed ephemeral-key matching,
    /// AEAD decryption, chunk bounds, or (for single-chunk messages) inner
    /// signature verification.
    BadPacket(BadPacket),
    /// Two envelope-signed packets from the same sender for the same
    /// `(run, recipient, round)` declaring different total `chunks` counts.
    ChunkCountConflict(BadPacket, BadPacket),
    /// A complete set of envelope-signed chunks (`0..chunks`) whose decrypted
    /// concatenation failed inner signature verification.
    BadMultiChunk(Vec<BadPacket>),
}

impl TransportFault {
    #[must_use]
    pub fn sender(&self) -> Option<PeerId> {
        match self {
            Self::BadPacket(packet) | Self::ChunkCountConflict(packet, _) => Some(packet.sender),
            Self::BadMultiChunk(packets) => packets.first().map(|packet| packet.sender),
        }
    }

    #[must_use]
    pub fn ciphertext_bytes(&self) -> usize {
        match self {
            Self::BadPacket(packet) => packet.ciphertext.len(),
            Self::ChunkCountConflict(a, b) => a.ciphertext.len().saturating_add(b.ciphertext.len()),
            Self::BadMultiChunk(packets) => packets.iter().fold(0usize, |acc, packet| {
                acc.saturating_add(packet.ciphertext.len())
            }),
        }
    }

    #[must_use]
    pub fn max_ciphertext_len(&self) -> usize {
        match self {
            Self::BadPacket(packet) => packet.ciphertext.len(),
            Self::ChunkCountConflict(a, b) => a.ciphertext.len().max(b.ciphertext.len()),
            Self::BadMultiChunk(packets) => packets
                .iter()
                .map(|packet| packet.ciphertext.len())
                .max()
                .unwrap_or(0),
        }
    }
}

/// Local relay evidence collected during a run: failed relay fetches witnessed
/// for other peers, plus verifiable transport faults from senders.
#[derive(Debug, Clone, Default, Eq, PartialEq, Encodable, Decodable)]
pub struct RelayEvidence {
    /// `(sender, recipient, round)` triples where this guardian tried to relay
    /// `sender`'s packet to `recipient` and `sender` failed to serve valid
    /// signed chunks.
    pub relay_missing: Vec<(PeerId, PeerId, u64)>,
    /// Verifiable transport faults observed from senders addressed to this
    /// guardian (at most one per sender).
    pub faults: Vec<TransportFault>,
}

/// Local relay evidence for a generation run.
#[derive(Debug, Encodable, Decodable)]
pub struct Bolt12PoolRelayEvidenceKey(pub u64);

#[derive(Debug, Encodable, Decodable)]
pub struct Bolt12PoolRelayEvidencePrefix;

impl_db_record!(
    key = Bolt12PoolRelayEvidenceKey,
    value = RelayEvidence,
    db_prefix = DbKeyPrefix::Bolt12PoolRelayEvidence,
);
impl_db_lookup!(
    key = Bolt12PoolRelayEvidenceKey,
    query_prefix = Bolt12PoolRelayEvidencePrefix
);
