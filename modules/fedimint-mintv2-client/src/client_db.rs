use std::collections::{BTreeMap, BTreeSet};

use bitcoin_hashes::hash160;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::{impl_db_lookup, impl_db_record};
use fedimint_mintv2_common::Denomination;
use strum::Display;
use strum_macros::EnumIter;

use crate::SpendableNote;
use crate::issuance::NoteIssuanceRequest;

#[repr(u8)]
#[derive(Clone, Display, EnumIter, Debug)]
pub enum DbKeyPrefix {
    Note = 0x20,
    RecoveryState = 0x21,
    FundingReservation = 0x22,
}

#[derive(Debug, Clone, Encodable, Decodable)]
pub struct SpendableNoteKey(pub SpendableNote);

#[derive(Debug, Clone, Encodable, Decodable)]
pub struct SpendableNotePrefix;

#[derive(Debug, Clone, Encodable, Decodable)]
pub struct SpendableNoteAmountPrefix(pub Denomination);

impl_db_record!(
    key = SpendableNoteKey,
    value = (),
    db_prefix = DbKeyPrefix::Note,
);

impl_db_lookup!(key = SpendableNoteKey, query_prefix = SpendableNotePrefix);

impl_db_lookup!(
    key = SpendableNoteKey,
    query_prefix = SpendableNoteAmountPrefix
);

/// Key for storing recovery progress state
#[derive(Debug, Clone, Encodable, Decodable)]
pub struct RecoveryStateKey;

/// Recovery state that can be checkpointed and resumed
#[derive(Debug, Clone, Encodable, Decodable)]
pub struct RecoveryState {
    /// Next item index to download
    pub next_index: u64,
    /// Total items (for progress calculation)
    pub total_items: u64,
    /// Already recovered note requests, keyed by `nonce_hash` (for efficient
    /// removal when inputs are seen)
    pub requests: BTreeMap<hash160::Hash, NoteIssuanceRequest>,
    /// Nonces seen (to detect duplicates)
    pub nonces: BTreeSet<hash160::Hash>,
}

impl_db_record!(
    key = RecoveryStateKey,
    value = RecoveryState,
    db_prefix = DbKeyPrefix::RecoveryState,
);

/// Index of reserved funding outcomes. The input state machine holds the notes
/// and final transaction ID from the same commit that enables submission.
#[derive(Debug, Encodable, Decodable)]
pub(crate) struct FundingReservationKey(pub fedimint_core::core::OperationId);

impl_db_record!(
    key = FundingReservationKey,
    value = crate::reservation::FundingReservation,
    db_prefix = DbKeyPrefix::FundingReservation,
    notify_on_modify = true,
);
