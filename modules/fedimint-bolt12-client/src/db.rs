use fedimint_bolt12_common::bolt12::RegistrationId;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::secp256k1::PublicKey;
use fedimint_core::{impl_db_lookup, impl_db_record};
use strum_macros::EnumIter;

#[repr(u8)]
#[derive(Clone, EnumIter, Debug)]
pub enum DbKeyPrefix {
    Bolt12NextOfferIndex = 0x01,
    Bolt12Offer = 0x02,
    Bolt12ReceiveStreamIndex = 0x03,
    Bolt12ReceiveStreamRewindGen = 0x04,
}

impl std::fmt::Display for DbKeyPrefix {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

/// The next index to use when registering a federated BOLT12 offer.
#[derive(Debug, Encodable, Decodable)]
pub struct Bolt12NextOfferIndexKey;

impl_db_record!(
    key = Bolt12NextOfferIndexKey,
    value = u64,
    db_prefix = DbKeyPrefix::Bolt12NextOfferIndex,
);

/// Local record of a registered federated BOLT12 offer.
#[derive(Debug, Clone, Eq, PartialEq, Encodable, Decodable)]
pub struct Bolt12OfferRecord {
    pub registration: RegistrationId,
    pub claim_pk: PublicKey,
    /// The encoded `lno1...` offer string, if stored locally.
    pub offer: Option<String>,
}

#[derive(Debug, Clone, Encodable, Decodable)]
pub struct Bolt12OfferKey(pub u64);

#[derive(Debug, Encodable, Decodable)]
pub struct Bolt12OfferPrefix;

impl_db_record!(
    key = Bolt12OfferKey,
    value = Bolt12OfferRecord,
    db_prefix = DbKeyPrefix::Bolt12Offer,
);

impl_db_lookup!(key = Bolt12OfferKey, query_prefix = Bolt12OfferPrefix);

/// Cursor into the federation's stream of funded BOLT12 receives.
#[derive(Debug, Encodable, Decodable)]
pub struct Bolt12ReceiveStreamIndexKey;

impl_db_record!(
    key = Bolt12ReceiveStreamIndexKey,
    value = u64,
    db_prefix = DbKeyPrefix::Bolt12ReceiveStreamIndex,
);

/// Monotonic generation bumped whenever an offer recovery rewinds
/// [`Bolt12ReceiveStreamIndexKey`].
#[derive(Debug, Encodable, Decodable)]
pub struct Bolt12ReceiveStreamRewindGenKey;

impl_db_record!(
    key = Bolt12ReceiveStreamRewindGenKey,
    value = u64,
    db_prefix = DbKeyPrefix::Bolt12ReceiveStreamRewindGen,
);
