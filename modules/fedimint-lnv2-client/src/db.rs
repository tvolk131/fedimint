use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::secp256k1::PublicKey;
use fedimint_core::util::SafeUrl;
use fedimint_core::{impl_db_lookup, impl_db_record};
use fedimint_lnv2_common::bolt12::RegistrationId;
use strum::EnumIter;

#[repr(u8)]
#[derive(Clone, EnumIter, Debug)]
pub enum DbKeyPrefix {
    Gateway = 0x41,
    IncomingContractStreamIndex = 0x42,
    Bolt12ReceiveStreamIndex = 0x43,
    Bolt12Offer = 0x44,
    Bolt12NextOfferIndex = 0x45,
    /// Prefixes between 0xb0..=0xcf shall all be considered allocated for
    /// historical and future external use
    ExternalReservedStart = 0xb0,
    /// Prefixes between 0xd0..=0xff shall all be considered allocated for
    /// historical and future internal use
    CoreInternalReservedStart = 0xd0,
    CoreInternalReservedEnd = 0xff,
}

#[derive(Debug, Encodable, Decodable)]
pub struct GatewayKey(pub PublicKey);

impl_db_record!(
    key = GatewayKey,
    value = SafeUrl,
    db_prefix = DbKeyPrefix::Gateway,
);

#[derive(Debug, Encodable, Decodable)]
pub struct IncomingContractStreamIndexKey;

impl_db_record!(
    key = IncomingContractStreamIndexKey,
    value = u64,
    db_prefix = DbKeyPrefix::IncomingContractStreamIndex
);

/// Cursor into the federation's stream of funded BOLT12 receives.
#[derive(Debug, Encodable, Decodable)]
pub struct Bolt12ReceiveStreamIndexKey;

impl_db_record!(
    key = Bolt12ReceiveStreamIndexKey,
    value = u64,
    db_prefix = DbKeyPrefix::Bolt12ReceiveStreamIndex
);

/// An offer this wallet registered, by its derivation index. Everything
/// secret about an offer is derived from that index, so this is a cache the
/// federation can rebuild.
#[derive(Debug, Clone, Encodable, Decodable)]
pub struct Bolt12OfferKey(pub u64);

#[derive(Debug, Encodable, Decodable)]
pub struct Bolt12OfferPrefix;

#[derive(Debug, Clone, Eq, PartialEq, Encodable, Decodable)]
pub struct Bolt12OfferRecord {
    pub registration: RegistrationId,
    pub claim_pk: PublicKey,
    /// The offer string, absent if the offer was rediscovered after a
    /// restore: the federation stores only its hash.
    pub offer: Option<String>,
}

impl_db_record!(
    key = Bolt12OfferKey,
    value = Bolt12OfferRecord,
    db_prefix = DbKeyPrefix::Bolt12Offer
);

impl_db_lookup!(key = Bolt12OfferKey, query_prefix = Bolt12OfferPrefix);

/// The first derivation index no offer of this wallet uses.
#[derive(Debug, Encodable, Decodable)]
pub struct Bolt12NextOfferIndexKey;

impl_db_record!(
    key = Bolt12NextOfferIndexKey,
    value = u64,
    db_prefix = DbKeyPrefix::Bolt12NextOfferIndex
);
