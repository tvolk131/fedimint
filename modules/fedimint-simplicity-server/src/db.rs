use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::module::ModuleConsensusVersion;
use fedimint_core::{OutPoint, PeerId, impl_db_lookup, impl_db_record};
pub use fedimint_simplicity_common::StoredContract;
use serde::Serialize;

#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Encodable, Decodable)]
pub struct ContractKey(pub OutPoint);
#[derive(Debug, Encodable, Decodable)]
pub struct ContractPrefix;
impl_db_record!(key = ContractKey, value = StoredContract, db_prefix = 0x01);
impl_db_lookup!(key = ContractKey, query_prefix = ContractPrefix);

#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Encodable, Decodable)]
pub struct BlockVoteKey(pub PeerId);
#[derive(Debug, Encodable, Decodable)]
pub struct BlockVotePrefix;
impl_db_record!(key = BlockVoteKey, value = u64, db_prefix = 0x02);
impl_db_lookup!(key = BlockVoteKey, query_prefix = BlockVotePrefix);

#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Encodable, Decodable)]
pub struct NamespaceKey(pub [u8; 32]);
impl_db_record!(key = NamespaceKey, value = (), db_prefix = 0x03);

#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Encodable, Decodable)]
pub struct AssetKey(pub fedimint_simplicity_common::assets::AssetId);
impl_db_record!(
    key = AssetKey,
    value = fedimint_simplicity_common::assets::AssetRecord,
    db_prefix = 0x04
);

/// Monotone votes are the durable activation state. Missing votes mean the
/// original configuration baseline; no local readiness observations are stored.
#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Encodable, Decodable)]
pub struct VersionVoteKey(pub PeerId);
#[derive(Debug, Encodable, Decodable)]
pub struct VersionVotePrefix;
impl_db_record!(
    key = VersionVoteKey,
    value = ModuleConsensusVersion,
    db_prefix = 0x05
);
impl_db_lookup!(key = VersionVoteKey, query_prefix = VersionVotePrefix);
