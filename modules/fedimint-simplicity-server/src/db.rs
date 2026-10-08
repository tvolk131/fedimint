use fedimint_core::encoding::{Decodable, Encodable};
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
