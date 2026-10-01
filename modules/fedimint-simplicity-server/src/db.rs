use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::{OutPoint, PeerId, impl_db_lookup, impl_db_record};
use fedimint_simplicity_common::ContractOutput;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, Encodable, Decodable)]
pub struct StoredContract {
    pub output: ContractOutput,
    pub creation_session: u64,
    pub creation_block_count: u64,
}

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
