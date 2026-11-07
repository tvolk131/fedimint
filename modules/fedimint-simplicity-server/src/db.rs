use fedimint_core::db::{DatabaseTransaction, IDatabaseTransactionOpsCoreTyped};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::module::ModuleConsensusVersion;
use fedimint_core::{Amount, OutPoint, PeerId, impl_db_lookup, impl_db_record};
use fedimint_simplicity_common::ContractError;
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

/// Bitcoin locked in all live contracts. Core audits after every consensus
/// item, so this total is kept in step with [`ContractKey`] instead of
/// summing a contract set that anyone can grow.
#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Encodable, Decodable)]
pub struct LiveContractTotalKey;
#[derive(Debug, Encodable, Decodable)]
pub struct LiveContractTotalPrefix;
impl_db_record!(key = LiveContractTotalKey, value = Amount, db_prefix = 0x06);
impl_db_lookup!(
    key = LiveContractTotalKey,
    query_prefix = LiveContractTotalPrefix
);

/// A fresh module database has no total until its first contract.
pub async fn live_contract_total(dbtx: &mut DatabaseTransaction<'_>) -> Amount {
    dbtx.get_value(&LiveContractTotalKey)
        .await
        .unwrap_or(Amount::ZERO)
}

/// Store a new live contract and add its amount to [`LiveContractTotalKey`].
/// Core checks funding after processing outputs, so an unfunded transaction
/// can overflow the tentative total. Reject it without changing either entry.
pub async fn insert_contract(
    dbtx: &mut DatabaseTransaction<'_>,
    point: OutPoint,
    contract: &StoredContract,
) -> Result<(), ContractError> {
    let total = live_contract_total(dbtx)
        .await
        .checked_add(contract.output.amount)
        .ok_or(ContractError::Limit)?;
    dbtx.insert_new_entry(&ContractKey(point), contract).await;
    dbtx.insert_entry(&LiveContractTotalKey, &total).await;
    Ok(())
}

/// Remove a live contract and subtract its amount from
/// [`LiveContractTotalKey`].
pub async fn remove_contract(
    dbtx: &mut DatabaseTransaction<'_>,
    point: OutPoint,
) -> Option<StoredContract> {
    let contract = dbtx.remove_entry(&ContractKey(point)).await?;
    let total = live_contract_total(dbtx)
        .await
        .checked_sub(contract.output.amount)
        .expect("the live contract total includes every live contract");
    dbtx.insert_entry(&LiveContractTotalKey, &total).await;
    Some(contract)
}
