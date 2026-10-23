use fedimint_core::db::{DatabaseTransaction, DbMigrationError, IDatabaseTransactionOpsCoreTyped};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::{Amount, OutPoint, PeerId, impl_db_lookup, impl_db_record};
use fedimint_server_core::migration::ServerModuleDbMigrationFnContext;
use fedimint_simplicity_common::{ContractError, ContractOutput};
use futures::StreamExt;
use serde::{Deserialize, Serialize};

use crate::Simplicity;

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

/// Bitcoin locked in all live contracts. Core audits after every consensus
/// item, so this total is kept in step with [`ContractKey`] instead of
/// summing a contract set that anyone can grow.
#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Encodable, Decodable)]
pub struct LiveContractTotalKey;
#[derive(Debug, Encodable, Decodable)]
pub struct LiveContractTotalPrefix;
impl_db_record!(key = LiveContractTotalKey, value = Amount, db_prefix = 0x05);
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

/// Seed [`LiveContractTotalKey`] from contracts stored before it existed.
pub(crate) async fn migrate_to_v1(
    mut ctx: ServerModuleDbMigrationFnContext<'_, Simplicity>,
) -> Result<(), DbMigrationError> {
    let mut dbtx = ctx.dbtx();
    let total = dbtx
        .find_by_prefix(&ContractPrefix)
        .await
        .fold(Some(Amount::ZERO), |total, (_, contract)| async move {
            total?.checked_add(contract.output.amount)
        })
        .await
        .ok_or_else(|| {
            DbMigrationError::Other(
                anyhow::anyhow!("live contract total overflows u64 msats").into(),
            )
        })?;
    dbtx.insert_entry(&LiveContractTotalKey, &total).await;
    Ok(())
}
