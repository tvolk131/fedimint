use fedimint_core::core::OperationId;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::{OutPoint, TransactionId, impl_db_lookup, impl_db_record};
use serde::Serialize;

use super::{HistoryEntry, WalletContract};

#[derive(Debug, Clone, Encodable, Decodable, Serialize)]
pub struct IdentityKey;
impl_db_record!(key = IdentityKey, value = [u8; 32], db_prefix = 0x01);

#[derive(Debug, Clone, Encodable, Decodable, Serialize)]
pub struct NextSessionKey;
impl_db_record!(key = NextSessionKey, value = u64, db_prefix = 0x02);

#[derive(Debug, Clone, Encodable, Decodable, Serialize)]
pub struct ContractKey(pub OutPoint);
#[derive(Debug, Encodable, Decodable)]
pub struct ContractPrefix;
impl_db_record!(key = ContractKey, value = WalletContract, db_prefix = 0x03);
impl_db_lookup!(key = ContractKey, query_prefix = ContractPrefix);

#[derive(Debug, Clone, Encodable, Decodable, Serialize)]
pub struct HistoryKey(pub u64, pub u64);
#[derive(Debug, Encodable, Decodable)]
pub struct HistoryPrefix;
impl_db_record!(key = HistoryKey, value = HistoryEntry, db_prefix = 0x04);
impl_db_lookup!(key = HistoryKey, query_prefix = HistoryPrefix);

#[derive(Debug, Clone, Encodable, Decodable, Serialize)]
pub struct ReservationKey(pub OutPoint);
impl_db_record!(key = ReservationKey, value = OperationId, db_prefix = 0x05);

#[derive(Debug, Clone, Encodable, Decodable, Serialize)]
pub struct RecoveryTargetKey;
impl_db_record!(key = RecoveryTargetKey, value = u64, db_prefix = 0x06);

#[derive(Debug, Clone, Encodable, Decodable, Serialize)]
pub struct OpenSessionKey;
impl_db_record!(key = OpenSessionKey, value = (u64, Option<bitcoin::hashes::sha256::Hash>), db_prefix = 0x07);

#[derive(Debug, Clone, Encodable, Decodable, Serialize)]
pub struct ObservedTransactionKey(pub TransactionId);
impl_db_record!(key = ObservedTransactionKey, value = (), db_prefix = 0x08);

#[derive(Debug, Clone, Encodable, Decodable, Serialize)]
pub struct OperationResultKey(pub OperationId);
impl_db_record!(key = OperationResultKey, value = Option<Result<(), String>>, db_prefix = 0x09, notify_on_modify = true);

#[derive(Debug, Clone, Encodable, Decodable, Serialize)]
pub struct IntentKey(pub OperationId);
#[derive(Debug, Encodable, Decodable)]
pub struct IntentPrefix;
impl_db_record!(
    key = IntentKey,
    value = crate::intent::IntentRecord,
    db_prefix = 0x0a,
    notify_on_modify = true
);
impl_db_lookup!(key = IntentKey, query_prefix = IntentPrefix);

#[derive(Debug, Clone, Encodable, Decodable, Serialize)]
pub struct ActiveIntentKey(pub OperationId);
#[derive(Debug, Encodable, Decodable)]
pub struct ActiveIntentPrefix;
impl_db_record!(key = ActiveIntentKey, value = (), db_prefix = 0x0b);
impl_db_lookup!(key = ActiveIntentKey, query_prefix = ActiveIntentPrefix);
