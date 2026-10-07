//! Outcome index for opt-in funding reservations. Notes and the final txid live
//! in the durable input state machine; no raw-note import API is exposed.
use fedimint_core::TransactionId;
use fedimint_core::core::OperationId;
use fedimint_core::db::{Database, DatabaseTransaction, IDatabaseTransactionOpsCoreTyped};
use fedimint_core::encoding::{Decodable, Encodable};

use crate::client_db::{FundingReservationKey, SpendableNoteKey};
use crate::input::{InputSMCommon, InputSMState};

#[derive(Debug, Clone, PartialEq, Eq, Encodable, Decodable)]
pub(crate) enum FundingReservation {
    AwaitingOutcome,
    Rejected(TransactionId),
    ReleaseRequested(TransactionId),
    Released(TransactionId),
    Complete(TransactionId),
}

/// Waking only permits rechecking the release request. In particular, learning
/// the rejection does not itself authorize restoring any notes.
pub(crate) async fn await_release_progress(
    db: &Database,
    operation: OperationId,
    txid: TransactionId,
) -> Result<(), anyhow::Error> {
    db.wait_key_check(&FundingReservationKey(operation), |record| match record {
        None => Some(Ok(())),
        Some(FundingReservation::AwaitingOutcome) => None,
        Some(FundingReservation::ReleaseRequested(bound)) if bound == txid => None,
        Some(FundingReservation::Rejected(bound) | FundingReservation::Released(bound))
            if bound == txid =>
        {
            Some(Ok(()))
        }
        Some(_) => Some(Err(anyhow::Error::msg(
            "funding reservation was accepted or belongs to another transaction",
        ))),
    })
    .await
    .0
}

/// The caller authenticates permanent invalidity. Mint additionally requires a
/// definitive rejection of the exact transaction that owns these notes.
pub(crate) async fn request_release(
    dbtx: &mut DatabaseTransaction<'_>,
    operation: OperationId,
    txid: TransactionId,
) -> Result<bool, anyhow::Error> {
    let key = FundingReservationKey(operation);
    match dbtx.get_value(&key).await {
        None => Ok(true),
        Some(FundingReservation::AwaitingOutcome) => Ok(false),
        Some(FundingReservation::Rejected(bound)) if bound == txid => {
            dbtx.insert_entry(&key, &FundingReservation::ReleaseRequested(txid))
                .await;
            Ok(false)
        }
        Some(FundingReservation::ReleaseRequested(bound)) if bound == txid => Ok(false),
        Some(FundingReservation::Released(bound)) if bound == txid => Ok(true),
        Some(_) => Err(anyhow::Error::msg(
            "funding reservation was accepted or belongs to another transaction",
        )),
    }
}

pub(crate) async fn record_outcome(
    dbtx: &mut DatabaseTransaction<'_>,
    common: &InputSMCommon,
    accepted: bool,
) -> InputSMState {
    let key = FundingReservationKey(common.operation_id);
    assert_eq!(
        dbtx.get_value(&key).await,
        Some(FundingReservation::AwaitingOutcome)
    );
    let (record, state) = if accepted {
        (
            FundingReservation::Complete(common.txid),
            InputSMState::Success,
        )
    } else {
        (
            FundingReservation::Rejected(common.txid),
            InputSMState::AwaitingRelease,
        )
    };
    dbtx.insert_entry(&key, &record).await;
    state
}

pub(crate) async fn restore_notes(
    dbtx: &mut DatabaseTransaction<'_>,
    common: &InputSMCommon,
    balance: tokio::sync::watch::Sender<()>,
) {
    let key = FundingReservationKey(common.operation_id);
    let record = dbtx.get_value(&key).await;
    if record == Some(FundingReservation::Released(common.txid)) {
        // Never reinsert notes after an already-committed release: another
        // operation may have selected them since then.
        return;
    }
    assert_eq!(
        record,
        Some(FundingReservation::ReleaseRequested(common.txid))
    );
    for note in &common.spendable_notes {
        dbtx.insert_new_entry(&SpendableNoteKey(note.clone()), &())
            .await;
    }
    dbtx.insert_entry(&key, &FundingReservation::Released(common.txid))
        .await;
    dbtx.on_commit(move || balance.send_replace(()));
}

#[cfg(test)]
mod tests;
