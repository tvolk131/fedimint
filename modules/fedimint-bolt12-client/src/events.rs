use fedimint_core::Amount;
use fedimint_core::core::{ModuleKind, OperationId};
use fedimint_eventlog::{Event, EventKind, EventPersistence};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct ReceivePaymentEvent {
    pub operation_id: OperationId,
    pub amount: Amount,
    pub fee: Amount,
}

impl Event for ReceivePaymentEvent {
    const MODULE: Option<ModuleKind> = Some(fedimint_bolt12_common::KIND);
    const KIND: EventKind = EventKind::from_static("bolt12-receive-payment");
    const PERSISTENCE: EventPersistence = EventPersistence::Persistent;
}
