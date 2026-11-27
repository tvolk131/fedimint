use bitcoin::hashes::sha256;
use fedimint_core::core::ModuleKind;
use fedimint_eventlog::{Event, EventKind, EventPersistence};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct IncomingPaymentSucceeded {
    pub payment_hash: sha256::Hash,
}

impl Event for IncomingPaymentSucceeded {
    const MODULE: Option<ModuleKind> = Some(fedimint_bolt12_common::KIND);
    const KIND: EventKind = EventKind::from_static("bolt12-incoming-payment-succeeded");
    const PERSISTENCE: EventPersistence = EventPersistence::Persistent;
}

#[derive(Serialize, Deserialize, Debug)]
pub struct IncomingPaymentFailed {
    pub payment_hash: sha256::Hash,
    pub error: String,
}

impl Event for IncomingPaymentFailed {
    const MODULE: Option<ModuleKind> = Some(fedimint_bolt12_common::KIND);
    const KIND: EventKind = EventKind::from_static("bolt12-incoming-payment-failed");
    const PERSISTENCE: EventPersistence = EventPersistence::Persistent;
}

#[derive(Serialize, Deserialize, Debug)]
pub struct CompleteLightningPaymentSucceeded {
    pub payment_hash: sha256::Hash,
}

impl Event for CompleteLightningPaymentSucceeded {
    const MODULE: Option<ModuleKind> = Some(fedimint_bolt12_common::KIND);
    const KIND: EventKind = EventKind::from_static("bolt12-complete-lightning-payment-succeeded");
    const PERSISTENCE: EventPersistence = EventPersistence::Persistent;
}
