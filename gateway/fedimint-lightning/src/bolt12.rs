//! Types for answering BOLT12 invoice requests for offers that the gateway
//! carries but does not issue, such as federated BOLT12 offers whose invoices
//! the federation's guardians sign.

use std::sync::Arc;

use lightning::offers::invoice::Bolt12Invoice;
use lightning::offers::invoice_request::InvoiceRequest;

use crate::LightningRpcError;

/// How many claimed invoice requests may wait for the gateway at once. The
/// node drops requests beyond that; payers retry.
pub const MAX_QUEUED_BOLT12_REQUESTS: usize = 64;

/// Decides, while the node processes an onion message, whether the gateway
/// answers an invoice request itself. It must not block.
pub type Bolt12RequestFilter = Arc<dyn Fn(&InvoiceRequest) -> bool + Send + Sync>;

type Responder = Box<dyn FnOnce(Bolt12Invoice) -> Result<(), LightningRpcError> + Send>;

/// An invoice request the gateway claimed, with the means to answer it over
/// the payer's reply path.
pub struct Bolt12Request {
    pub invoice_request: InvoiceRequest,
    responder: Responder,
}

impl Bolt12Request {
    pub fn new(
        invoice_request: InvoiceRequest,
        responder: impl FnOnce(Bolt12Invoice) -> Result<(), LightningRpcError> + Send + 'static,
    ) -> Self {
        Self {
            invoice_request,
            responder: Box::new(responder),
        }
    }

    /// Send `invoice` to the payer.
    pub fn respond(self, invoice: Bolt12Invoice) -> Result<(), LightningRpcError> {
        (self.responder)(invoice)
    }
}

impl std::fmt::Debug for Bolt12Request {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Bolt12Request").finish_non_exhaustive()
    }
}

pub(crate) fn unsupported() -> LightningRpcError {
    LightningRpcError::Bolt12Error {
        failure_reason: "This Lightning backend cannot serve externally issued BOLT12 offers"
            .to_string(),
    }
}
