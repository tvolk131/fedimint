//! Real Mint v2 ecash for client scenarios that must prove funding is reserved,
//! returned or spent exactly. The dummy module only bootstraps issuance; all
//! other funding comes from the mint, with nonzero fees.
use fedimint_client::transaction::TransactionBuilder;
use fedimint_core::core::OperationId;
use fedimint_core::db::IDatabaseTransactionOpsCoreTyped;
use fedimint_mintv2_client::{MintClientInit, SpendableNote};
use futures::StreamExt;

use super::*;

pub(super) async fn builder(stopped: bool) -> ClientBuilder {
    let mut builder = super::builder(stopped).await;
    builder.with_module(MintClientInit);
    builder
}

pub(super) async fn funds(client: &ClientHandle) {
    let input = client
        .get_first_module::<DummyClientModule>()
        .unwrap()
        .create_input(Amount::from_sats(10_000));
    let operation = OperationId::new_random();
    let change = client
        .finalize_and_submit_transaction(
            operation,
            "test ecash issuance",
            |_| (),
            TransactionBuilder::new().with_inputs(input),
        )
        .await
        .unwrap();
    client
        .await_primary_bitcoin_module_outputs(operation, change.into_iter().collect())
        .await
        .unwrap();
}

pub(super) async fn notes(client: &ClientHandle) -> Vec<SpendableNote> {
    let mint = client
        .get_first_instance(&fedimint_mintv2_common::KIND)
        .unwrap();
    client
        .db()
        .with_prefix_module_id(mint)
        .0
        .begin_transaction_nc()
        .await
        .find_by_prefix(&fedimint_mintv2_client::client_db::SpendableNotePrefix)
        .await
        .map(|(key, ())| key.0)
        .collect()
        .await
}
