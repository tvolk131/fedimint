use fedimint_core::core::{DynInputError, DynOutputError};
use fedimint_metrics::{Encoder as _, TextEncoder};

use super::*;

#[tokio::test]
async fn overlapping_calls_and_cancelled_futures_leave_no_active_work() {
    let registry = Registry::new();
    let metrics = ValidationMetrics::new(&registry);
    let active = metrics.active.with_label_values(&["resolve"]);
    let completed = metrics.start(Phase::Resolve);
    let cancelled = async {
        let _call = metrics.start(Phase::Resolve);
        futures::future::pending::<()>().await;
    };
    let mut cancelled = Box::pin(cancelled);
    assert!(futures::poll!(&mut cancelled).is_pending());
    assert_eq!(active.get(), 2);
    assert_eq!(completed.finish(Ok(7)), Ok(7));
    assert_eq!(active.get(), 1);
    drop(cancelled);
    assert_eq!(active.get(), 0);
    assert_eq!(metrics.calls.with_label_values(&["resolve", "ok"]).get(), 1);
    assert_eq!(
        metrics
            .calls
            .with_label_values(&["resolve", "interrupted"])
            .get(),
        1
    );
    assert_eq!(
        metrics
            .duration
            .with_label_values(&["resolve"])
            .get_sample_count(),
        2
    );
}

#[test]
fn rejection_metrics_preserve_errors_without_exporting_their_payloads() {
    let registry = Registry::new();
    let metrics = ValidationMetrics::new(&registry);
    let secret = "never-export-transaction-or-signature-data".to_owned();
    for (error, outcome) in [
        (
            TransactionError::Input(DynInputError::from_typed(
                123,
                ContractError::UnknownContract,
            )),
            "unknown_contract",
        ),
        (
            TransactionError::Output(DynOutputError::from_typed(
                456,
                ContractOutputError(ContractError::Limit),
            )),
            "resource_limit",
        ),
        (
            TransactionError::InvalidSignature {
                tx: secret.clone(),
                hash: secret.clone(),
                sig: secret.clone(),
                key: secret.clone(),
            },
            "signature",
        ),
        (
            TransactionError::UnsupportedSignatureScheme {
                variant: 987_654_321,
            },
            "signature_scheme",
        ),
    ] {
        let result: Result<(), _> = metrics.start(Phase::Structure).finish(Err(error.clone()));
        assert_eq!(result, Err(error));
        assert_eq!(
            metrics
                .calls
                .with_label_values(&["structure", outcome])
                .get(),
            1
        );
    }
    let mut bytes = vec![];
    TextEncoder::new()
        .encode(&registry.gather(), &mut bytes)
        .unwrap();
    let text = String::from_utf8(bytes).unwrap();
    assert!(!text.contains(&secret));
    assert!(!text.contains("987654321"));
    for family in registry.gather() {
        for metric in family.get_metric() {
            assert!(
                metric
                    .get_label()
                    .iter()
                    .all(|label| matches!(label.name(), "phase" | "outcome"))
            );
        }
    }
    assert_eq!(metrics.active.with_label_values(&["structure"]).get(), 0);
}
