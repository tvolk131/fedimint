//! Observations of module hook invocations, not committed transactions. Both
//! admission and consensus invoke these hooks; neither decisions nor fees use
//! metrics. Labels are fixed categories, never transaction or wallet data.
#![allow(clippy::disallowed_types)]
// Prometheus descriptor macros use `HashMap` internally.

use std::sync::LazyLock;
use std::time::Instant;

use fedimint_core::transaction::TransactionError;
use fedimint_metrics::prometheus::{IntGauge, IntGaugeVec, Registry};
use fedimint_metrics::{Histogram, HistogramVec, IntCounterVec, REGISTRY, histogram_opts, opts};
use fedimint_simplicity_common::{ContractError, ContractOutputError};

pub(crate) static VALIDATION: LazyLock<ValidationMetrics> =
    LazyLock::new(|| ValidationMetrics::new(&REGISTRY));

#[derive(Clone, Copy)]
pub(crate) enum Phase {
    Structure,
    Resolve,
    Prepare,
    Validate,
}

impl Phase {
    fn label(self) -> &'static str {
        match self {
            Self::Structure => "structure",
            Self::Resolve => "resolve",
            Self::Prepare => "prepare",
            Self::Validate => "validate",
        }
    }
}

pub(crate) struct ValidationMetrics {
    duration: HistogramVec,
    calls: IntCounterVec,
    active: IntGaugeVec,
}

impl ValidationMetrics {
    fn new(registry: &Registry) -> Self {
        let duration = HistogramVec::new(
            histogram_opts!(
                "simplicity_validation_seconds",
                "Module validation hook wall time, including interrupted calls",
                vec![0.000_01, 0.000_1, 0.001, 0.01, 0.1, 1.0, 10.0]
            ),
            &["phase"],
        )
        .expect("valid fixed histogram descriptor");
        let calls = IntCounterVec::new(
            opts!(
                "simplicity_validation_calls_total",
                "Finished module hook calls by outcome; ok does not mean transaction acceptance"
            ),
            &["phase", "outcome"],
        )
        .expect("valid fixed counter descriptor");
        let active = IntGaugeVec::new(
            opts!(
                "simplicity_validation_active",
                "Module validation hook calls in progress, not queued requests"
            ),
            &["phase"],
        )
        .expect("valid fixed gauge descriptor");
        registry
            .register(Box::new(duration.clone()))
            .expect("unique Simplicity duration metric");
        registry
            .register(Box::new(calls.clone()))
            .expect("unique Simplicity outcome metric");
        registry
            .register(Box::new(active.clone()))
            .expect("unique Simplicity active metric");
        Self {
            duration,
            calls,
            active,
        }
    }

    pub(crate) fn start(&self, phase: Phase) -> ValidationCall {
        let phase = phase.label();
        let active = self.active.with_label_values(&[phase]);
        active.inc();
        ValidationCall {
            started: Instant::now(),
            duration: self.duration.with_label_values(&[phase]),
            calls: self.calls.clone(),
            active,
            phase,
            outcome: "interrupted",
        }
    }
}

pub(crate) struct ValidationCall {
    started: Instant,
    duration: Histogram,
    calls: IntCounterVec,
    active: IntGauge,
    phase: &'static str,
    outcome: &'static str,
}

impl ValidationCall {
    pub(crate) fn finish<T>(
        mut self,
        result: Result<T, TransactionError>,
    ) -> Result<T, TransactionError> {
        self.outcome = result.as_ref().err().map_or("ok", rejection);
        result
    }
}

impl Drop for ValidationCall {
    fn drop(&mut self) {
        self.duration
            .observe(Instant::now().duration_since(self.started).as_secs_f64());
        self.calls
            .with_label_values(&[self.phase, self.outcome])
            .inc();
        self.active.dec();
    }
}

fn rejection(error: &TransactionError) -> &'static str {
    let contract = match error {
        TransactionError::Input(error) => error.as_any().downcast_ref::<ContractError>(),
        TransactionError::Output(error) => error
            .as_any()
            .downcast_ref::<ContractOutputError>()
            .map(|error| &error.0),
        TransactionError::InvalidSignature { .. } => return "signature",
        TransactionError::UnsupportedSignatureScheme { .. } => return "signature_scheme",
        TransactionError::InvalidWitnessLength => return "signature_count",
        TransactionError::UnbalancedTransaction { .. } => return "unbalanced",
    };
    match contract {
        Some(ContractError::MissingContext) => "missing_context",
        Some(ContractError::Version) => "version",
        Some(ContractError::UnknownContract) => "unknown_contract",
        Some(ContractError::DuplicateOutput) => "duplicate_output",
        Some(ContractError::Context) => "context",
        Some(ContractError::Limit) => "resource_limit",
        Some(ContractError::Program) => "program",
        Some(ContractError::Commitment) => "commitment",
        Some(ContractError::Rejected) => "program_rejected",
        Some(ContractError::Assets) => "assets",
        Some(ContractError::NamespaceUsed) => "namespace_used",
        Some(ContractError::CreationSignature) => "creation_signature",
        None => "other_module",
    }
}

#[cfg(test)]
mod tests;
