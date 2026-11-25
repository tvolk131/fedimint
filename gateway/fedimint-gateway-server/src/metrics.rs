#![allow(clippy::disallowed_types)]
// Prometheus registration macros use `HashMap` internally.

use std::sync::LazyLock;

use fedimint_metrics::prometheus::{
    HistogramVec, IntCounterVec, register_histogram_vec_with_registry,
    register_int_counter_vec_with_registry,
};
use fedimint_metrics::{REGISTRY, histogram_opts, opts};

/// Histogram of HTLC handling durations in seconds
pub static HTLC_HANDLING_DURATION_SECONDS: LazyLock<HistogramVec> = LazyLock::new(|| {
    register_histogram_vec_with_registry!(
        histogram_opts!(
            "gateway_htlc_handling_duration_seconds",
            "Duration of HTLC handling in the gateway",
        ),
        &["outcome"],
        REGISTRY
    )
    .expect("metric registration should not fail")
});

/// Histogram of LNv2 HTLC handling attempt durations in seconds
pub static HTLC_LNV2_ATTEMPT_DURATION_SECONDS: LazyLock<HistogramVec> = LazyLock::new(|| {
    register_histogram_vec_with_registry!(
        histogram_opts!(
            "gateway_htlc_lnv2_attempt_duration_seconds",
            "Duration of LNv2 HTLC handling attempts in the gateway",
        ),
        &["outcome"],
        REGISTRY
    )
    .expect("metric registration should not fail")
});

/// Histogram of LNv1 HTLC handling attempt durations in seconds
pub static HTLC_LNV1_ATTEMPT_DURATION_SECONDS: LazyLock<HistogramVec> = LazyLock::new(|| {
    register_histogram_vec_with_registry!(
        histogram_opts!(
            "gateway_htlc_lnv1_attempt_duration_seconds",
            "Duration of LNv1 HTLC handling attempts in the gateway",
        ),
        &["outcome"],
        REGISTRY
    )
    .expect("metric registration should not fail")
});

/// Counter of federated BOLT12 invoice requests handled by the gateway
pub static BOLT12_INVOICE_REQUESTS_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec_with_registry!(
        opts!(
            "gateway_bolt12_invoice_requests_total",
            "Federated BOLT12 invoice requests handled by the gateway by outcome",
        ),
        &["outcome"],
        REGISTRY
    )
    .expect("metric registration should not fail")
});

/// Histogram of federated BOLT12 HTLC handling durations in seconds
pub static BOLT12_HTLC_HANDLING_DURATION_SECONDS: LazyLock<HistogramVec> = LazyLock::new(|| {
    register_histogram_vec_with_registry!(
        histogram_opts!(
            "gateway_bolt12_htlc_handling_duration_seconds",
            "Duration of federated BOLT12 HTLC handling in the gateway by outcome",
        ),
        &["outcome"],
        REGISTRY
    )
    .expect("metric registration should not fail")
});
