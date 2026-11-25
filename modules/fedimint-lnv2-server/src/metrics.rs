#![allow(clippy::disallowed_types)]
// Prometheus registration macros use `HashMap` internally.

use std::sync::LazyLock;

use fedimint_metrics::prometheus::{
    IntCounterVec, IntGauge, register_histogram_vec_with_registry,
    register_int_counter_vec_with_registry, register_int_gauge_with_registry,
};
use fedimint_metrics::{AMOUNTS_BUCKETS_SATS, HistogramVec, REGISTRY, histogram_opts, opts};

pub(crate) static LN_FUNDED_CONTRACT_SATS: LazyLock<HistogramVec> = LazyLock::new(|| {
    register_histogram_vec_with_registry!(
        histogram_opts!(
            "lnv2_funded_contract_sats",
            "Funded (with outgoing or incoming direction) contract amount in sats",
            AMOUNTS_BUCKETS_SATS.clone()
        ),
        &["direction"],
        REGISTRY
    )
    .expect("metric registration should not fail")
});

pub(crate) static LN_OUTGOING_CONTRACT_SETTLED: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec_with_registry!(
        opts!(
            "lnv2_outgoing_contract_settled_total",
            "Settled outgoing contracts by outcome (claim, refund or cancel)"
        ),
        &["outcome"],
        REGISTRY
    )
    .expect("metric registration should not fail")
});

pub(crate) static BOLT12_POOL_ITEMS: LazyLock<IntGauge> = LazyLock::new(|| {
    register_int_gauge_with_registry!(
        opts!(
            "lnv2_bolt12_pool_items",
            "Number of ready federation-generated BOLT12 preimages in the pool"
        ),
        REGISTRY
    )
    .expect("metric registration should not fail")
});

pub(crate) static BOLT12_POOL_RUNS_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec_with_registry!(
        opts!(
            "lnv2_bolt12_pool_runs_total",
            "Federated BOLT12 MPC preimage generation runs by outcome"
        ),
        &["outcome"],
        REGISTRY
    )
    .expect("metric registration should not fail")
});

pub(crate) static BOLT12_POOL_RUN_DURATION_SECONDS: LazyLock<HistogramVec> = LazyLock::new(|| {
    register_histogram_vec_with_registry!(
        histogram_opts!(
            "lnv2_bolt12_pool_run_duration_seconds",
            "Local wall-clock duration of federated BOLT12 MPC generation runs in seconds",
            vec![0.5, 1.0, 2.0, 5.0, 10.0, 30.0, 60.0, 120.0, 300.0]
        ),
        &["outcome"],
        REGISTRY
    )
    .expect("metric registration should not fail")
});

pub(crate) static BOLT12_POOL_BLAME_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec_with_registry!(
        opts!(
            "lnv2_bolt12_pool_blame_total",
            "Federated BOLT12 MPC blame and dispute events by kind"
        ),
        &["kind"],
        REGISTRY
    )
    .expect("metric registration should not fail")
});

pub(crate) static BOLT12_RECEIVES_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec_with_registry!(
        opts!(
            "lnv2_bolt12_receives_total",
            "Federated BOLT12 receive lifecycle events by source (stock, pool) and outcome (reserved, funded, claimed, refunded)"
        ),
        &["source", "outcome"],
        REGISTRY
    )
    .expect("metric registration should not fail")
});
