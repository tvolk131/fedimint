//! Correctness of the workloads shared with the opt-in performance harness
//! (`benches/resources`). These run the harness's own assertions, so a case
//! cannot be measured against an expectation that ordinary tests never check.
//! Nothing here measures time.
#[allow(dead_code)]
#[path = "../benches/resources/fixtures.rs"]
mod fixtures;

use fixtures::adversarial::{self, CASES};

/// Every registered fixture: resource preflight, decoding, VM execution,
/// guardian validation and funded core submission.
#[test]
fn registered_fixtures_agree_across_preflight_vm_validation_and_core() {
    fixtures::check_all();
}

// `adversarial::check_all` is split by workload family so libtest can run the
// families in parallel. `every_adversarial_case_belongs_to_one_family` keeps
// the split equal to `CASES`, and `check_family` refuses an empty family.
const LARGE_PROGRAMS: &[&str] = &["constants_", "packed_"];
const SHAPES: &[&str] = &["chain_", "balanced_", "mixed_", "wide_", "hash_blocks_"];
const SIGNATURES_AND_CREATIONS: &[&str] = &["signatures_", "creations_"];
const CONTEXT: &[&str] = &["context_"];
const FAMILIES: &[&[&str]] = &[LARGE_PROGRAMS, SHAPES, SIGNATURES_AND_CREATIONS, CONTEXT];

fn in_family(family: &[&str], name: &str) -> bool {
    family.iter().any(|prefix| name.starts_with(prefix))
}

fn check_family(family: &[&str]) {
    let names: Vec<_> = CASES
        .iter()
        .copied()
        .filter(|name| in_family(family, name))
        .collect();
    assert!(!names.is_empty(), "no adversarial case matches {family:?}");
    adversarial::check_cases(&names);
}

#[test]
fn every_adversarial_case_belongs_to_one_family() {
    for name in CASES {
        let owners = FAMILIES
            .iter()
            .filter(|family| in_family(family, name))
            .count();
        assert_eq!(owners, 1, "{name}: add it to exactly one family test");
    }
}

#[test]
fn large_and_packed_programs_agree_in_submission_and_consensus() {
    check_family(LARGE_PROGRAMS);
}

#[test]
fn chain_balanced_mixed_wide_and_hash_workloads_agree_in_submission_and_consensus() {
    check_family(SHAPES);
}

#[test]
fn signature_and_creation_workloads_agree_in_submission_and_consensus() {
    check_family(SIGNATURES_AND_CREATIONS);
}

#[test]
fn repeated_context_access_and_late_failure_agree_in_submission_and_consensus() {
    check_family(CONTEXT);
}
