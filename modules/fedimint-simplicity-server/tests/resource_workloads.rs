// Share exact adversarial transactions with the optional performance harness.
#[allow(dead_code)]
#[path = "../benches/resources/fixtures.rs"]
mod fixtures;

#[test]
fn repeated_context_access_and_late_failure_agree_in_submission_and_consensus() {
    let names: Vec<_> = fixtures::adversarial::CASES
        .iter()
        .copied()
        .filter(|name| name.starts_with("context_"))
        .collect();
    fixtures::adversarial::check_cases(&names);
}
