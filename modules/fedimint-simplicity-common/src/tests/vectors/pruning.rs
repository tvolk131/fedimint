use simplicity::BitMachine;

use super::*;
use crate::compiler::{self, Value, ValueConstructible};
use crate::{ContractError, runtime};

fn program(source: &str, witnesses: compiler::WitnessValues) -> (ContractInput, Environment) {
    let compiled = compiler::compile(source, Default::default()).unwrap();
    let satisfied = compiled.satisfy(witnesses).unwrap();
    let (program, witness) = satisfied.redeem().to_vec_with_witness();
    let mut input = input();
    input.program = program;
    input.witness = witness;
    let mut env = environment();
    env.current.cmr = compiled.commit().cmr().to_byte_array();
    (input, env)
}

#[test]
fn unexecuted_revealed_branch_is_rejected_even_when_execution_succeeds() {
    let (input, env) = program(
        "fn main() { match witness::PATH { true => { assert!(jet::eq_32(42, 42)); }, false => { assert!(jet::eq_64(7, 7)); }, } }",
        compiler::witnesses([("PATH", Value::from(true))]),
    );
    let decoded = runtime::decode_program(&input).unwrap();
    BitMachine::for_program(&decoded)
        .unwrap()
        .exec(&decoded, &env)
        .unwrap();
    assert_eq!(runtime::execute(&input, &env), Err(ContractError::Rejected));
}

#[test]
fn pruned_spend_keeps_commitment_and_charges_its_submitted_representation() {
    for path in [false, true] {
        let (mut input, env) = program(
            "fn main() { match witness::PATH { true => { assert!(jet::eq_32(42, 42)); }, false => { assert!(jet::eq_64(7, 7)); }, } }",
            compiler::witnesses([("PATH", Value::from(path))]),
        );
        let decoded = runtime::decode_program(&input).unwrap();
        let pruned = decoded.prune(&env).unwrap();
        assert_eq!(decoded.cmr(), pruned.cmr());
        assert_ne!(decoded.to_vec_with_witness(), pruned.to_vec_with_witness());
        (input.program, input.witness) = pruned.to_vec_with_witness();
        assert_eq!(runtime::execute(&input, &env), runtime::input_fee(&input));
    }
}

#[test]
fn branch_free_program_requires_no_changes() {
    let (input, env) = program(
        "fn main() { assert!(jet::eq_32(42, 42)); }",
        Default::default(),
    );
    let decoded = runtime::decode_program(&input).unwrap();
    assert_eq!(
        decoded.to_vec_with_witness(),
        decoded.prune(&env).unwrap().to_vec_with_witness()
    );
    assert!(runtime::execute(&input, &env).is_ok());
}

#[test]
fn pruning_commits_to_the_branch_selected_by_the_clock() {
    let (mut input, mut env) = program(
        "fn main() { match jet::lt_64(jet::fm_session_index(), 10) { true => { assert!(jet::eq_32(42, 42)); }, false => { assert!(jet::eq_64(7, 7)); }, } }",
        Default::default(),
    );
    env.session_index = 9;
    let original = runtime::decode_program(&input).unwrap();
    (input.program, input.witness) = original.prune(&env).unwrap().to_vec_with_witness();
    assert!(runtime::execute(&input, &env).is_ok());
    env.session_index = 10;
    assert_eq!(runtime::execute(&input, &env), Err(ContractError::Rejected));
    (input.program, input.witness) = original.prune(&env).unwrap().to_vec_with_witness();
    assert!(runtime::execute(&input, &env).is_ok());
}

#[test]
fn shared_case_may_reveal_both_branches_when_both_are_executed() {
    let source = "fn choose(value: bool) { match value { true => { assert!(jet::eq_32(42, 42)); }, false => { assert!(jet::eq_64(7, 7)); }, } } fn main() { choose(witness::FIRST); choose(witness::SECOND); }";
    for (first, second) in [(false, true), (true, false), (true, true), (false, false)] {
        let (input, env) = program(
            source,
            compiler::witnesses([
                ("FIRST", Value::from(first)),
                ("SECOND", Value::from(second)),
            ]),
        );
        let decoded = runtime::decode_program(&input).unwrap();
        if first != second {
            assert_eq!(
                decoded.to_vec_with_witness(),
                decoded.prune(&env).unwrap().to_vec_with_witness()
            );
            assert!(runtime::execute(&input, &env).is_ok());
        } else {
            assert_eq!(runtime::execute(&input, &env), Err(ContractError::Rejected));
        }
    }
}

#[test]
fn revealing_an_unused_edge_is_invalid_even_if_its_child_executes_elsewhere() {
    // Both case children are the same unit node. CHECK_EXEC alone would pass;
    // CHECK_CASE must still reject the unused edge.
    let (input, env) = program(
        "fn main() { match witness::PATH { true => {}, false => {}, } }",
        compiler::witnesses([("PATH", Value::from(true))]),
    );
    let decoded = runtime::decode_program(&input).unwrap();
    BitMachine::for_program(&decoded)
        .unwrap()
        .exec(&decoded, &env)
        .unwrap();
    assert_eq!(runtime::execute(&input, &env), Err(ContractError::Rejected));
}

pub(super) fn observations() -> serde_json::Value {
    let mut observations = Vec::new();
    for path in [false, true] {
        let (input, env) = program(
            "fn main() { match witness::PATH { true => { assert!(jet::eq_32(42, 42)); }, false => { assert!(jet::eq_64(7, 7)); }, } }",
            compiler::witnesses([("PATH", Value::from(path))]),
        );
        let original = runtime::decode_program(&input).unwrap();
        let pruned = original.prune(&env).unwrap();
        let mut pruned_input = input.clone();
        (pruned_input.program, pruned_input.witness) = pruned.to_vec_with_witness();
        observations.push(serde_json::json!({
            "path": path, "cmr": original.cmr().to_byte_array(),
            "program": pruned_input.program, "witness": pruned_input.witness,
            "unpruned": super::transcript::outcome(runtime::execute(&input, &env)),
            "pruned": super::transcript::outcome(runtime::execute(&pruned_input, &env)),
        }));
    }
    serde_json::json!(observations)
}

#[test]
fn hidden_branch_types_do_not_leak_unused_signature_witnesses() {
    let (mut input, env) = program(
        "fn main() { let signature: Signature = witness::SIG; match witness::PATH { true => { jet::bip_0340_verify((0, jet::fm_sig_hash_all()), signature); }, false => {}, }; assert!(jet::eq_32(witness::KEEP, 42)); }",
        compiler::witnesses([
            ("PATH", Value::from(false)),
            ("SIG", Value::byte_array([0; 64])),
            ("KEEP", Value::u32(42)),
        ]),
    );
    let original = runtime::decode_program(&input).unwrap();
    let pruned = compiler::prune(&original, &env).unwrap();
    assert_eq!(pruned.cmr(), original.cmr());
    (input.program, input.witness) = pruned.to_vec_with_witness();
    assert!(
        input.witness.len() <= 5,
        "unused signature must not be published"
    );
    assert!(runtime::execute(&input, &env).is_ok());
}

#[test]
fn retyped_witnesses_are_canonically_shared_after_pruning() {
    let (mut input, env) = program(
        "fn main() { let first: u64 = witness::FIRST; let second: u32 = witness::SECOND; match witness::PATH { true => { assert!(jet::eq_64(first, 7)); assert!(jet::eq_32(second, 42)); }, false => {}, } }",
        compiler::witnesses([
            ("PATH", Value::from(false)),
            ("FIRST", Value::u64(7)),
            ("SECOND", Value::u32(42)),
        ]),
    );
    let original = runtime::decode_program(&input).unwrap();
    let pruned = compiler::prune(&original, &env).unwrap();
    assert_eq!(pruned.cmr(), original.cmr());
    (input.program, input.witness) = pruned.to_vec_with_witness();
    assert!(input.witness.len() <= 1);
    assert!(runtime::execute(&input, &env).is_ok());
}

#[test]
fn distinct_witness_instances_cannot_union_their_executed_branches() {
    use simplicity::dag::{DagLike, InternalSharing};
    use simplicity::node::Inner;
    let (input, env) = program(
        "fn main() { match witness::FIRST { true => { assert!(jet::eq_64(witness::A, 1)); }, false => { assert!(jet::eq_64(witness::B, 2)); }, }; match witness::SECOND { true => { assert!(jet::eq_64(witness::C, 1)); }, false => { assert!(jet::eq_64(witness::D, 2)); }, } }",
        compiler::witnesses([
            ("FIRST", Value::from(true)),
            ("SECOND", Value::from(false)),
            ("A", Value::u64(1)),
            ("B", Value::u64(3)),
            ("C", Value::u64(3)),
            ("D", Value::u64(2)),
        ]),
    );
    let node = runtime::decode_program(&input).unwrap();
    let cases: Vec<_> = node
        .as_ref()
        .post_order_iter::<InternalSharing>()
        .filter(|data| matches!(data.node.inner(), Inner::Case(..)))
        .map(|data| (data.node.cmr(), data.node.ihr()))
        .collect();
    assert!(
        cases
            .iter()
            .any(|a| cases.iter().any(|b| a.0 == b.0 && a.1 != b.1)),
        "fixture needs CMR-equal but IHR-distinct cases"
    );
    BitMachine::for_program(&node)
        .unwrap()
        .exec(&node, &env)
        .unwrap();
    assert_eq!(runtime::execute(&input, &env), Err(ContractError::Rejected));
}

pub(super) fn seeds() -> Vec<ContractInput> {
    [false, true].into_iter().flat_map(|path| {
        let (input, env) = program(
            "fn main() { match witness::PATH { true => { assert!(jet::eq_32(42, 42)); }, false => { assert!(jet::eq_64(7, 7)); }, } }",
            compiler::witnesses([("PATH", Value::from(path))]),
        );
        let node = runtime::decode_program(&input).unwrap();
        let mut pruned = input.clone();
        (pruned.program, pruned.witness) = compiler::prune(&node, &env).unwrap().to_vec_with_witness();
        [input, pruned]
    }).collect()
}
