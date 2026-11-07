use std::sync::Arc;

use super::*;
use crate::{ContractError, compiler, runtime};

#[test]
fn action_outputs_cannot_satisfy_zero_amount_or_state_contract_checks() {
    for source in [
        "fn main() { assert!(jet::eq_64(jet::fm_output_amount(0), 0)); }",
        "fn main() { assert!(jet::eq_256(jet::fm_output_state(0), 0)); }",
    ] {
        let program = compiler::compile(source, Default::default()).unwrap();
        let satisfied = program.satisfy(Default::default()).unwrap();
        let mut input = input();
        (input.program, input.witness) = satisfied.redeem().to_vec_with_witness();
        for version in [0, 1] {
            let mut env = environment();
            env.current.version = version;
            env.current.cmr = program.commit().cmr().to_byte_array();
            let output = Arc::make_mut(&mut env.outputs)[0]
                .contract
                .as_mut()
                .unwrap();
            output.amount = Amount::ZERO;
            output.state = [0; 32];
            assert!(
                runtime::execute(&input, &env).is_ok(),
                "v{version} {source}"
            );
            Arc::make_mut(&mut env.outputs)[0].contract =
                Some(ContractOutput::action_output(Default::default()));
            assert_eq!(
                runtime::execute(&input, &env),
                Err(ContractError::Rejected),
                "v{version} {source}"
            );
        }
    }
}
