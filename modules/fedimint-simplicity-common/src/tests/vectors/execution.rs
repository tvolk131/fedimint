use simplicity::Cost;

use super::*;
use crate::{ContractError, runtime};

#[test]
fn literal_programs_pin_cmr_resource_bounds_fees_and_execution_versions() {
    for vector in fixtures()["programs"].as_array().unwrap() {
        let mut input = input();
        input.program = bytes(vector["program"].as_str().unwrap());
        input.witness = bytes(vector["witness"].as_str().unwrap());
        let cmr: [u8; 32] = bytes(vector["cmr"].as_str().unwrap()).try_into().unwrap();
        let program = runtime::decode_program(&input).unwrap();
        assert_eq!(program.cmr().to_byte_array(), cmr, "{}", vector["name"]);
        assert_eq!(
            program.bounds().cost,
            Cost::from_milliweight(vector["cost"].as_u64().unwrap() as u32)
        );
        assert_eq!(
            program.bounds().extra_cells,
            vector["cells"].as_u64().unwrap() as usize
        );
        assert_eq!(
            program.bounds().extra_frames,
            vector["frames"].as_u64().unwrap() as usize
        );
        let mut env = environment();
        env.current.cmr = cmr;
        assert_eq!(
            runtime::execute(&input, &env).unwrap().msats,
            vector["fee"].as_u64().unwrap()
        );
        env.current.version = 0;
        if vector["name"] == "issuance" {
            assert_eq!(runtime::execute(&input, &env), Err(ContractError::Version));
        } else {
            assert!(runtime::execute(&input, &env).is_ok());
        }
        env.current.version = 1;
        env.current.cmr[0] ^= 1;
        assert_eq!(
            runtime::execute(&input, &env),
            Err(ContractError::Commitment)
        );
        input.witness.push(0); // Extra witness bytes are never ignored.
        assert_eq!(
            runtime::decode_program(&input).unwrap_err(),
            ContractError::Program
        );
    }
}
