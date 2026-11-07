use fedimint_core::secp256k1::XOnlyPublicKey;

use crate::ContractProgram;
use crate::compiler::{U256, Value, ValueConstructible, arguments};

pub fn owner_program(owner: XOnlyPublicKey) -> anyhow::Result<ContractProgram> {
    ContractProgram::compile(
        include_str!("../contracts/asset_owner.simf"),
        arguments([(
            "OWNER",
            Value::u256(U256::from_byte_array(owner.serialize())),
        )]),
    )
}
