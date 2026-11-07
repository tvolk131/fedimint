//! Test-only policies standing in for application templates.
//!
//! The core crate ships only the `owner` template. Its generic safety tests
//! still need a descriptor with parameters and a policy with consensus clocks,
//! so they use this small stand-in rather than a production application.
use anyhow::ensure;
use fedimint_core::encoding::{Decodable as _, Encodable as _};
use fedimint_core::secp256k1::XOnlyPublicKey;

use crate::compiler::{U256, Value, ValueConstructible, arguments};
use crate::descriptor::{BuiltinTemplates, ContractDescriptor, ContractTemplates};
// The one place that names where the generic owner program is exported from.
pub(crate) use crate::owner_program;
use crate::{ContractProgram, common};

/// An owner-authorized policy with consensus timelocks and a branch that
/// preserves its policy and state while adding collateral. This is a test copy,
/// not the application template of the same shape.
pub(crate) const ORIGINAL_POLICY: &str = include_str!("fixtures/top_up_or_release.simf");

pub(crate) const ORIGINAL_TEMPLATE: &str = "test-original-policy";

pub(crate) fn word(bytes: [u8; 32]) -> Value {
    Value::u256(U256::from_byte_array(bytes))
}

pub(crate) fn original_descriptor(
    key_nonce: [u8; 32],
    min_session: u64,
    min_block_count: u64,
) -> ContractDescriptor {
    ContractDescriptor {
        template: ORIGINAL_TEMPLATE.to_owned(),
        parameters: (min_session, min_block_count).consensus_encode_to_vec(),
        ..ContractDescriptor::owner(key_nonce)
    }
}

/// The core owner template plus [`ORIGINAL_TEMPLATE`] at version one.
#[derive(Debug)]
pub(crate) struct OriginalTemplates;

impl ContractTemplates for OriginalTemplates {
    fn owns_balance(&self, descriptor: &ContractDescriptor) -> bool {
        (descriptor.template == ORIGINAL_TEMPLATE && descriptor.template_version == 1)
            || BuiltinTemplates.owns_balance(descriptor)
    }

    fn compile(
        &self,
        descriptor: &ContractDescriptor,
        owner: XOnlyPublicKey,
    ) -> anyhow::Result<(u32, ContractProgram)> {
        if descriptor.template != ORIGINAL_TEMPLATE {
            return BuiltinTemplates.compile(descriptor, owner);
        }
        ensure!(
            descriptor.template_version == 1,
            "unsupported template version"
        );
        let (min_session, min_block_count) =
            <(u64, u64)>::consensus_decode_whole(&descriptor.parameters, &Default::default())?;
        Ok((
            common::EXECUTION_VERSION,
            ContractProgram::compile(
                ORIGINAL_POLICY,
                arguments([
                    ("OWNER", word(owner.serialize())),
                    ("MIN_SESSION", Value::u64(min_session)),
                    ("MIN_BLOCK_COUNT", Value::u64(min_block_count)),
                ]),
            )?,
        ))
    }
}
