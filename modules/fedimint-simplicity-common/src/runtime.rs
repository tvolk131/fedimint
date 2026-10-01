use std::sync::Arc;

use fedimint_core::Amount;
use fedimint_core::core::ModuleInstanceId;
use simplicity::dag::{DagLike, InternalSharing};
use simplicity::{BitIter, BitMachine, Cost, RedeemNode};

use crate::jet::FedimintJet;
use crate::{ContractError, ContractInput, ContractOutput, MAX_PROGRAM_BYTES, MAX_WITNESS_BYTES};

#[derive(Debug, Clone)]
pub struct EnvironmentOutput {
    pub module_id: ModuleInstanceId,
    pub hash: [u8; 32],
    /// Rich views are exposed only for this Simplicity module instance.
    pub contract: Option<ContractOutput>,
}

#[derive(Debug, Clone)]
pub struct Environment {
    pub signature_hash: [u8; 32],
    pub session_index: u64,
    pub block_count: u64,
    pub current: ContractOutput,
    pub creation_session: u64,
    pub creation_block_count: u64,
    pub input_index: u32,
    pub input_count: u32,
    pub outputs: Vec<EnvironmentOutput>,
}

pub fn decode_program(input: &ContractInput) -> Result<Arc<RedeemNode>, ContractError> {
    if input.program.len() > MAX_PROGRAM_BYTES || input.witness.len() > MAX_WITNESS_BYTES {
        return Err(ContractError::Limit);
    }
    // Compact witnesses can expand into very large padded values. Check inferred
    // types before the redemption decoder allocates any of those values.
    simplicity::types::Context::with_context(|ctx| {
        let construct = simplicity::ConstructNode::decode::<_, FedimintJet>(
            &ctx,
            BitIter::from(input.program.iter().copied()),
        )
        .map_err(|_| ContractError::Program)?;
        construct
            .set_arrow_to_program()
            .map_err(|_| ContractError::Program)?;
        let mut total_type_bits = 0usize;
        for node in construct.as_ref().post_order_iter::<InternalSharing>() {
            let arrow = node
                .node
                .arrow()
                .finalize()
                .map_err(|_| ContractError::Program)?;
            for width in [arrow.source.bit_width(), arrow.target.bit_width()] {
                if width > 1_048_576 {
                    return Err(ContractError::Limit);
                }
                total_type_bits = total_type_bits.saturating_add(width);
                if total_type_bits > 16_777_216 {
                    return Err(ContractError::Limit);
                }
            }
        }
        Ok(())
    })?;
    let program = RedeemNode::decode::<_, _, FedimintJet>(
        BitIter::from(input.program.iter().copied()),
        BitIter::from(input.witness.iter().copied()),
    )
    .map_err(|_| ContractError::Program)?;
    let bounds = program.bounds();
    if bounds.cost > Cost::from_milliweight(10_000_000)
        || bounds.extra_cells > 1_048_576
        || bounds.extra_frames > 1_024
    {
        return Err(ContractError::Limit);
    }
    Ok(program)
}

/// Fees use the static bound of the submitted redemption program, never
/// measured execution time. One millisatoshi per rounded weight unit plus
/// encoded bytes.
pub fn input_fee(input: &ContractInput) -> Result<Amount, ContractError> {
    let program = decode_program(input)?;
    Ok(program_fee(input, &program))
}

fn program_fee(input: &ContractInput, program: &RedeemNode) -> Amount {
    let weight: bitcoin::Weight = program.bounds().cost.into();
    Amount::from_msats(
        100 + weight.to_wu() + input.program.len() as u64 + input.witness.len() as u64,
    )
}

pub fn execute(input: &ContractInput, environment: &Environment) -> Result<Amount, ContractError> {
    let program = decode_program(input)?;
    if program.cmr().to_byte_array() != environment.current.cmr {
        return Err(ContractError::Commitment);
    }
    let mut machine = BitMachine::for_program(&program).map_err(|_| ContractError::Limit)?;
    machine
        .exec(&program, environment)
        .map_err(|_| ContractError::Rejected)?;
    Ok(program_fee(input, &program))
}
