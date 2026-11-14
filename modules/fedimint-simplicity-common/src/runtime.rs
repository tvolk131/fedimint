use std::sync::Arc;

use fedimint_core::Amount;
use fedimint_core::core::ModuleInstanceId;
use simplicity::dag::{DagLike, InternalSharing};
use simplicity::{BitIter, BitMachine, Cost, RedeemNode};

use crate::jet::FedimintJet;
use crate::{
    BASE_ITEM_FEE_MSAT, ContractError, ContractInput, ContractOutput, MAX_EXTRA_CELLS,
    MAX_EXTRA_FRAMES, MAX_PROGRAM_BYTES, MAX_PROGRAM_MILLIWEIGHT, MAX_TOTAL_TYPE_BITS,
    MAX_TYPE_BITS, MAX_WITNESS_BYTES,
};

mod preflight;
mod pruning;

#[derive(Debug, Clone)]
pub struct EnvironmentOutput {
    pub module_id: ModuleInstanceId,
    pub hash: [u8; 32],
    /// Rich views are exposed only for this Simplicity module instance.
    pub contract: Option<ContractOutput>,
}

#[derive(Debug, Clone)]
pub struct EnvironmentInput {
    pub outpoint: fedimint_core::OutPoint,
    pub contract: ContractOutput,
}

#[derive(Debug, Clone)]
pub struct Environment {
    /// Transaction-wide data is shared across input executions. Only the
    /// current contract and its clocks/index vary.
    pub inputs: Arc<[EnvironmentInput]>,
    pub actions: Arc<crate::assets::AssetActions>,
    pub signature_hash: [u8; 32],
    pub session_index: u64,
    pub block_count: u64,
    pub current: ContractOutput,
    pub creation_session: u64,
    pub creation_block_count: u64,
    pub input_index: u32,
    pub input_count: u32,
    pub outputs: Arc<[EnvironmentOutput]>,
}

pub fn decode_program(input: &ContractInput) -> Result<Arc<RedeemNode>, ContractError> {
    if input.program.len() > MAX_PROGRAM_BYTES || input.witness.len() > MAX_WITNESS_BYTES {
        return Err(ContractError::Limit);
    }
    preflight::check(&input.program).map_err(|_| ContractError::Program)?;
    // Compact witnesses can expand into very large padded values. Check
    // inferred types before the redemption decoder allocates any of those
    // values.
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
                if width > MAX_TYPE_BITS {
                    return Err(ContractError::Limit);
                }
                total_type_bits = total_type_bits.saturating_add(width);
                if total_type_bits > MAX_TOTAL_TYPE_BITS {
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
    if bounds.cost > Cost::from_milliweight(MAX_PROGRAM_MILLIWEIGHT)
        || bounds.extra_cells > MAX_EXTRA_CELLS
        || bounds.extra_frames > MAX_EXTRA_FRAMES
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
        BASE_ITEM_FEE_MSAT
            + weight.to_wu()
            + input.program.len() as u64
            + input.witness.len() as u64,
    )
}

pub fn execute(input: &ContractInput, environment: &Environment) -> Result<Amount, ContractError> {
    let program = decode_program(input)?;
    execute_decoded(input, environment, &program)
}

/// Check execution-version restrictions and the stored policy commitment
/// without allocating a machine or executing any jet.
pub fn check_commitment(
    program: &RedeemNode,
    output: &ContractOutput,
) -> Result<(), ContractError> {
    if output.version != crate::EXECUTION_VERSION {
        return Err(ContractError::Version);
    }
    if program.cmr().to_byte_array() != output.cmr {
        return Err(ContractError::Commitment);
    }
    Ok(())
}

/// Execute the result of decoding this exact input. Guardian preparations are
/// scoped to the immutable transaction and recheck the snapshot commitment.
pub fn execute_decoded(
    input: &ContractInput,
    environment: &Environment,
    program: &RedeemNode,
) -> Result<Amount, ContractError> {
    check_commitment(program, &environment.current)?;
    let mut machine = BitMachine::for_program(program).map_err(|_| ContractError::Limit)?;
    let mut tracker = pruning::Execution::default();
    machine
        .exec_with_tracker(program, environment, &mut tracker)
        .map_err(|_| ContractError::Rejected)?;
    tracker.check(program)?;
    Ok(program_fee(input, program))
}
