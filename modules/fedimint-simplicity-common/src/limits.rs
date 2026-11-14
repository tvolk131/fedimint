//! Consensus limits and fee terms of execution version one. Every value here
//! is a consensus rule: changing one requires a new execution version.

/// Simplicity inputs, or Simplicity outputs, of one instance in a transaction.
pub const MAX_CONTRACTS: usize = 32;
/// Outputs of any kind in an outer transaction with Simplicity items.
pub const MAX_TRANSACTION_OUTPUTS: usize = 128;
pub const MAX_PROGRAM_BYTES: usize = 8_192;
pub const MAX_WITNESS_BYTES: usize = 8_192;
/// Program and witness bytes of every Simplicity input in a transaction.
pub const MAX_TRANSACTION_REDEMPTION_BYTES: usize = 16_384;
pub const MAX_RECOVERY_BYTES: usize = 1_024;
/// Entries in an asset bundle, and creations or authorities in asset actions.
pub const MAX_ASSETS: usize = 32;

/// Largest bit width of any single inferred type in a redemption program.
pub const MAX_TYPE_BITS: usize = 1_048_576;
/// Sum of every inferred source and target type width in a redemption program.
pub const MAX_TOTAL_TYPE_BITS: usize = 16_777_216;
/// Bit machine memory bounds of one redemption program.
pub const MAX_EXTRA_CELLS: usize = 1_048_576;
pub const MAX_EXTRA_FRAMES: usize = 1_024;

/// Static cost bound of one redemption program. The transaction-wide budget,
/// [`MAX_TRANSACTION_MILLIWEIGHT`], is stricter.
pub const MAX_PROGRAM_MILLIWEIGHT: u32 = 10_000_000;
/// Static cost of every redemption program in a transaction, plus
/// [`CREATION_SIGNATURE_MILLIWEIGHT`] per asset creation.
pub const MAX_TRANSACTION_MILLIWEIGHT: u32 = 2_000_000;
/// Creation authorization runs outside the VM. Charge it conservatively in
/// the same budget; this is a resource charge, not a change to the asset fee.
pub const CREATION_SIGNATURE_MILLIWEIGHT: u32 = 100_000;

/// Fixed fee for every Simplicity input or output, before size and cost terms.
pub const BASE_ITEM_FEE_MSAT: u64 = 100;
/// Fee for every asset created, on top of the action output's item fee.
pub const CREATION_FEE_MSAT: u64 = 100;
