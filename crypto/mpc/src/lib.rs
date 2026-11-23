//! Experimental honest-majority MPC that generates payment hashes whose
//! preimage no single party knows. See the crate README.

pub mod circuit;
pub mod direct;
pub mod engine;
pub mod field;
pub mod memory;
pub mod replay;
pub mod sha256;

/// The most parties a run may have. Evaluation points are the party indices
/// plus one (`1..=MAX_PARTIES`), so every pairwise difference stays below 64.
/// Supports committees up to `m = 31` (`N = 46` guardians).
pub const MAX_PARTIES: usize = 32;

/// The most multiplication triples a run may consume.
pub const MAX_TRIPLES: usize = 30_000_000;
