//! Experimental honest-majority MPC that generates payment hashes whose
//! preimage no single party knows. See the crate README.

pub mod circuit;
pub mod direct;
pub mod engine;
pub mod field;
pub mod memory;
pub mod replay;

/// The most parties a run may have. Evaluation points are the party indices
/// plus one, so every pairwise difference stays below 32.
pub const MAX_PARTIES: usize = 16;

/// The most multiplication triples a run may consume.
pub const MAX_TRIPLES: usize = 1_000_000;
