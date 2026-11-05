//! Read-only catch-up progress. Only successful method completion establishes
//! a usable wallet; reaching the final session is not a success signal.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncProgress {
    /// The next session to apply, and the exclusive recovery boundary.
    Wallet { next: u64, end: u64 },
    /// Public lineage replay remains atomic even as its read cursor advances.
    Contracts { next: u64, end: u64 },
}
