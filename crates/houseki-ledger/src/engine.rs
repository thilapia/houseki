//! Stateless synchronous reference ledger orchestration.

/// Native executor whose policy always comes from the trusted parent.
#[derive(Debug, Default)]
pub struct LedgerEngine;

impl LedgerEngine {
    /// Constructs a stateless native executor without caller-selected rules.
    pub const fn new() -> Self {
        Self
    }
}
