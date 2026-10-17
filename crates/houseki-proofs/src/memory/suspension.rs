//! Scoped restoration of allocation tagging around a public copy.

use super::{ACTIVE, Account};

/// Restores allocation tagging after copying an explicitly public result.
pub(super) struct Suspension {
    /// Still-live attempt restored when this stack guard leaves scope.
    pub(super) account: *const Account,
}

impl Drop for Suspension {
    /// Restores the same thread's attempt even if public output construction unwinds.
    fn drop(&mut self) {
        ACTIVE.with(|active| active.set(self.account));
    }
}
