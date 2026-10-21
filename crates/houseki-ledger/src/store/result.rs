//! The outcome of publishing or retrying one complete checkpoint.

use super::CommittedCheckpoint;

/// Successful publication or an exact previously recorded historical publication.
pub enum CommitResult {
    /// This attempt published one complete new checkpoint image.
    Published(
        /// Actual checkpoint published by this attempt.
        CommittedCheckpoint,
    ),

    /// This exact candidate was already committed and no effect was applied again.
    AlreadyCommitted(
        /// Original checkpoint retained for this exact retry.
        CommittedCheckpoint,
    ),
}

impl CommitResult {
    /// Consumes either success form into its original committed checkpoint handle.
    pub fn checkpoint(self) -> CommittedCheckpoint {
        match self {
            Self::Published(c) | Self::AlreadyCommitted(c) => c,
        }
    }
}
