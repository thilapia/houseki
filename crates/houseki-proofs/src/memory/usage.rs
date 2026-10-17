//! Public cleanup measurements for a completed private attempt.

/// Observed release accounting for a completed attempt, without private values.
#[derive(Debug)]
pub(crate) struct Usage {
    /// Maximum simultaneously retained tagged payload bytes.
    pub(crate) peak_bytes: usize,

    /// Total payload bytes cleared before their storage was released.
    pub(crate) wiped_bytes: usize,
}
