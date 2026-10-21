//! Scope bound cleanup of a selected test only failure.

/// Restores normal execution even when a test assertion unwinds.
pub(crate) struct Injection;

impl Drop for Injection {
    /// Removes this thread's selected test failure.
    fn drop(&mut self) {
        super::SELECTED.set(None)
    }
}
