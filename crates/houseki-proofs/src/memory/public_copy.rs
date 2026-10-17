//! Explicit escape for canonical public proof bytes after private processing.

use std::ptr;

use super::{ACTIVE, MemoryError, suspension::Suspension};

/// Copies only canonical public proof bytes outside the private allocation lifetime.
///
/// Callers must never use this escape for witnesses, traces or backend intermediate data.
pub(crate) fn public_copy(bytes: &[u8]) -> Result<Vec<u8>, MemoryError> {
    let account = ACTIVE.with(|active| active.replace(ptr::null()));
    let _suspension = Suspension { account };

    let mut result = Vec::new();
    result
        .try_reserve_exact(bytes.len())
        .map_err(|_| MemoryError::AllocationFailed)?;
    result.extend_from_slice(bytes);

    Ok(result)
}
