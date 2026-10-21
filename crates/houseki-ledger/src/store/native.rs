//! Retained actual committed ownership for historical queries and exact retry matching.

use crate::{ParentToken, state::CommittedRecord};
use std::sync::Arc;

/// A historical successful publication with its exact original expected parent.
#[derive(Clone)]
pub(crate) struct NativeCheckpoint {
    /// Complete original parent comparison token retained by value.
    pub(crate) parent: ParentToken,

    /// Complete actual record without a recursively retained store image.
    pub(crate) record: Arc<CommittedRecord>,
}
