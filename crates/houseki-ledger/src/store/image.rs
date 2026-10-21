//! One immutable complete store image with no recursively retained prior image.

use super::ReplayArchive;
use crate::state::CommittedRecord;
use std::sync::Arc;

/// State/head and complete replay history cross one ownership publication boundary.
pub(crate) struct StoreImage {
    /// Actual complete current checkpoint record.
    pub(crate) current: Arc<CommittedRecord>,

    /// Consistent archive and native historical query owners.
    pub(crate) history: ReplayArchive,
}

impl StoreImage {
    /// Installs only a validated bootstrap record into an empty consistent image.
    pub(crate) fn bootstrap(record: Arc<CommittedRecord>) -> Self {
        let history = ReplayArchive::bootstrap(&record);
        Self {
            current: record,
            history,
        }
    }
}
