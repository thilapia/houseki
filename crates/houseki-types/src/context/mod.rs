//! Values that identify the context in which protocol rules apply.

mod checkpoint_sequence;
mod validity_checkpoint_range;

pub use checkpoint_sequence::CheckpointSequence;
pub use validity_checkpoint_range::{ValidityCheckpointRange, ValidityCheckpointRangeError};
