//! Projection of completed transaction bodies into typed encryption inputs.

mod error;
mod projection;

pub use error::NoteContextError;
pub use projection::{payment_encryption_core, withdrawal_encryption_core};
