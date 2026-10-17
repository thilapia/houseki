//! Checked note delivery, authenticated recovery and completed body projection.

mod error;
mod projection;
mod recovery;
mod seal;

pub use error::{NoteContextError, NoteOutputEncryptionError, NoteRecoveryError};
pub use projection::{payment_encryption_core, withdrawal_encryption_core};
pub use recovery::recover_payment_output;
pub use seal::{encrypt_payment_output, encrypt_withdrawal_output};
