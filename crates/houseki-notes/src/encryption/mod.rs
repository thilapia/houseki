//! Checked output encryption and completed body projection for note delivery.

mod error;
mod projection;
mod seal;

pub use error::{NoteContextError, NoteOutputEncryptionError};
pub use projection::{payment_encryption_core, withdrawal_encryption_core};
pub use seal::{encrypt_payment_output, encrypt_withdrawal_output};
