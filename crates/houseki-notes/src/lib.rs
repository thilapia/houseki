//! Note semantics, checked output encryption and transaction core projection for Houseki.

#![warn(missing_docs, clippy::missing_docs_in_private_items)]

#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "Native payment relation consumers are separate increments."
    )
)]
mod accumulation;
mod blinding;
mod encryption;
mod format;
mod opening;
mod recipient;

pub use blinding::{NoteBlinding, NoteBlindingError};
pub use encryption::{
    NoteContextError, NoteOutputEncryptionError, encrypt_payment_output, encrypt_withdrawal_output,
    payment_encryption_core, withdrawal_encryption_core,
};
pub use format::{NoteFormat, NoteFormatError};
pub use opening::{NoteOpening, NoteOpeningError};
pub use recipient::{NoteRecipient, NoteRecipientError};
