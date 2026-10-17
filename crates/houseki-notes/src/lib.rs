//! Note semantics, checked delivery, authenticated recovery and core projection for Houseki.

#![warn(missing_docs, clippy::missing_docs_in_private_items)]

mod accumulation;
mod blinding;
mod encryption;
mod format;
mod nullifier;
mod opening;
mod recipient;
mod relation;

pub use blinding::{NoteBlinding, NoteBlindingError};
pub use encryption::{
    NoteContextError, NoteOutputEncryptionError, NoteRecoveryError, encrypt_payment_output,
    encrypt_withdrawal_output, payment_encryption_core, recover_payment_output,
    recover_withdrawal_output, withdrawal_encryption_core,
};
pub use format::{NoteFormat, NoteFormatError};
pub use nullifier::derive_nullifier;
pub use opening::{NoteOpening, NoteOpeningError};
pub use recipient::{NoteAddressError, NoteRecipient, NoteRecipientError};
pub use relation::{
    PaymentRelationError, SpendRelationError, SpendWitness, WithdrawalOutputRelationError,
    check_payment, check_spend, check_withdrawal_output,
};
