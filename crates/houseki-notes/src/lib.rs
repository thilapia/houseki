//! Note semantics and transaction encryption projection for Houseki.

#![warn(missing_docs, clippy::missing_docs_in_private_items)]

mod blinding;
mod encryption;

pub use blinding::{NoteBlinding, NoteBlindingError};
pub use encryption::{NoteContextError, payment_encryption_core, withdrawal_encryption_core};
