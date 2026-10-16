//! Note semantics and transaction encryption projection for Houseki.

#![warn(missing_docs, clippy::missing_docs_in_private_items)]

mod encryption;

pub use encryption::{NoteContextError, payment_encryption_core};
