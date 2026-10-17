//! Concrete application note trees and protected native membership witnesses.

#![warn(missing_docs, clippy::missing_docs_in_private_items)]

mod tree;
mod witness;

pub use tree::{NoteTree, NoteTreeError};
#[cfg(feature = "proofs")]
pub use witness::ProofPathAccessError;
pub use witness::{NoteMembershipError, NoteMembershipWitness};
