//! Public note outputs carried by transaction bodies.

use super::{EncryptedNoteEnvelope, NoteCommitment};

/// A note commitment paired with its encrypted recovery envelope.
///
/// Payments use the same output representation for recipient notes and optional
/// change. Reward withdrawals also create a note output. The pair contains no
/// public recipient identifier, plaintext amount or change marker.
///
/// Construction preserves the supplied values without establishing that the
/// envelope decrypts to an opening of this commitment. Recipients must recover
/// and validate the note, including recomputing its commitment under the allowed
/// rules. A valid transaction proof does not establish successful delivery.
///
/// The containing body determines output order and must bind the commitment,
/// complete envelope and output context into authorization. Consumers enforce
/// active count and byte limits and the supported proof relation. This type
/// assigns no wire encoding or future note insertion position.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct NoteOutput {
    commitment: NoteCommitment,
    envelope: EncryptedNoteEnvelope,
}

impl NoteOutput {
    /// Pairs a declared commitment and envelope without verifying their relation.
    pub const fn new(commitment: NoteCommitment, envelope: EncryptedNoteEnvelope) -> Self {
        Self {
            commitment,
            envelope,
        }
    }

    /// Returns the declared note commitment.
    pub const fn commitment(&self) -> NoteCommitment {
        self.commitment
    }

    /// Borrows the encrypted note envelope.
    pub const fn envelope(&self) -> &EncryptedNoteEnvelope {
        &self.envelope
    }

    /// Consumes the output and returns its commitment and envelope.
    pub fn into_parts(self) -> (NoteCommitment, EncryptedNoteEnvelope) {
        (self.commitment, self.envelope)
    }
}
