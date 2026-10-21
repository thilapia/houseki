//! Exact checked join of accepted original outputs and their assigned tree positions.

mod body;

pub use body::OutputBody;

use crate::ExecutionArtifactId;
use houseki_types::{NoteOutput, NotePosition, VertexId};

/// Borrowed accepted output tied to one checked committed occurrence and original body
/// slot.
#[derive(Debug)]
pub struct AcceptedOutput<'a> {
    /// Complete containing artifact identity.
    pub(in crate::store) artifact_id: ExecutionArtifactId,

    /// Range relative canonical occurrence index.
    pub(in crate::store) occurrence_index: u64,

    /// Exact original vertex and payload position.
    pub(in crate::store) origin: (VertexId, u64),

    /// Original body output slot.
    pub(in crate::store) output_index: u64,

    /// Actual assigned note insertion position.
    pub(in crate::store) position: NotePosition,

    /// Exact corresponding original public output.
    pub(in crate::store) output: &'a NoteOutput,

    /// Complete original recovery context.
    pub(in crate::store) body: OutputBody<'a>,
}

impl<'a> AcceptedOutput<'a> {
    /// Returns the complete containing artifact identity.
    pub const fn artifact_id(&self) -> ExecutionArtifactId {
        self.artifact_id
    }

    /// Returns the range relative original occurrence index.
    pub const fn occurrence_index(&self) -> u64 {
        self.occurrence_index
    }

    /// Returns the exact vertex and payload origin.
    pub const fn origin(&self) -> (VertexId, u64) {
        self.origin
    }

    /// Returns the original body output slot, including repeated commitments.
    pub const fn output_index(&self) -> u64 {
        self.output_index
    }

    /// Returns the actual assigned note position.
    pub const fn position(&self) -> NotePosition {
        self.position
    }

    /// Borrows the exact corresponding encrypted output and commitment.
    pub const fn output(&self) -> &'a NoteOutput {
        self.output
    }

    /// Borrows full canonical context required by existing native recovery APIs.
    pub const fn body(&self) -> OutputBody<'a> {
        self.body
    }
}
