//! Per checkpoint public outcome observations derived from committed records.

use houseki_ledger::{CommittedCheckpoint, ExecutionArtifactId};
use houseki_types::ExecutionOutcome;

/// Public identity and exact occurrence/output counts for one actual checkpoint.
#[derive(Debug, Clone)]
pub(crate) struct CheckpointMeasurement {
    /// Canonical artifact identity for the observation.
    artifact: ExecutionArtifactId,

    /// Historical checkpoint position, without claiming global freshness.
    sequence: u64,

    /// Accepted genuine occurrences.
    accepted: usize,

    /// State rejected genuine occurrences.
    rejected: usize,

    /// Actual appended outputs, retaining equal commitments at distinct positions.
    outputs: usize,
}

impl CheckpointMeasurement {
    /// Counts only actual committed public outcomes and their complete output view.
    pub(crate) fn capture(checkpoint: &CommittedCheckpoint) -> Self {
        let accepted = checkpoint
            .receipts()
            .iter()
            .filter(|receipt| receipt.outcome() == ExecutionOutcome::Accepted)
            .count();
        Self {
            artifact: checkpoint.artifact().identity(),
            sequence: checkpoint.artifact().header().sequence.value(),
            accepted,
            rejected: checkpoint.receipts().len() - accepted,
            outputs: checkpoint.accepted_outputs().count(),
        }
    }

    /// Encodes separately keyed rows so empty checkpoints and identities remain
    /// visible.
    pub(crate) fn report(&self) -> String {
        let identity: String = self
            .artifact
            .as_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        format!(
            "checkpoint.{}.artifact_id={}\ncheckpoint.{}.accepted={}\ncheckpoint.{}.rejected={}\ncheckpoint.{}.appended_outputs={}\n",
            self.sequence,
            identity,
            self.sequence,
            self.accepted,
            self.sequence,
            self.rejected,
            self.sequence,
            self.outputs,
        )
    }
}
