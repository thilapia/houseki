//! Allocation-free accepted-output projection over already checked committed records.

use super::{AcceptedOutput, CommittedCheckpoint, OutputBody};
use houseki_types::{ExecutionOutcome, NoteOutput, TransactionEnvelope};

/// Joins accepted receipts, original body slots and actual appends in canonical order.
pub(super) fn accepted_outputs(
    checkpoint: &CommittedCheckpoint,
) -> impl Iterator<Item = AcceptedOutput<'_>> + '_ {
    checkpoint
        .artifact()
        .occurrences()
        .iter()
        .zip(checkpoint.receipts())
        .zip(checkpoint.effects())
        .enumerate()
        .flat_map(move |(index, ((occurrence, receipt), effect))| {
            let accepted = effect
                .accepted
                .as_ref()
                .filter(|_| matches!(receipt.outcome(), ExecutionOutcome::Accepted));
            let (outputs, body): (&[NoteOutput], OutputBody<'_>) = match occurrence.envelope() {
                TransactionEnvelope::Payment(e) => {
                    (e.body().outputs().outputs(), OutputBody::Payment(e.body()))
                }
                TransactionEnvelope::RewardWithdrawal(e) => (
                    std::slice::from_ref(e.body().output()),
                    OutputBody::RewardWithdrawal(e.body()),
                ),
            };
            accepted.into_iter().flat_map(move |accepted| {
                outputs.iter().enumerate().zip(&accepted.appends).map(
                    move |((slot, output), append)| AcceptedOutput {
                        artifact_id: checkpoint.artifact().identity(),
                        occurrence_index: index as u64,
                        origin: (occurrence.vertex_id(), occurrence.transaction_index()),
                        output_index: slot as u64,
                        position: append.position,
                        output,
                        body,
                    },
                )
            })
        })
}
