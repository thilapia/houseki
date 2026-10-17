//! Bounded withdrawal trace construction borrowing the original native opening owner.

use super::WithdrawalAir;
use crate::{
    CancellationToken,
    backend::{BackendError, OpeningFields, Trace},
    gadgets::Opening,
};
use houseki_notes::NoteOpening;

/// Converts one borrowed opening into four complete guarded cycles for the hiding PCS.
pub(super) fn build(
    air: &WithdrawalAir,
    opening: &NoteOpening,
    cancellation: &CancellationToken,
) -> Result<Trace, BackendError> {
    if cancellation.is_cancelled() {
        return Err(BackendError::Cancelled);
    }

    let fields = OpeningFields::new(opening)?;
    let mut trace = Trace::new(
        WithdrawalAir::ROWS,
        Opening::WIDTH,
        WithdrawalAir::ROWS * Opening::WIDTH,
    )?;
    for cycle in trace
        .values_mut()
        .as_chunks_mut::<{ Opening::CYCLE * Opening::WIDTH }>()
        .0
    {
        if cancellation.is_cancelled() {
            return Err(BackendError::Cancelled);
        }

        air.opening
            .assign(fields.input(), cycle)
            .map_err(|_| BackendError::InvalidTrace)?;
    }

    Ok(trace)
}

/// Native ownership, statement compatibility and allocation bounds.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        profile::{ExpectedIdentity, Relation},
        statement::Statement,
    };
    use houseki_types::Amount;
    use p3_air::check_all_constraints;
    use p3_matrix::dense::RowMajorMatrix;

    /// Guarded conversion agrees with native commitments at every important amount boundary.
    #[test]
    fn reward_withdrawal_trace_matches_native_statement() {
        let air = WithdrawalAir::new();
        for atoms in [1, (1_u128 << 64) + 3, Amount::MAX_ATOMS] {
            let (opening, body) = super::super::fixture::withdrawal(atoms, 0);
            let identity = ExpectedIdentity {
                profile: body.context().proof_profile_id(),
                relation: Relation::RewardWithdrawal,
                shape: 1,
                manifest: [7; 64],
            };
            let statement = Statement::withdrawal(&body, body.context(), &identity).unwrap();
            let trace = build(&air, &opening, &CancellationToken::new()).unwrap();
            let matrix = RowMajorMatrix::new(trace.values().to_vec(), trace.width());

            assert_eq!(trace.height(), 512);
            assert!(
                check_all_constraints(&air, &matrix, &statement.public_values, Some(1)).is_ok()
            );
            assert_eq!(opening.commitment().unwrap(), body.output().commitment());
        }
    }

    /// Cancellation before witness import leaves no trace allocation or retained witness copy.
    #[test]
    fn reward_withdrawal_trace_cancellation_precedes_allocation() {
        let (opening, _) = super::super::fixture::withdrawal(1, 0);
        let air = WithdrawalAir::new();
        let cancellation = CancellationToken::new();
        cancellation.cancel();
        let (result, calls, bytes) =
            crate::test_allocator::measure(|| build(&air, &opening, &cancellation));

        assert!(matches!(result, Err(BackendError::Cancelled)));
        assert_eq!((calls, bytes), (0, 0));
    }
}
