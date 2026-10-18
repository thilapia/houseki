//! Borrowed protected inputs for the supported payment shapes.

mod error;

pub use error::WitnessShapeError;

use crate::profile::payment::{ShapeError, SupportedPaymentShape};
use houseki_notes::{NoteOpening, SpendWitness};
use std::fmt;

/// Borrows original protected owners without allocating or copying private material.
///
/// Construction checks shape only, leaving every spending equation and exact body comparison
/// to the relation implementation.
///
/// The witness cannot outlive either borrowed slice or any referenced owner.
///
/// ```compile_fail,E0515
/// use houseki_notes::{NoteOpening, SpendWitness};
/// use houseki_proofs::PaymentWitness;
/// fn escaping<'a>(inputs: &'a [SpendWitness<'a>], opening: &'a NoteOpening) -> PaymentWitness<'a> {
///     let outputs = [opening];
///     PaymentWitness::new(inputs, &outputs).unwrap()
/// }
/// ```
pub struct PaymentWitness<'a> {
    /// Original spends with caller owned keys, openings and paths.
    inputs: &'a [SpendWitness<'a>],

    /// Original output openings without a second private owner.
    outputs: &'a [&'a NoteOpening],
}

impl<'a> PaymentWitness<'a> {
    /// Checks supported counts in input then output order without allocating.
    ///
    /// # Errors
    ///
    /// Returns the corresponding [`WitnessShapeError`] unless inputs number one through four
    /// and outputs number one through two.
    pub fn new(
        inputs: &'a [SpendWitness<'a>],
        outputs: &'a [&'a NoteOpening],
    ) -> Result<Self, WitnessShapeError> {
        SupportedPaymentShape::new(inputs.len(), outputs.len()).map_err(|error| match error {
            ShapeError::UnsupportedInputCount => WitnessShapeError::UnsupportedInputCount,
            ShapeError::UnsupportedOutputCount => WitnessShapeError::UnsupportedOutputCount,
        })?;

        Ok(Self { inputs, outputs })
    }

    /// Borrows the same spend slice with its original owner lifetime.
    pub const fn inputs(&self) -> &'a [SpendWitness<'a>] {
        self.inputs
    }

    /// Borrows the same output reference slice with its original owner lifetime.
    pub const fn outputs(&self) -> &'a [&'a NoteOpening] {
        self.outputs
    }
}

impl fmt::Debug for PaymentWitness<'_> {
    /// Omits counts, values and all referenced owners from diagnostics.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PaymentWitness([REDACTED])")
    }
}

/// Shape, lifetime and fixed diagnostic tests.
#[cfg(test)]
mod tests {
    use super::*;

    /// Rejects unsupported counts without retaining inputs or allocating.
    #[test]
    fn witness_errors_are_redacted() {
        let (result, allocations, _) =
            crate::test_allocator::measure(|| PaymentWitness::new(&[], &[]));
        let error = result.unwrap_err();

        assert_eq!(error, WitnessShapeError::UnsupportedInputCount);
        assert_eq!(allocations, 0);
        assert_eq!(format!("{error:?}"), "UnsupportedInputCount");
        assert_eq!(error.to_string(), "unsupported payment input count");
        assert_eq!(
            WitnessShapeError::UnsupportedOutputCount.to_string(),
            "unsupported payment output count"
        );
    }
}
