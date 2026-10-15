//! Input and ordinary note output counts for payments.

mod error;

pub use error::PaymentShapeError;

/// The numbers of real inputs and ordinary note outputs in a payment.
///
/// Both counts must be at least one. Outputs include recipient notes and any
/// optional change, while the separate public fee never contributes to the
/// output count. A payment without change can therefore have one output.
///
/// Counts use `usize` to describe list lengths in memory and do not define a
/// wire representation. A transaction body must derive them from its actual
/// lists and enforce the active size and work limits. Constructing a shape
/// checks only the minimum counts, without establishing proof support or
/// transaction validity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PaymentShape {
    input_count: usize,
    output_count: usize,
}

impl PaymentShape {
    /// Constructs a payment shape from its input and ordinary note output counts.
    ///
    /// # Errors
    ///
    /// Returns [`PaymentShapeError::EmptyInputs`] for zero inputs or
    /// [`PaymentShapeError::EmptyOutputs`] for zero outputs, checking inputs
    /// first when both counts are zero.
    pub const fn new(input_count: usize, output_count: usize) -> Result<Self, PaymentShapeError> {
        if input_count == 0 {
            return Err(PaymentShapeError::EmptyInputs);
        }
        if output_count == 0 {
            return Err(PaymentShapeError::EmptyOutputs);
        }

        Ok(Self {
            input_count,
            output_count,
        })
    }

    /// Returns the number of real inputs.
    pub const fn input_count(&self) -> usize {
        self.input_count
    }

    /// Returns the number of ordinary note outputs, excluding the public fee.
    pub const fn output_count(&self) -> usize {
        self.output_count
    }
}

#[cfg(test)]
mod tests {
    use super::{PaymentShape, PaymentShapeError};

    #[test]
    fn construction_accepts_variable_counts_without_requiring_change() {
        for (inputs, outputs) in [(1, 1), (1, 2), (3, 1), (2, 4), (usize::MAX, usize::MAX)] {
            let shape = PaymentShape::new(inputs, outputs).unwrap();

            assert_eq!(shape.input_count(), inputs);
            assert_eq!(shape.output_count(), outputs);
        }
    }

    #[test]
    fn construction_rejects_payments_without_inputs() {
        for outputs in [0, 1, usize::MAX] {
            assert!(matches!(
                PaymentShape::new(0, outputs),
                Err(PaymentShapeError::EmptyInputs)
            ));
        }
    }

    #[test]
    fn construction_rejects_payments_without_note_outputs() {
        for inputs in [1, usize::MAX] {
            assert!(matches!(
                PaymentShape::new(inputs, 0),
                Err(PaymentShapeError::EmptyOutputs)
            ));
        }
    }
}
