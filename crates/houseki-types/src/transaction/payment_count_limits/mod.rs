//! Configurable limits on payment input and ordinary note output counts.

mod error;

pub use error::PaymentCountLimitsError;

use super::PaymentShape;

/// Inclusive maximum input and ordinary note output counts for payments.
///
/// Both maxima must be at least one so that the limits can admit a payment.
/// Output counts include recipient notes and optional change, with the public
/// fee remaining separate as defined by [`PaymentShape`].
///
/// Callers supply the limits from the applicable protocol context. This type
/// assigns no default or network policy and uses `usize` for counts in memory.
///
/// Passing its check establishes only that the shape fits these two maxima.
///
/// Consumers must also bind counts to the actual body lists and enforce byte,
/// work and proof support requirements.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PaymentCountLimits {
    max_input_count: usize,
    max_output_count: usize,
}

impl PaymentCountLimits {
    /// Constructs inclusive count limits that can admit a payment.
    ///
    /// # Errors
    ///
    /// Returns [`PaymentCountLimitsError::ZeroInputLimit`] or
    /// [`PaymentCountLimitsError::ZeroOutputLimit`] for a zero maximum,
    /// checking the input limit first.
    pub const fn new(
        max_input_count: usize,
        max_output_count: usize,
    ) -> Result<Self, PaymentCountLimitsError> {
        if max_input_count == 0 {
            return Err(PaymentCountLimitsError::ZeroInputLimit);
        }
        if max_output_count == 0 {
            return Err(PaymentCountLimitsError::ZeroOutputLimit);
        }

        Ok(Self {
            max_input_count,
            max_output_count,
        })
    }

    /// Returns the inclusive maximum number of real inputs.
    pub const fn max_input_count(&self) -> usize {
        self.max_input_count
    }

    /// Returns the inclusive maximum number of ordinary note outputs.
    pub const fn max_output_count(&self) -> usize {
        self.max_output_count
    }

    /// Checks that both counts fit within their respective maxima.
    ///
    /// # Errors
    ///
    /// Returns [`PaymentCountLimitsError::InputCountExceedsLimit`] or
    /// [`PaymentCountLimitsError::OutputCountExceedsLimit`] with the actual
    /// count and its maximum, checking inputs first.
    pub const fn validate_shape(&self, shape: PaymentShape) -> Result<(), PaymentCountLimitsError> {
        if shape.input_count() > self.max_input_count {
            return Err(PaymentCountLimitsError::InputCountExceedsLimit {
                actual: shape.input_count(),
                maximum: self.max_input_count,
            });
        }
        if shape.output_count() > self.max_output_count {
            return Err(PaymentCountLimitsError::OutputCountExceedsLimit {
                actual: shape.output_count(),
                maximum: self.max_output_count,
            });
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{PaymentCountLimits, PaymentCountLimitsError, PaymentShape};

    #[test]
    fn construction_rejects_limits_that_cannot_admit_a_payment() {
        for outputs in [0, 1, usize::MAX] {
            assert!(matches!(
                PaymentCountLimits::new(0, outputs),
                Err(PaymentCountLimitsError::ZeroInputLimit)
            ));
        }
        for inputs in [1, usize::MAX] {
            assert!(matches!(
                PaymentCountLimits::new(inputs, 0),
                Err(PaymentCountLimitsError::ZeroOutputLimit)
            ));
        }
    }

    #[test]
    fn validation_accepts_shapes_at_and_below_both_limits() {
        let limits = PaymentCountLimits::new(3, 4).unwrap();

        for (inputs, outputs) in [(1, 1), (3, 1), (1, 4), (3, 4)] {
            let shape = PaymentShape::new(inputs, outputs).unwrap();

            assert!(limits.validate_shape(shape).is_ok());
        }
    }

    #[test]
    fn validation_reports_excess_inputs_before_outputs() {
        let limits = PaymentCountLimits::new(3, 4).unwrap();

        for (inputs, outputs) in [(4, 4), (4, 5), (usize::MAX, 1)] {
            let shape = PaymentShape::new(inputs, outputs).unwrap();

            assert!(matches!(
                limits.validate_shape(shape),
                Err(PaymentCountLimitsError::InputCountExceedsLimit { actual, maximum })
                    if actual == inputs && maximum == 3
            ));
        }
    }

    #[test]
    fn validation_reports_excess_note_outputs() {
        let limits = PaymentCountLimits::new(3, 4).unwrap();

        for outputs in [5, usize::MAX] {
            let shape = PaymentShape::new(3, outputs).unwrap();

            assert!(matches!(
                limits.validate_shape(shape),
                Err(PaymentCountLimitsError::OutputCountExceedsLimit { actual, maximum })
                    if actual == outputs && maximum == 4
            ));
        }
    }

    #[test]
    fn maximum_native_counts_can_be_checked_in_const_contexts() {
        const LIMITS: PaymentCountLimits = match PaymentCountLimits::new(usize::MAX, usize::MAX) {
            Ok(limits) => limits,
            Err(_) => panic!("positive limits are representable"),
        };
        const SHAPE: PaymentShape = match PaymentShape::new(usize::MAX, usize::MAX) {
            Ok(shape) => shape,
            Err(_) => panic!("positive counts are representable"),
        };
        const RESULT: Result<(), PaymentCountLimitsError> = LIMITS.validate_shape(SHAPE);

        assert_eq!(LIMITS.max_input_count(), usize::MAX);
        assert_eq!(LIMITS.max_output_count(), usize::MAX);
        assert!(RESULT.is_ok());
    }
}
