//! Checked public counts for complete payment schedules.

use super::ShapeError;

/// Validated public counts for one complete payment schedule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SupportedPaymentShape {
    /// Number of actual input notes.
    inputs: usize,

    /// Number of actual output notes.
    outputs: usize,
}

impl SupportedPaymentShape {
    /// Checks inputs before outputs without allocating or performing count arithmetic.
    pub(crate) fn new(inputs: usize, outputs: usize) -> Result<Self, ShapeError> {
        if !(1..=4).contains(&inputs) {
            return Err(ShapeError::UnsupportedInputCount);
        }

        if !(1..=2).contains(&outputs) {
            return Err(ShapeError::UnsupportedOutputCount);
        }

        Ok(Self { inputs, outputs })
    }

    /// Returns the validated input count.
    pub(crate) const fn inputs(self) -> usize {
        self.inputs
    }

    /// Returns the validated output count.
    pub(crate) const fn outputs(self) -> usize {
        self.outputs
    }

    /// Encodes both exact counts independently of trace or statement dimensions.
    pub(crate) const fn code(self) -> u32 {
        ((self.inputs as u32) << 8) | self.outputs as u32
    }

    /// Returns the exact number of byte limbs in the semantic public vector.
    pub(crate) const fn public_values_len(self) -> usize {
        160 + 64 * (self.inputs + self.outputs)
    }
}

/// Count boundaries and unique identity codes for the bounded payment family.
#[cfg(test)]
mod tests {
    use super::*;

    /// Accepts all eight count pairs with distinct codes and exact semantic lengths.
    #[test]
    fn payment_shapes_cover_exactly_four_by_two() {
        let mut codes = std::collections::HashSet::new();
        for inputs in 1..=4 {
            for outputs in 1..=2 {
                let shape = SupportedPaymentShape::new(inputs, outputs).unwrap();

                assert_eq!(shape.inputs(), inputs);
                assert_eq!(shape.outputs(), outputs);
                assert_eq!(shape.public_values_len(), 160 + 64 * (inputs + outputs));
                assert!(codes.insert(shape.code()));
            }
        }

        let maximum = SupportedPaymentShape::new(4, 2).unwrap();

        assert_eq!(maximum.code(), 0x0402);
        assert_eq!(maximum.public_values_len(), 544);
        assert_eq!(codes.len(), 8);
    }

    /// Rejects unsupported counts before count arithmetic, with input errors taking precedence.
    #[test]
    fn payment_shape_rejects_invalid_counts_before_arithmetic() {
        for inputs in [0, 5, usize::MAX] {
            for outputs in [0, 1, 2, 3, usize::MAX] {
                assert_eq!(
                    SupportedPaymentShape::new(inputs, outputs),
                    Err(ShapeError::UnsupportedInputCount)
                );
            }
        }

        for inputs in 1..=4 {
            for outputs in [0, 3, usize::MAX] {
                assert_eq!(
                    SupportedPaymentShape::new(inputs, outputs),
                    Err(ShapeError::UnsupportedOutputCount)
                );
            }
        }
    }
}
