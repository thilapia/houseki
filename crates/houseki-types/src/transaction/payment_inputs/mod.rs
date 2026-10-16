//! A payment's declared anchor and ordered input nullifiers.

mod error;

pub use error::PaymentInputsError;

use super::PaymentCountLimits;
use crate::{NoteRoot, Nullifier};
use std::collections::HashMap;

/// A declared note tree anchor and a nonempty list of distinct input nullifiers.
///
/// Construction preserves input order and checks the actual list length against
/// the supplied input limit. It rejects duplicates rather than sorting or
/// removing them, so the list remains suitable for binding to the payment body
/// and its proof statement. Output limits are checked with the payment's outputs.
///
/// Callers must supply the applicable protocol limits and enforce decoding
/// bounds before allocating the input vector. This type validates an existing
/// vector and assigns no network limit or wire encoding. Consumers must recheck
/// the count if the applicable limits change.
///
/// The anchor is declared data, not evidence of finality or eligibility. Proof
/// verification must bind each nullifier to an authorized note and its original
/// position under this anchor. Execution separately checks the allowed anchor
/// history and evolving spent set, then applies all effects atomically.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PaymentInputs {
    anchor: NoteRoot,
    nullifiers: Vec<Nullifier>,
}

impl PaymentInputs {
    /// Constructs payment inputs without changing their order.
    ///
    /// # Errors
    ///
    /// Returns [`PaymentInputsError::EmptyInputs`] for an empty list or
    /// [`PaymentInputsError::InputCountExceedsLimit`] for an excessive count.
    /// Count checks run before duplicate detection, which reports the first
    /// repeated slot in input order as [`PaymentInputsError::DuplicateNullifier`].
    pub fn new(
        anchor: NoteRoot,
        nullifiers: Vec<Nullifier>,
        limits: PaymentCountLimits,
    ) -> Result<Self, PaymentInputsError> {
        if nullifiers.is_empty() {
            return Err(PaymentInputsError::EmptyInputs);
        }

        if nullifiers.len() > limits.max_input_count() {
            return Err(PaymentInputsError::InputCountExceedsLimit {
                actual: nullifiers.len(),
                maximum: limits.max_input_count(),
            });
        }

        let mut first_indices = HashMap::with_capacity(nullifiers.len());
        for (index, nullifier) in nullifiers.iter().enumerate() {
            if let Some(first_index) = first_indices.insert(nullifier, index) {
                return Err(PaymentInputsError::DuplicateNullifier {
                    first_index,
                    duplicate_index: index,
                });
            }
        }

        Ok(Self { anchor, nullifiers })
    }

    /// Returns the declared note tree anchor.
    pub const fn anchor(&self) -> NoteRoot {
        self.anchor
    }

    /// Borrows the input nullifiers in their original order.
    pub fn nullifiers(&self) -> &[Nullifier] {
        &self.nullifiers
    }

    /// Returns the input count derived from the actual list length.
    pub fn input_count(&self) -> usize {
        self.nullifiers.len()
    }

    /// Consumes the inputs and returns the declared anchor and ordered list.
    pub fn into_parts(self) -> (NoteRoot, Vec<Nullifier>) {
        (self.anchor, self.nullifiers)
    }
}

#[cfg(test)]
mod tests {
    use super::{PaymentCountLimits, PaymentInputs, PaymentInputsError};
    use crate::{NoteRoot, Nullifier};

    #[test]
    fn construction_preserves_anchor_and_input_order_at_the_limit() {
        let anchor = NoteRoot::from_bytes([42; 64]);
        let nullifiers = vec![
            Nullifier::from_bytes([3; 64]),
            Nullifier::from_bytes([1; 64]),
            Nullifier::from_bytes([2; 64]),
        ];
        let limits = PaymentCountLimits::new(3, 1).unwrap();
        let inputs = PaymentInputs::new(anchor, nullifiers.clone(), limits).unwrap();

        assert_eq!(inputs.anchor(), anchor);
        assert_eq!(inputs.nullifiers(), nullifiers.as_slice());
        assert_eq!(inputs.input_count(), 3);
        assert_eq!(inputs.into_parts(), (anchor, nullifiers));
    }

    #[test]
    fn construction_accepts_one_input_and_distinct_full_digest_values() {
        let anchor = NoteRoot::from_bytes([0; 64]);
        let first = Nullifier::from_bytes([0; 64]);
        let mut last_byte_differs = [0; 64];
        last_byte_differs[63] = 1;
        let second = Nullifier::from_bytes(last_byte_differs);
        let limits = PaymentCountLimits::new(2, 1).unwrap();

        assert!(PaymentInputs::new(anchor, vec![first], limits).is_ok());
        assert!(PaymentInputs::new(anchor, vec![first, second], limits).is_ok());
    }

    #[test]
    fn construction_rejects_empty_inputs() {
        let result = PaymentInputs::new(
            NoteRoot::from_bytes([0; 64]),
            vec![],
            PaymentCountLimits::new(1, 1).unwrap(),
        );

        assert!(matches!(result, Err(PaymentInputsError::EmptyInputs)));
    }

    #[test]
    fn construction_rejects_excess_inputs_before_checking_duplicates() {
        let result = PaymentInputs::new(
            NoteRoot::from_bytes([0; 64]),
            vec![Nullifier::from_bytes([0; 64]); 3],
            PaymentCountLimits::new(2, 1).unwrap(),
        );

        assert!(matches!(
            result,
            Err(PaymentInputsError::InputCountExceedsLimit {
                actual: 3,
                maximum: 2
            })
        ));
    }

    #[test]
    fn construction_reports_the_first_repeated_slot_in_input_order() {
        let a = Nullifier::from_bytes([1; 64]);
        let b = Nullifier::from_bytes([2; 64]);
        let c = Nullifier::from_bytes([3; 64]);
        let limits = PaymentCountLimits::new(5, 1).unwrap();

        for (nullifiers, first, duplicate) in [
            (vec![a, a], 0, 1),
            (vec![a, b, a], 0, 2),
            (vec![a, b, c, b, a], 1, 3),
        ] {
            assert!(matches!(
                PaymentInputs::new(NoteRoot::from_bytes([0; 64]), nullifiers, limits),
                Err(PaymentInputsError::DuplicateNullifier { first_index, duplicate_index })
                    if first_index == first && duplicate_index == duplicate
            ));
        }
    }
}
