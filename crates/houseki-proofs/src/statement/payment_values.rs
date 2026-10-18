//! Borrowed semantic fields for every supported bounded payment shape.

use crate::profile::payment::SupportedPaymentShape;

/// Retains trusted public shape metadata while exposing only the selected statement's fields.
pub(crate) struct PaymentValues<'a, T> {
    /// Exact validated public vector in canonical statement order.
    values: &'a [T],

    /// Number of expected nullifiers selected by the trusted circuit identity.
    inputs: usize,

    /// Number of expected output commitments selected by the trusted circuit identity.
    outputs: usize,
}

impl<'a, T> PaymentValues<'a, T> {
    /// Computes the public length only for the eight supported payment shapes.
    pub(crate) fn length(inputs: usize, outputs: usize) -> Option<usize> {
        Some(
            SupportedPaymentShape::new(inputs, outputs)
                .ok()?
                .public_values_len(),
        )
    }

    /// Checks exact storage length against caller-selected shape without reading witness data.
    pub(crate) fn new(values: &'a [T], inputs: usize, outputs: usize) -> Option<Self> {
        if values.len() != Self::length(inputs, outputs)? {
            return None;
        }

        Some(Self {
            values,
            inputs,
            outputs,
        })
    }

    /// Borrows the expected network.
    pub(crate) fn network(&self) -> &'a [T; 64] {
        self.values[..64].try_into().unwrap()
    }

    /// Borrows the expected note-tree anchor root.
    pub(crate) fn root(&self) -> &'a [T; 64] {
        self.values[64..128].try_into().unwrap()
    }

    /// Borrows the full occupied count, including the full-tree value 2^64.
    pub(crate) fn count(&self) -> &'a [T; 16] {
        self.values[128..144].try_into().unwrap()
    }

    /// Borrows all public fee bytes.
    pub(crate) fn fee(&self) -> &'a [T; 16] {
        self.values[144..160].try_into().unwrap()
    }

    /// Returns one expected input nullifier and rejects an index outside the selected shape.
    pub(crate) fn nullifier(&self, index: usize) -> Option<&'a [T; 64]> {
        if index >= self.inputs {
            return None;
        }

        let start = 160 + index * 64;
        Some(self.values[start..start + 64].try_into().unwrap())
    }

    /// Returns one expected output commitment without exposing its private opening fields.
    pub(crate) fn commitment(&self, index: usize) -> Option<&'a [T; 64]> {
        if index >= self.outputs {
            return None;
        }

        let start = 160 + (self.inputs + index) * 64;
        Some(self.values[start..start + 64].try_into().unwrap())
    }
}

/// Exact field mapping and checked counts across every supported shape.
#[cfg(test)]
mod tests {
    use super::*;

    /// Shared lengths preserve the frozen order and never admit ambiguous extra cells or indices.
    #[test]
    fn payment_view_preserves_all_shapes_and_endpoints() {
        let values: Vec<_> = (0..545).collect();
        for inputs in 1..=4 {
            for outputs in 1..=2 {
                let length = 160 + 64 * (inputs + outputs);
                let view = PaymentValues::new(&values[..length], inputs, outputs).unwrap();
                assert_eq!(view.network(), &values[..64]);
                assert_eq!(view.root(), &values[64..128]);
                assert_eq!(view.count(), &values[128..144]);
                assert_eq!(view.fee(), &values[144..160]);
                for index in 0..inputs {
                    assert_eq!(
                        view.nullifier(index).unwrap(),
                        &values[160 + 64 * index..224 + 64 * index]
                    );
                }

                for index in 0..outputs {
                    assert_eq!(
                        view.commitment(index).unwrap(),
                        &values[160 + 64 * (inputs + index)..224 + 64 * (inputs + index)]
                    );
                }

                assert!(view.nullifier(inputs).is_none());
                assert!(view.commitment(outputs).is_none());
                assert!(view.commitment(usize::MAX).is_none());
                for wrong in [length - 1, length + 1] {
                    assert!(PaymentValues::new(&values[..wrong], inputs, outputs).is_none());
                }
            }
        }

        for (inputs, outputs) in [(0, 1), (1, 0), (5, 1), (1, 3), (usize::MAX, usize::MAX)] {
            assert!(PaymentValues::new(&values, inputs, outputs).is_none());
            assert!(PaymentValues::<u8>::length(inputs, outputs).is_none());
        }
    }
}
