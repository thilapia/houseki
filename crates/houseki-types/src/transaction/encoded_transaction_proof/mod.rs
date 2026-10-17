//! Bounded opaque proof bytes carried by a transaction envelope.

mod error;

pub use error::EncodedTransactionProofError;

/// An owned encoded transaction proof checked against a supplied byte limit.
///
/// This value preserves opaque proof bytes without depending on a proof backend or selecting an
/// encoding.
///
/// The verifier must resolve the allowed proof profile from the transaction context, apply its
/// decoding rules and verify the proper relation against the statement derived from the actual
/// body and kind.
///
/// Construction checks only the inclusive maximum byte length.
///
/// Empty bytes are representable because minimum lengths and proof structure belong to the
/// profile.
///
/// Neither successful construction nor byte equality establishes proof validity, authorization
/// or eligibility for execution.
///
/// Callers must supply the applicable limit and enforce decoding bounds before allocating proof
/// bytes or decoded backend structures.
///
/// They must also enforce verification work limits and total envelope size separately.
///
/// A change in limits requires a new length check.
///
/// No default network limit or outer wire framing is assigned here.
///
/// These bytes belong to the transaction envelope and are excluded from the semantic transaction
/// identifier.
///
/// They do not replace any required public account signatures or the separate checkpoint
/// execution proof package.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EncodedTransactionProof(
    /// Opaque encoded proof bytes under a supplied inclusive limit.
    Vec<u8>,
);

impl EncodedTransactionProof {
    /// Stores opaque proof bytes under an inclusive byte limit.
    ///
    /// # Errors
    ///
    /// Returns [`EncodedTransactionProofError::ByteLengthExceedsLimit`] if the supplied bytes
    /// exceed `max_proof_bytes`.
    ///
    /// A zero maximum permits only an empty value, without establishing that it is a valid proof
    /// encoding.
    pub fn new(
        bytes: Vec<u8>,
        max_proof_bytes: usize,
    ) -> Result<Self, EncodedTransactionProofError> {
        if bytes.len() > max_proof_bytes {
            return Err(EncodedTransactionProofError::ByteLengthExceedsLimit {
                actual: bytes.len(),
                maximum: max_proof_bytes,
            });
        }

        Ok(Self(bytes))
    }

    /// Borrows all encoded proof bytes without interpreting them.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Returns the actual encoded proof length, excluding outer framing.
    pub fn byte_len(&self) -> usize {
        self.0.len()
    }

    /// Consumes the value and returns every encoded proof byte in order.
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

/// Construction, conversion and rejection properties of [`EncodedTransactionProof`].
#[cfg(test)]
mod tests {
    use super::{EncodedTransactionProof, EncodedTransactionProofError};

    /// Checks that construction preserves every byte at the inclusive limit.
    #[test]
    fn construction_preserves_every_byte_at_the_inclusive_limit() {
        let bytes: Vec<u8> = (0..=u8::MAX).rev().collect();
        let proof = EncodedTransactionProof::new(bytes.clone(), bytes.len()).unwrap();

        assert_eq!(proof.as_bytes(), bytes.as_slice());
        assert_eq!(proof.byte_len(), bytes.len());
        assert_eq!(proof.into_bytes(), bytes);
    }

    /// Checks that construction rejects proofs above the supplied limit.
    #[test]
    fn construction_rejects_proofs_above_the_supplied_limit() {
        for (actual, maximum) in [(1, 0), (2, 1), (257, 256)] {
            let result = EncodedTransactionProof::new(vec![0; actual], maximum);

            assert!(matches!(
                result,
                Err(EncodedTransactionProofError::ByteLengthExceedsLimit {
                    actual: reported_actual, maximum: reported_maximum,
                }) if reported_actual == actual && reported_maximum == maximum
            ));
        }
    }

    /// Checks that encoded storage leaves format and validity checks to the profile.
    #[test]
    fn encoded_storage_leaves_format_and_validity_checks_to_the_profile() {
        for (bytes, maximum) in [
            (vec![], 0),
            (vec![], 1),
            (vec![0], 1),
            (vec![u8::MAX; 3], 4),
            (vec![0], usize::MAX),
        ] {
            let proof = EncodedTransactionProof::new(bytes.clone(), maximum).unwrap();

            assert_eq!(proof.into_bytes(), bytes);
        }
    }
}
