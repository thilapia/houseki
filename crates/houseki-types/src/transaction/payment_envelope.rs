//! Payment bodies paired with their encoded authorization proofs.

use super::{EncodedTransactionProof, PaymentBody};

/// A payment body and its declared encoded proof.
///
/// Ordinary payments use proof based transfer authorization, so this envelope adds no
/// independent spending signature.
///
/// The operation kind and proof profile come from the body.
///
/// Construction preserves the pair without decoding the proof or establishing that it proves the
/// body's expected statement.
///
/// Before admission, consumers must resolve the allowed profile, derive the expected statement
/// from the actual body and verify the proof and its complete body binding.
///
/// They must enforce active count, payload, proof byte, total size and work limits, including
/// allocation bounds during decoding.
///
/// Component construction does not establish that those limits are current or compatible.
///
/// Envelope equality includes both the body and proof bytes.
///
/// The semantic transaction identifier excludes proof bytes, while DAG payload commitments must
/// cover the complete envelope and its position in the payload.
///
/// This type computes neither identifier nor commitment and assigns no wire encoding.
///
/// It provides no evidence of execution, finality or recipient recovery.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PaymentEnvelope {
    /// Complete declared payment effects and authorization context.
    body: PaymentBody,

    /// Opaque encoded authorization proof without a verification claim.
    proof: EncodedTransactionProof,
}

impl PaymentEnvelope {
    /// Pairs a payment body and encoded proof without verifying their relation.
    pub const fn new(body: PaymentBody, proof: EncodedTransactionProof) -> Self {
        Self { body, proof }
    }

    /// Borrows the complete declared payment body.
    pub const fn body(&self) -> &PaymentBody {
        &self.body
    }

    /// Borrows the encoded proof without claiming validity or authorization.
    pub const fn proof(&self) -> &EncodedTransactionProof {
        &self.proof
    }

    /// Consumes the envelope and returns its complete body and encoded proof.
    pub fn into_parts(self) -> (PaymentBody, EncodedTransactionProof) {
        (self.body, self.proof)
    }
}
