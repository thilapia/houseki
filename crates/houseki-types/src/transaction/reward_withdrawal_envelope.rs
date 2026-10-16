//! Reward withdrawal bodies paired with their encoded proofs and signatures.

use super::{EncodedTransactionProof, RewardWithdrawalBody};
use crate::EncodedMlDsa87Signature;

/// A reward withdrawal body and its declared encoded proof and signature.
///
/// The proof must establish that the output note contains the public withdrawal
/// amount. The ML-DSA-87 signature separately authorizes the source debit and
/// must cover the complete body and its context. Both are required, and neither
/// is verified by constructing this envelope. The operation kind and proof
/// profile come from the body.
///
/// Before admission, consumers must resolve the allowed profile, derive the
/// expected statement from the actual body and verify its proof binding. They
/// must authenticate the account authority and its relationship to the declared
/// public key and account identifier, then verify the signature outside proofs
/// under the selected signing transcript. An output proof alone cannot authorize
/// a withdrawal, and a signature alone cannot establish the output amount.
///
/// Consumers enforce active payload, proof byte, total size and work limits,
/// including allocation bounds during decoding. Execution must check balances,
/// nonce matching and exhaustion, exact fees and atomic state updates.
/// Construction does not establish admission eligibility or successful execution.
///
/// Equality includes the body, proof and signature bytes. The semantic
/// transaction identifier excludes proof and signature bytes, while DAG payload
/// commitments cover the complete envelope and its position in the payload.
///
/// This type computes neither identifier nor commitment, assigns no wire
/// encoding and provides no evidence of finality or recipient recovery.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RewardWithdrawalEnvelope {
    body: RewardWithdrawalBody,
    proof: EncodedTransactionProof,
    signature: EncodedMlDsa87Signature,
}

impl RewardWithdrawalEnvelope {
    /// Groups a withdrawal body, encoded proof and signature without verifying them.
    pub const fn new(
        body: RewardWithdrawalBody,
        proof: EncodedTransactionProof,
        signature: EncodedMlDsa87Signature,
    ) -> Self {
        Self {
            body,
            proof,
            signature,
        }
    }

    /// Borrows the complete declared withdrawal body.
    pub const fn body(&self) -> &RewardWithdrawalBody {
        &self.body
    }

    /// Borrows the encoded output proof without claiming validity.
    pub const fn proof(&self) -> &EncodedTransactionProof {
        &self.proof
    }

    /// Borrows the encoded signature without claiming authorization.
    pub const fn signature(&self) -> &EncodedMlDsa87Signature {
        &self.signature
    }

    /// Consumes the envelope and returns its complete body, proof and signature.
    pub fn into_parts(
        self,
    ) -> (
        RewardWithdrawalBody,
        EncodedTransactionProof,
        EncodedMlDsa87Signature,
    ) {
        (self.body, self.proof, self.signature)
    }
}
