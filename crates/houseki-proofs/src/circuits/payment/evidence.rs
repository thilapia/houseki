//! Evidence borrowing the complete verified payment and its independently expected anchor.

use crate::ProofContext;
use houseki_types::{NoteTreeAnchor, PaymentBody};

/// Complete payment evidence bound to every ordered effect, envelope and expected context field.
///
/// Each input proves spending authority, membership at an occupied original position and its
/// exact nullifier, while each output proves a positive ordinary opening and exact conservation
/// includes the public fee once.
///
/// This evidence does not establish unspentness, eligible anchors, fee policy, activation, delivery
/// correctness, tree capacity or atomic execution.
///
/// Evidence borrows no private owner, proof storage or runtime admission slot.
///
/// Callers cannot construct evidence directly.
///
/// ```compile_fail,E0451
/// use houseki_proofs::{ProofContext, VerifiedPayment};
/// use houseki_types::{NoteTreeAnchor, PaymentBody};
/// fn forge<'a>(body: &'a PaymentBody, anchor: &'a NoteTreeAnchor, context: &'a ProofContext) -> VerifiedPayment<'a> {
///     VerifiedPayment { body, anchor, context }
/// }
/// ```
///
/// The verified anchor must outlive its evidence.
///
/// ```compile_fail,E0515
/// use houseki_proofs::{ProofContext, ProofRuntime, VerifiedPayment, verify_payment};
/// use houseki_types::{EncodedTransactionProof, NoteTreeAnchor, PaymentBody};
/// fn escape<'a>(body: &'a PaymentBody, anchor: NoteTreeAnchor, proof: &EncodedTransactionProof, context: &'a ProofContext) -> VerifiedPayment<'a> {
///     verify_payment(&ProofRuntime::new(), body, &anchor, proof, context).unwrap()
/// }
/// ```
#[derive(Debug)]
#[must_use]
pub struct VerifiedPayment<'a> {
    /// Exact immutable body supplied to successful verification.
    pub(super) body: &'a PaymentBody,

    /// Independently supplied root, network and occupied count.
    pub(super) anchor: &'a NoteTreeAnchor,

    /// Independently selected expected context.
    pub(super) context: &'a ProofContext,
}

impl<'a> VerifiedPayment<'a> {
    /// Borrows the complete verified body without authorizing state changes.
    pub const fn body(&self) -> &'a PaymentBody {
        self.body
    }

    /// Borrows the exact verified anchor without asserting eligibility.
    pub const fn anchor(&self) -> &'a NoteTreeAnchor {
        self.anchor
    }

    /// Borrows the expected context without asserting activation.
    pub const fn context(&self) -> &'a ProofContext {
        self.context
    }
}
