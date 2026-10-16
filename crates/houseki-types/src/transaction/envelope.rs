//! Common envelopes for supported transaction operations.

use super::{PaymentEnvelope, RewardWithdrawalEnvelope, TransactionKind};

/// A declared payment or reward withdrawal with its required authorization data.
///
/// Each variant carries the complete envelope for its operation. Payments carry
/// an encoded proof, while reward withdrawals also require an encoded ML-DSA-87
/// signature. There is no optional signature field or independent kind tag that
/// could disagree with the body. Consumers can match the variant to borrow or
/// take ownership of the corresponding envelope.
///
/// Both payloads are boxed to keep the common enum compact without reserving
/// space for the withdrawal's large encoded key and signature in every value.
/// This is an in-memory representation choice and assigns no wire layout.
///
/// Construction and conversion preserve unverified data. Consumers must apply
/// the selected operation's context, size, proof and authorization checks before
/// admission, then enforce its state rules during execution. Equality includes
/// authorization bytes, while the semantic transaction identifier excludes them.
/// This type assigns no wire tags, computes no identifier and establishes no
/// eligibility, execution or finality.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum TransactionEnvelope {
    /// A private payment with its encoded authorization proof.
    Payment(Box<PaymentEnvelope>),

    /// A reward withdrawal with its encoded output proof and required signature.
    RewardWithdrawal(Box<RewardWithdrawalEnvelope>),
}

impl TransactionEnvelope {
    /// Returns the operation kind implied by the contained envelope.
    pub const fn kind(&self) -> TransactionKind {
        match self {
            Self::Payment(_) => TransactionKind::Payment,
            Self::RewardWithdrawal(_) => TransactionKind::RewardWithdrawal,
        }
    }
}

impl From<PaymentEnvelope> for TransactionEnvelope {
    /// Wraps a complete payment envelope without verifying it.
    fn from(envelope: PaymentEnvelope) -> Self {
        Self::Payment(Box::new(envelope))
    }
}

impl From<RewardWithdrawalEnvelope> for TransactionEnvelope {
    /// Wraps a complete reward withdrawal envelope without verifying it.
    fn from(envelope: RewardWithdrawalEnvelope) -> Self {
        Self::RewardWithdrawal(Box::new(envelope))
    }
}
