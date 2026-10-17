//! Value safe errors for exact bounded canonical body codecs.

use crate::{
    AmountError, PaymentCountLimitsError, PaymentInputsError, PaymentOutputsError,
    PaymentShapeError, RewardWithdrawalBodyError, ValidityCheckpointRangeError,
};
use thiserror::Error;

/// A failure to encode or decode one complete canonical transaction body.
#[derive(Debug, Error)]
pub enum BodyCodecError {
    /// The complete input or planned output exceeds its active bound.
    #[error("canonical body length {actual} exceeds maximum {maximum}")]
    BodyTooLong {
        /// Complete byte count.
        actual: usize,

        /// Inclusive active byte maximum.
        maximum: usize,
    },

    /// One opaque payload exceeds its active bound.
    #[error("canonical payload length {actual} exceeds maximum {maximum}")]
    PayloadTooLong {
        /// Payload byte count excluding its encapsulation.
        actual: usize,

        /// Inclusive active payload maximum.
        maximum: usize,
    },

    /// A complete codec version has no supported rules.
    #[error("unsupported canonical body version {version}")]
    UnsupportedVersion {
        /// Complete four byte version identifier.
        version: u32,
    },

    /// The operation tag differs from the typed decoder's operation.
    #[error("canonical body kind {actual} does not match expected kind {expected}")]
    UnexpectedKind {
        /// Complete declared operation tag.
        actual: u32,

        /// Tag required by the typed decoder.
        expected: u32,
    },

    /// A field or declared list cannot fit in the remaining input bytes.
    #[error("truncated canonical body")]
    Truncated,

    /// Bytes remain after the complete canonical body.
    #[error("trailing canonical body bytes")]
    TrailingBytes,

    /// A length cannot fit host arithmetic or its fixed wire representation.
    #[error("canonical body length cannot be represented")]
    LengthOverflow,

    /// Bounded allocation could not be reserved.
    #[error("could not allocate canonical body storage")]
    AllocationFailed,

    /// A public amount is outside its bounded representation.
    #[error(transparent)]
    Amount(
        /// Original representation failure.
        #[from]
        AmountError,
    ),

    /// The validity range is reversed.
    #[error(transparent)]
    Validity(
        /// Original representation failure.
        #[from]
        ValidityCheckpointRangeError,
    ),

    /// A payment shape has an empty list.
    #[error(transparent)]
    Shape(
        /// Original representation failure.
        #[from]
        PaymentShapeError,
    ),

    /// An actual count exceeds an active maximum.
    #[error(transparent)]
    Counts(
        /// Original representation failure.
        #[from]
        PaymentCountLimitsError,
    ),

    /// Declared payment inputs violate their list invariants.
    #[error(transparent)]
    Inputs(
        /// Original representation failure.
        #[from]
        PaymentInputsError,
    ),

    /// Declared payment outputs violate their list invariants.
    #[error(transparent)]
    Outputs(
        /// Original representation failure.
        #[from]
        PaymentOutputsError,
    ),

    /// A withdrawal violates its positive public amount invariant.
    #[error(transparent)]
    Withdrawal(
        /// Original representation failure.
        #[from]
        RewardWithdrawalBodyError,
    ),
}
