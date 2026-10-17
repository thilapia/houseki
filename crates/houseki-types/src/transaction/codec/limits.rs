//! Active count and byte bounds for complete canonical bodies.

use crate::PaymentCountLimits;

/// Caller supplied inclusive bounds for canonical body encoding and decoding.
///
/// These values establish representation limits without selecting network activation policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BodyCodecLimits {
    /// Inclusive input and output count maxima for payments.
    payment_counts: PaymentCountLimits,

    /// Inclusive byte maximum for each opaque encrypted payload.
    max_payload_bytes: usize,

    /// Inclusive byte maximum for the complete body.
    max_body_bytes: usize,
}

impl BodyCodecLimits {
    /// Retains active bounds, allowing zero byte maxima that reject nonempty encodings.
    pub const fn new(
        payment_counts: PaymentCountLimits,
        max_payload_bytes: usize,
        max_body_bytes: usize,
    ) -> Self {
        Self {
            payment_counts,
            max_payload_bytes,
            max_body_bytes,
        }
    }

    /// Returns payment count limits to recheck against actual lists.
    pub const fn payment_counts(&self) -> PaymentCountLimits {
        self.payment_counts
    }

    /// Returns the inclusive maximum for each payload, excluding its encapsulation.
    pub const fn max_payload_bytes(&self) -> usize {
        self.max_payload_bytes
    }

    /// Returns the inclusive maximum for the complete encoded body.
    pub const fn max_body_bytes(&self) -> usize {
        self.max_body_bytes
    }
}
