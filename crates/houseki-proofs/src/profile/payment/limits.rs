//! Representation bounds for the complete bounded payment family.

use houseki_types::{BodyCodecLimits, PaymentCountLimits};

/// Keeps each envelope and the complete body bounded independently of the selected shape.
pub(crate) fn body_limits() -> BodyCodecLimits {
    BodyCodecLimits::new(
        PaymentCountLimits::new(4, 2).expect("nonzero fixed counts"),
        4096,
        16384,
    )
}
