//! Checked shape policy and frozen identity for complete bounded payments.

mod error;
#[cfg(test)]
mod fingerprint;
mod limits;
mod manifest;
mod shape;

pub(crate) use error::ShapeError;
pub(crate) use limits::body_limits;
#[cfg(any(feature = "experimental-profiles", all(test, feature = "prover")))]
pub use manifest::EXPERIMENTAL_PAYMENT_PROFILE;
pub(crate) use manifest::identity;
pub(crate) use shape::SupportedPaymentShape;
