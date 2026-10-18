//! Checked shape policy for the bounded payment family.

mod error;
#[cfg(test)]
mod fingerprint;
mod limits;
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "public payment admission follows profile validation"
    )
)]
mod manifest;
mod shape;

pub(crate) use error::ShapeError;
#[cfg_attr(
    not(test),
    expect(
        unused_imports,
        reason = "payment profile admission follows complete constraints"
    )
)]
pub(crate) use limits::body_limits;
#[cfg_attr(
    not(test),
    expect(
        unused_imports,
        reason = "public payment admission follows profile validation"
    )
)]
pub use manifest::EXPERIMENTAL_PAYMENT_PROFILE;
#[cfg_attr(
    not(test),
    expect(
        unused_imports,
        reason = "public payment admission follows profile validation"
    )
)]
pub(crate) use manifest::identity;
pub(crate) use shape::SupportedPaymentShape;
