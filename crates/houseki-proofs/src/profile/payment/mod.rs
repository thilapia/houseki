//! Checked shape policy for the bounded payment family.

mod error;
mod limits;
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
pub(crate) use shape::SupportedPaymentShape;
