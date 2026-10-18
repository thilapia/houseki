//! Byte representation constraints shared by integer and hash components.

mod byte;
mod bytes;
#[cfg(any(test, feature = "prover"))]
mod error;
mod field;

#[cfg(test)]
pub(crate) use byte::ByteAir;
#[cfg(any(test, feature = "prover"))]
pub(crate) use byte::assign_byte;
pub(crate) use byte::eval_byte;
#[cfg(test)]
pub(crate) use bytes::BytesAir;
#[cfg(any(test, feature = "prover"))]
pub(crate) use bytes::assign_bytes;
pub(crate) use bytes::eval_bytes;
#[cfg(any(test, feature = "prover"))]
pub(crate) use error::EncodingError;
#[cfg(test)]
pub(crate) use field::FieldAir;
#[cfg(any(test, feature = "prover"))]
pub(crate) use field::assign_field_bytes;
pub(crate) use field::eval_field_bytes;
