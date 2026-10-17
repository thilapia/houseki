//! Byte representation constraints shared by integer and hash components.

mod byte;
#[cfg(test)]
mod byte_air;
mod bytes;
#[cfg(test)]
mod bytes_air;
#[cfg(any(test, feature = "prover"))]
mod error;
mod field;
#[cfg(test)]
mod field_air;

#[cfg(any(test, feature = "prover"))]
pub(crate) use byte::assign_byte;
pub(crate) use byte::eval_byte;
#[cfg(test)]
pub(crate) use byte_air::ByteAir;
#[cfg(any(test, feature = "prover"))]
pub(crate) use bytes::assign_bytes;
pub(crate) use bytes::eval_bytes;
#[cfg(test)]
pub(crate) use bytes_air::BytesAir;
#[cfg(any(test, feature = "prover"))]
pub(crate) use error::EncodingError;
#[cfg(any(test, feature = "prover"))]
pub(crate) use field::assign_field_bytes;
pub(crate) use field::eval_field_bytes;
#[cfg(test)]
pub(crate) use field_air::FieldAir;
