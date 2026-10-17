//! Bounded amounts and exact arithmetic over sixteen little endian byte limbs.

mod addition;
#[cfg(test)]
mod addition_air;
#[cfg(any(test, feature = "prover"))]
mod error;
#[cfg(any(test, feature = "prover"))]
mod integer;

#[cfg(any(test, feature = "prover"))]
pub(crate) use addition::assign_addition;
pub(crate) use addition::eval_addition;
#[cfg(test)]
pub(crate) use addition_air::AdditionAir;
#[cfg(any(test, feature = "prover"))]
pub(crate) use error::AmountError;
