//! Bounded amounts and exact arithmetic over sixteen little endian byte limbs.

mod addition;
#[cfg(test)]
mod addition_air;
#[cfg(any(test, feature = "prover"))]
mod error;
#[cfg(any(test, feature = "prover"))]
mod integer;
mod range;
#[cfg(test)]
mod range_air;

#[cfg(any(test, feature = "prover"))]
pub(crate) use addition::assign_addition;
pub(crate) use addition::eval_addition;
#[cfg(test)]
pub(crate) use addition_air::AdditionAir;
#[cfg(any(test, feature = "prover"))]
pub(crate) use error::AmountError;
#[cfg(any(test, feature = "prover"))]
pub(crate) use range::assign_amount;
pub(crate) use range::eval_amount;
#[cfg(test)]
pub(crate) use range_air::AmountAir;
