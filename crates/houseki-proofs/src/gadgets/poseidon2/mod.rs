//! Constraints for the fixed application hash transcript and its field encoding.

mod framing;
mod linear;
mod permutation;
#[cfg(test)]
mod permutation_air;
mod profile;
#[cfg(any(test, feature = "prover"))]
mod scratch;

pub(crate) use framing::Frame;
#[cfg(test)]
pub(crate) use framing::FramingAir;
#[cfg(test)]
pub(crate) use permutation_air::PermutationAir;
