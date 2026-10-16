//! Internal native hash adapters, selected by concrete Houseki operations.

mod poseidon2;
mod sha3_512;

pub(crate) use poseidon2::poseidon2;
pub(crate) use sha3_512::sha3_512;
