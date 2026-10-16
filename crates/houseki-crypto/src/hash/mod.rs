//! Internal native hash adapters, selected by concrete Houseki operations.

mod sha3_512;

pub(crate) use sha3_512::sha3_512;
