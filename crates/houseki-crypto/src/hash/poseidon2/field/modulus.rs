//! Compile time Montgomery parameters for the fixed Goldilocks modulus.

use crypto_bigint::{
    U64,
    modular::{ConstMontyParams, FixedMontyParams},
};

use crate::hash::poseidon2::profile::MODULUS;

/// Public parameters shared by every field value without carrying sensitive state.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(super) struct GoldilocksModulus;

impl ConstMontyParams<{ U64::LIMBS }> for GoldilocksModulus {
    /// Number of machine limbs needed to represent a 64 bit field value.
    const LIMBS: usize = U64::LIMBS;

    /// Montgomery parameters computed from the existing public profile modulus.
    const PARAMS: FixedMontyParams<{ U64::LIMBS }> = FixedMontyParams::new_vartime(
        U64::from_u64(MODULUS)
            .to_odd()
            .expect_copied("the Goldilocks modulus is odd"),
    );
}
