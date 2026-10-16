//! Fixed public-input profile from Plonky3 0.8.0 at
//! a21e3ed42905040ad49c519e402f018381c12d0c. No caller-selected parameters.

use std::sync::OnceLock;

use p3_goldilocks::{Goldilocks, Poseidon2Goldilocks, default_goldilocks_poseidon2_16};
use p3_symmetric::Permutation;

pub(super) const MODULUS: u64 = 0xffff_ffff_0000_0001;
pub(super) const WIDTH: usize = 16;
pub(super) const RATE: usize = 7;
pub(super) const PACKED_BYTES: usize = 7;
pub(super) const OUTPUT_ELEMENTS: usize = 11;

pub(super) fn permute(state: &mut [Goldilocks; WIDTH]) {
    // The factory uses the pinned constants, x^7, four initial full rounds,
    // 22 partial rounds and four final full rounds on every supported target.
    // Cache only public permutation parameters, never a transcript state.
    static PERMUTATION: OnceLock<Poseidon2Goldilocks<WIDTH>> = OnceLock::new();
    PERMUTATION
        .get_or_init(default_goldilocks_poseidon2_16)
        .permute_mut(state);
}

#[cfg(test)]
mod tests {
    use super::{Goldilocks, permute};
    use p3_field::PrimeField64;

    #[test]
    fn fixed_backend_matches_upstream_width_16_known_answer() {
        // Plonky3 a21e3ed42905040ad49c519e402f018381c12d0c,
        // goldilocks/src/poseidon2.rs::test_default_goldilocks_poseidon2_width_16.
        let mut state = Goldilocks::new_array([
            0x4d3f967fab9d4979,
            0x57e1fba55677697e,
            0x57429a86e75a3774,
            0x31d379f3a592b5eb,
            0x497232e1b648e3f1,
            0x325a7db57173c39e,
            0xa802252d78bee916,
            0x8920f55e154adef8,
            0xa1225bc9c7913658,
            0xd687be5097ffd038,
            0x89f514ef0c913e48,
            0x21fd4a9cf548cd84,
            0x570a1586ada436ff,
            0x46bfbf38ccd740ae,
            0x23651b3f3ab26484,
            0xe90f3b02127fa552,
        ]);
        permute(&mut state);
        assert_eq!(
            state.map(|x| x.as_canonical_u64()),
            [
                0xf0f7717837c7032a,
                0xf12fbcc838feb15b,
                0xd8661f6fa4165ad8,
                0x351cdc546760d1a9,
                0x99474334bf02445f,
                0x46fc4e9ceb376d6a,
                0x4601808321fcd920,
                0xc58bfd0342dc60df,
                0xb7f3acd43f3c029c,
                0x5c7afa6a6997dfc5,
                0xecbef8b82906c887,
                0xd490e3b4e945d87c,
                0x31866766b83ebe0b,
                0xb32d52f6e7a5bea2,
                0x9522431667b3c5f9,
                0xeaf5638a69518f65,
            ]
        );
    }
}
