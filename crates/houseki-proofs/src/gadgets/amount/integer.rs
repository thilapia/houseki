//! Guarded integer conversion for assignment over existing field byte arrays.

use super::AmountError;
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_goldilocks::Goldilocks;
use zeroize::Zeroizing;

/// Validates all byte limbs and reconstructs an exact integer in guarded storage.
///
/// The original cells remain borrowed and canonical word temporaries are wiped on every return.
///
/// # Errors
///
/// Returns [`AmountError::InvalidLimb`] if any canonical field value exceeds 255.
pub(super) fn read(limbs: &[Goldilocks; 16]) -> Result<Zeroizing<u128>, AmountError> {
    let mut value = Zeroizing::new(0_u128);
    for (index, limb) in limbs.iter().enumerate() {
        let word = Zeroizing::new(limb.as_canonical_u64());
        if *word > 255 {
            return Err(AmountError::InvalidLimb);
        }

        *value |= u128::from(*word) << (8 * index);
    }

    Ok(value)
}

/// Overwrites all output limbs without allocating an intermediate byte array.
///
/// The caller retains cleanup responsibility for both the borrowed integer and destination.
pub(super) fn write(value: &u128, limbs: &mut [Goldilocks; 16]) {
    for (index, limb) in limbs.iter_mut().enumerate() {
        *limb = Goldilocks::from_u8((value >> (8 * index)) as u8);
    }
}
