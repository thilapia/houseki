//! Guarded four-hash assignment into caller-owned strided storage.

use super::{Input, Spend, SpendError};
use crate::gadgets::Scratch;
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_goldilocks::Goldilocks;
use zeroize::Zeroizing;

impl Spend {
    /// Validates complete sources and storage before overwriting any operation cells.
    ///
    /// Shape errors precede byte errors, both leave the destination unchanged, and stride gaps
    /// remain owned by the caller throughout assignment and cleanup.
    pub(crate) fn assign(
        &self,
        input: Input<'_>,
        rows: &mut [Goldilocks],
        stride: usize,
    ) -> Result<(), SpendError> {
        let required = (Self::ROWS - 1)
            .checked_mul(stride)
            .and_then(|start| start.checked_add(Self::WIDTH));
        if stride < Self::WIDTH || required.is_none_or(|length| length > rows.len()) {
            return Err(SpendError::ShapeMismatch);
        }

        for part in [
            input.spending_key.as_slice(),
            input.nullifier_key.as_slice(),
            input.network.as_slice(),
            input.commitment.as_slice(),
            input.position.as_slice(),
        ] {
            for value in part {
                let word = Zeroizing::new(value.as_canonical_u64());
                if *word > 255 {
                    return Err(SpendError::InvalidByte);
                }
            }
        }

        for phase in 0..Self::ROWS {
            rows[phase * stride..phase * stride + Self::WIDTH].fill(Goldilocks::ZERO);
        }

        let mut first = Scratch::<64>::default();
        let mut second = Scratch::<64>::default();
        self.spending
            .assign(
                &[input.network, input.spending_key],
                &mut rows[192..],
                stride,
            )
            .expect("validated spend sources and layout");
        self.spending.copy_digest(&rows[192..], stride, &mut first);
        self.nullifier_key
            .assign(
                &[input.network, input.nullifier_key],
                &mut rows[21 * stride + 192..],
                stride,
            )
            .expect("validated spend sources and layout");
        self.nullifier_key
            .copy_digest(&rows[21 * stride + 192..], stride, &mut second);
        for phase in 0..Self::ROWS {
            let row = &mut rows[phase * stride..phase * stride + 192];
            row[..32].copy_from_slice(input.spending_key);
            row[32..64].copy_from_slice(input.nullifier_key);
            row[64..128].copy_from_slice(&first[..]);
            row[128..192].copy_from_slice(&second[..]);
        }

        self.ownership
            .assign(
                &[input.network, &first[..], &second[..]],
                &mut rows[42 * stride + 192..],
                stride,
            )
            .expect("validated spend sources and layout");
        let version = [
            Goldilocks::ONE,
            Goldilocks::ZERO,
            Goldilocks::ZERO,
            Goldilocks::ZERO,
        ];
        self.nullifier
            .assign(
                &[
                    input.network,
                    &version,
                    input.nullifier_key,
                    input.commitment,
                    input.position,
                ],
                &mut rows[65 * stride + 192..],
                stride,
            )
            .expect("validated spend sources and layout");

        Ok(())
    }
}
