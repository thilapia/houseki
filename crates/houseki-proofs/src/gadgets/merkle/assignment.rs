//! Guarded path evaluation directly into caller-owned membership rows.

use super::{Input, Membership, MembershipError};
use crate::gadgets::{Scratch, assign_byte};
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_goldilocks::Goldilocks;
use zeroize::Zeroizing;

impl Membership {
    /// Validates every source and occupancy before assigning one complete path without allocation.
    ///
    /// Shape errors precede byte, count and occupancy errors, leaving destinations unchanged.
    ///
    /// The caller owns all sources and destination cleanup, including preserved stride gaps.
    pub(crate) fn assign(
        &self,
        input: Input<'_>,
        rows: &mut [Goldilocks],
        stride: usize,
    ) -> Result<(), MembershipError> {
        let required = (Self::ROWS - 1)
            .checked_mul(stride)
            .and_then(|start| start.checked_add(Self::WIDTH));
        if stride < Self::WIDTH || required.is_none_or(|length| length > rows.len()) {
            return Err(MembershipError::ShapeMismatch);
        }

        for part in [
            input.network.as_slice(),
            input.count.as_slice(),
            input.commitment.as_slice(),
            input.position.as_slice(),
            input.siblings.as_flattened(),
        ] {
            for value in part {
                let word = Zeroizing::new(value.as_canonical_u64());
                if *word > 255 {
                    return Err(MembershipError::InvalidByte);
                }
            }
        }

        let count = integer(input.count);
        let position = integer(input.position);
        if *count > 1_u128 << 64 {
            return Err(MembershipError::InvalidCount);
        }

        if *position >= *count {
            return Err(MembershipError::UnoccupiedPosition);
        }

        let difference = Zeroizing::new(*count - *position - 1);
        let mut bits = Scratch::<64>::default();
        for (byte, destination) in input.position.iter().zip(bits.as_chunks_mut::<8>().0) {
            assign_byte(byte, destination).expect("preflighted position byte");
        }

        for phase in 0..Self::ROWS {
            let row = &mut rows[phase * stride..phase * stride + Self::WIDTH];
            row.fill(Goldilocks::ZERO);
            row[192..256].copy_from_slice(&bits[..]);
        }

        let mut carry = Zeroizing::new(1_u16);
        for byte in 0..16 {
            let value = Zeroizing::new(((*difference >> (8 * byte)) & 255) as u8);
            rows[256 + byte] = Goldilocks::from_u8(*value);
            assign_byte(
                &Goldilocks::from_u8(*value),
                (&mut rows[272 + byte * 8..280 + byte * 8])
                    .try_into()
                    .unwrap(),
            )
            .expect("bounded difference byte");
            *carry += *value as u16 + ((*position >> (8 * byte)) & 255) as u16;
            *carry >>= 8;
            rows[400 + byte] = Goldilocks::from_u16(*carry);
        }

        let mut current = Scratch::<64>::default();
        let mut digest = Scratch::<64>::default();
        self.leaf
            .assign(&[input.network, input.commitment], &mut rows[416..], stride)
            .expect("validated leaf sources and storage");
        self.leaf.copy_digest(&rows[416..], stride, &mut current);
        for phase in 0..21 {
            rows[phase * stride + 128..phase * stride + 192].copy_from_slice(&current[..]);
        }

        let mut children = Scratch::<128>::default();
        for (level, sibling) in input.siblings.iter().enumerate() {
            crate::memory::checkpoint();
            let orientation = bits[level];
            for byte in 0..64 {
                children[byte] = current[byte] + orientation * (sibling[byte] - current[byte]);
                children[64 + byte] = sibling[byte] + orientation * (current[byte] - sibling[byte]);
            }

            let start = 21 + 23 * level;
            let encoded_level = [
                Goldilocks::from_usize(level),
                Goldilocks::ZERO,
                Goldilocks::ZERO,
                Goldilocks::ZERO,
            ];
            self.parent
                .assign(
                    &[
                        input.network,
                        &encoded_level,
                        &children[..64],
                        &children[64..],
                    ],
                    &mut rows[start * stride + 416..],
                    stride,
                )
                .expect("validated parent sources and storage");
            self.parent
                .copy_digest(&rows[start * stride + 416..], stride, &mut digest);
            for phase in start..start + 23 {
                let row = &mut rows[phase * stride..phase * stride + 192];
                row[..64].copy_from_slice(&current[..]);
                row[64..128].copy_from_slice(sibling);
                row[128..192].copy_from_slice(&digest[..]);
            }

            current.copy_from_slice(&digest[..]);
        }

        let depth = [
            Goldilocks::from_u8(64),
            Goldilocks::ZERO,
            Goldilocks::ZERO,
            Goldilocks::ZERO,
        ];
        self.root
            .assign(
                &[input.network, &depth, input.count, &current[..]],
                &mut rows[1493 * stride + 416..],
                stride,
            )
            .expect("validated root sources and storage");
        for phase in 1493..Self::ROWS {
            rows[phase * stride..phase * stride + 64].copy_from_slice(&current[..]);
        }

        Ok(())
    }
}

/// Reads already validated little endian byte limbs into guarded integer storage.
fn integer(bytes: &[Goldilocks]) -> Zeroizing<u128> {
    let mut value = Zeroizing::new(0_u128);
    for (index, byte) in bytes.iter().enumerate() {
        *value |= (byte.as_canonical_u64() as u128) << (8 * index);
    }

    value
}
