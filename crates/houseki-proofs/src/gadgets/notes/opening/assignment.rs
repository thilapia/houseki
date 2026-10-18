//! Validated private opening assignment into caller-owned trace cycles.

use super::{Input, Opening, OpeningError};
use crate::gadgets::{Scratch, assign_amount, notes::assign_recipient_pair};
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_goldilocks::Goldilocks;
use zeroize::Zeroizing;

impl Opening {
    /// Preflights complete inputs and then overwrites every cell without allocating.
    ///
    /// Shape errors precede invalid byte cells, unsupported identifiers, invalid positive amount
    /// and noncanonical key coefficients, with every failure leaving all destinations unchanged.
    ///
    /// The caller owns input and trace cleanup, and guarded local storage retains intermediates
    /// only until assignment returns without exposing the private recipient digest.
    pub(crate) fn assign(
        &self,
        input: Input<'_>,
        rows: &mut [Goldilocks],
    ) -> Result<(), OpeningError> {
        if rows.is_empty() || !rows.len().is_multiple_of(Self::CYCLE * Self::WIDTH) {
            return Err(OpeningError::ShapeMismatch);
        }

        for part in [
            input.version.as_slice(),
            input.recipient.as_slice(),
            input.amount.as_slice(),
            input.blinding.as_slice(),
        ] {
            for value in part {
                let word = Zeroizing::new(value.as_canonical_u64());
                if *word > 255 {
                    return Err(OpeningError::InvalidByte);
                }
            }
        }

        for identifier in [
            input.version.as_slice(),
            &input.recipient[..4],
            &input.recipient[68..72],
        ] {
            for (index, value) in identifier.iter().enumerate() {
                if *value != Goldilocks::from_bool(index == 0) {
                    return Err(OpeningError::UnsupportedFormat);
                }
            }
        }

        let mut amount = Scratch::<289>::default();
        assign_amount_auxiliary(input.amount, &mut amount)?;
        let mut pair_bits = Scratch::<24>::default();
        let mut differences = Scratch::<24>::default();
        for pair in input.recipient[136..1672].as_chunks::<3>().0 {
            assign_recipient_pair(
                pair,
                pair_bits.as_chunks_mut::<8>().0.try_into().unwrap(),
                differences.as_chunks_mut::<12>().0.try_into().unwrap(),
            )?;
        }

        let network = &input.recipient[4..68];
        let suite = &input.recipient[68..72];
        let ownership = &input.recipient[72..136];
        let key = &input.recipient[136..];
        let mut binding = Scratch::<64>::default();
        for cycle in rows.as_chunks_mut::<{ Self::CYCLE * Self::WIDTH }>().0 {
            cycle.fill(Goldilocks::ZERO);
            self.recipient
                .assign(&[network, suite, key], &mut cycle[176..], Self::WIDTH)
                .expect("complete opening inputs and storage were validated");
            self.recipient
                .copy_digest(&cycle[176..], Self::WIDTH, &mut binding);

            for row in cycle.as_chunks_mut::<1493>().0 {
                row[..64].copy_from_slice(ownership);
                row[64..80].copy_from_slice(input.amount);
                row[80..112].copy_from_slice(input.blinding);
                row[112..176].copy_from_slice(&binding[..]);
            }

            for (index, pair) in self.pairs.iter().enumerate() {
                let start = pair.phase * Self::WIDTH + 1085 + pair.slot * 24;
                assign_recipient_pair(
                    key[index * 3..index * 3 + 3].try_into().unwrap(),
                    pair_bits.as_chunks_mut::<8>().0.try_into().unwrap(),
                    cycle[start..start + 24]
                        .as_chunks_mut::<12>()
                        .0
                        .try_into()
                        .unwrap(),
                )
                .expect("all recipient coefficients were validated");
            }

            self.commitment
                .assign(
                    &[
                        network,
                        input.version,
                        ownership,
                        &binding[..],
                        input.amount,
                        input.blinding,
                    ],
                    &mut cycle[52 * Self::WIDTH + 176..],
                    Self::WIDTH,
                )
                .expect("complete opening inputs and storage were validated");
            cycle[76 * Self::WIDTH + 1085..76 * Self::WIDTH + 1374].copy_from_slice(&amount[..]);
        }

        Ok(())
    }
}

/// Reuses the amount owner while storing only auxiliaries beside the shared private amount.
pub(super) fn assign_amount_auxiliary(
    amount: &[Goldilocks; 16],
    destination: &mut [Goldilocks; 289],
) -> Result<(), OpeningError> {
    let (remainder, rest) = destination.split_at_mut(16);
    let (bits, rest) = rest.split_at_mut(128);
    let (remainder_bits, rest) = rest.split_at_mut(128);
    let (carries, inverse) = rest.split_at_mut(16);
    assign_amount::<true>(
        amount,
        bits.as_chunks_mut::<8>().0.try_into().unwrap(),
        remainder.try_into().unwrap(),
        remainder_bits.as_chunks_mut::<8>().0.try_into().unwrap(),
        carries.try_into().unwrap(),
        &mut inverse[0],
    )?;

    Ok(())
}
