//! Complete V1 note opening with private key, recipient binding, amount and blinding.

#[cfg(test)]
mod air;
#[cfg(any(test, feature = "prover"))]
mod assignment;
#[cfg(any(test, feature = "prover"))]
mod error;
#[cfg(test)]
mod fixture;
#[cfg(any(test, feature = "prover"))]
mod input;
mod key_pair;

#[cfg(test)]
pub(crate) use air::OpeningAir;
#[cfg(any(test, feature = "prover"))]
pub(crate) use error::OpeningError;
#[cfg(test)]
pub(crate) use fixture::OpeningFixture;
#[cfg(any(test, feature = "prover"))]
pub(crate) use input::Input;

use crate::gadgets::{eval_amount, poseidon2::ScheduledHash};
use key_pair::KeyPair;
use p3_air::AirBuilder;
use p3_field::PrimeCharacteristicRing;
use p3_goldilocks::Goldilocks;

/// Shared note relation whose caller owns the fixed schedule and expected statement links.
///
/// Recipient key bytes exist only in the hash rows, and the derived recipient digest remains
/// private while linking the complete key hash to the note commitment hash.
///
/// V1 note, address and suite identifiers are fixed relation constants, while ownership is
/// declared data and blinding freshness and recipient key possession are outside this claim.
pub(crate) struct Opening {
    /// Complete network, suite and key transcript.
    recipient: ScheduledHash<35>,

    /// Complete network, version, ownership, recipient, amount and blinding transcript.
    commitment: ScheduledHash<7>,

    /// Exact once-only coverage of all canonical coefficient pairs in the key hash.
    pairs: [KeyPair; 512],

    /// Number of difference slots occupied in each recipient absorption row.
    pair_counts: [usize; 35],
}

impl Opening {
    /// Ownership, amount, blinding, recipient digest, hash work and shared bound auxiliaries.
    pub(crate) const WIDTH: usize = 1493;

    /// Fixed circuit-selected cycle containing all phases and an idle suffix.
    pub(crate) const CYCLE: usize = 128;

    /// Seventy-seven active phase selectors followed by the cycle's last-row selector.
    pub(crate) const SELECTORS: usize = 78;

    /// Constructs public metadata without reading or allocating witness storage.
    pub(crate) fn new() -> Self {
        let recipient =
            ScheduledHash::<35>::new(b"houseki/v1/recipient/kem-key", &[64, 4, 1568]).unwrap();
        let commitment =
            ScheduledHash::<7>::new(b"houseki/v1/note/commitment", &[64, 4, 64, 64, 16, 32])
                .unwrap();
        let mut positions = [(usize::MAX, 0); 1568];
        for (phase, block) in recipient.blocks().iter().enumerate() {
            for (local, part, offset) in block.input_positions() {
                if part == 2 {
                    positions[offset] = (phase, local);
                }
            }
        }

        assert!(positions.iter().all(|(phase, _)| *phase < 35));
        let mut pair_counts = [0; 35];
        let pairs = std::array::from_fn(|index| {
            let positions: [_; 3] = positions[index * 3..index * 3 + 3].try_into().unwrap();
            let phase = positions[0].0;
            let slot = pair_counts[phase];
            pair_counts[phase] += 1;
            assert!(slot < 17 && positions[2].0 <= phase + 1);

            KeyPair {
                phase,
                slot,
                positions,
            }
        });

        Self {
            recipient,
            commitment,
            pairs,
            pair_counts,
        }
    }

    /// Borrows the constrained private amount for a circuit's public equality or conservation.
    pub(crate) fn amount<T>(row: &[T; 1493]) -> &[T; 16] {
        row[64..80].try_into().unwrap()
    }

    /// Enforces one complete opening under the caller's trusted 128-row cycle selectors.
    ///
    /// Selectors 0 through 76 identify their corresponding cycle rows, and selector 77 marks
    /// row 127 so independent openings may occupy consecutive cycles without sharing secrets.
    ///
    /// Expected network and commitment expressions must retain their intended values throughout
    /// the operation, whether sourced from public statement fields or other private constraints.
    pub(crate) fn eval<AB: AirBuilder<F = Goldilocks>>(
        &self,
        builder: &mut AB,
        row: &[AB::Var; 1493],
        next: &[AB::Var; 1493],
        selectors: &[AB::Expr],
        network: &[AB::Expr; 64],
        commitment: &[AB::Expr; 64],
    ) {
        assert_eq!(selectors.len(), Self::SELECTORS);
        for index in 0..176 {
            builder
                .when_transition()
                .when(AB::Expr::ONE - selectors[77].clone())
                .assert_eq(row[index], next[index]);
        }

        let hash = row[176..1085].try_into().unwrap();
        let next_hash = next[176..1085].try_into().unwrap();
        self.recipient
            .eval(builder, hash, next_hash, &selectors[..52]);
        self.commitment
            .eval(builder, hash, next_hash, &selectors[52..76]);

        for (phase, block) in self.recipient.blocks().iter().enumerate() {
            for (local, part, offset) in block.input_positions() {
                let expected = match part {
                    0 => Some(network[offset].clone()),
                    1 => Some(AB::Expr::from_bool(offset == 0)),
                    _ => None,
                };

                if let Some(expected) = expected {
                    builder
                        .when(selectors[phase].clone())
                        .assert_eq(row[219 + local], expected);
                }
            }
        }

        for pair in &self.pairs {
            pair.eval(
                builder,
                hash,
                next_hash,
                row[1085..].try_into().unwrap(),
                selectors[pair.phase].clone(),
            );
        }

        for (phase, block) in self.commitment.blocks().iter().enumerate() {
            for (local, part, offset) in block.input_positions() {
                let expected = match part {
                    0 => network[offset].clone(),
                    1 => AB::Expr::from_bool(offset == 0),
                    2 => row[offset].into(),
                    3 => row[112 + offset].into(),
                    4 => row[64 + offset].into(),
                    5 => row[80 + offset].into(),
                    _ => unreachable!("fixed note transcript has six parts"),
                };

                builder
                    .when(selectors[52 + phase].clone())
                    .assert_eq(row[219 + local], expected);
            }
        }

        for word in 0..16 {
            for byte in 0..4 {
                builder
                    .when(selectors[36 + word].clone())
                    .assert_eq(row[1033 + byte], row[112 + word * 4 + byte]);
                builder
                    .when(selectors[60 + word].clone())
                    .assert_eq(row[1033 + byte], commitment[word * 4 + byte].clone());
            }
        }

        let auxiliary = &row[1085..];
        eval_amount::<true, _>(
            &mut builder.when(selectors[76].clone()),
            Self::amount(row),
            auxiliary[16..144].as_chunks::<8>().0.try_into().unwrap(),
            auxiliary[..16].try_into().unwrap(),
            auxiliary[144..272].as_chunks::<8>().0.try_into().unwrap(),
            auxiliary[272..288].try_into().unwrap(),
            auxiliary[288],
        );

        for (phase, count) in self.pair_counts.iter().enumerate() {
            for value in &auxiliary[count * 24..] {
                builder.when(selectors[phase].clone()).assert_zero(*value);
            }
        }

        for value in &auxiliary[289..] {
            builder.when(selectors[76].clone()).assert_zero(*value);
        }

        let bounding: AB::Expr =
            selectors[..35].iter().cloned().sum::<AB::Expr>() + selectors[76].clone();
        for value in auxiliary {
            builder
                .when(AB::Expr::ONE - bounding.clone())
                .assert_zero(*value);
        }

        let hashing: AB::Expr = selectors[..76].iter().cloned().sum();
        for value in &row[176..1085] {
            builder
                .when(AB::Expr::ONE - hashing.clone())
                .assert_zero(*value);
        }
    }
}

/// Native vectors, independent validity and exact source coverage for the complete relation.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::gadgets::{Opening, OpeningAir, OpeningError, OpeningFixture, OpeningInput};
    use p3_air::check_all_constraints;
    use p3_field::PrimeCharacteristicRing;
    use p3_matrix::dense::RowMajorMatrix;

    /// Assigns all independent vectors with caller-owned buffers and no hidden allocation.
    #[test]
    fn complete_opening_matches_independent_native_vectors() {
        let air = OpeningAir::new();
        for case in 0..3 {
            let fixture = OpeningFixture::new(case);
            let mut rows = vec![Goldilocks::NEG_ONE; 128 * Opening::WIDTH];
            let input: OpeningInput<'_> = fixture.view();
            let (result, allocations, bytes) =
                crate::test_allocator::measure(|| air.opening.assign(input, &mut rows));
            result.unwrap();
            assert_eq!((allocations, bytes), (0, 0));

            assert!(
                check_all_constraints(
                    &air,
                    &RowMajorMatrix::new(rows, Opening::WIDTH),
                    &fixture.public,
                    Some(10)
                )
                .is_ok(),
                "native vector {case}"
            );
        }
    }

    /// Every byte, identifier, coefficient and amount is preflighted atomically.
    #[test]
    fn invalid_opening_inputs_preserve_destinations() {
        let opening = Opening::new();
        let mut rows = vec![Goldilocks::NEG_ONE; 128 * Opening::WIDTH];
        for offset in 0..1756 {
            let mut fixture = OpeningFixture::new(0);
            fixture.input[offset] = Goldilocks::from_u16(256);
            assert_eq!(
                opening.assign(fixture.view(), &mut rows),
                Err(OpeningError::InvalidByte)
            );
            assert!(rows.iter().all(|value| *value == Goldilocks::NEG_ONE));
        }

        for offset in (0..8).chain(72..76) {
            let mut fixture = OpeningFixture::new(0);
            fixture.input[offset] += Goldilocks::ONE;
            assert_eq!(
                opening.assign(fixture.view(), &mut rows),
                Err(OpeningError::UnsupportedFormat)
            );
        }

        for atoms in [0, houseki_types::Amount::MAX_ATOMS + 1, u128::MAX] {
            let mut fixture = OpeningFixture::new(0);
            fixture.input[1708..1724]
                .copy_from_slice(&atoms.to_le_bytes().map(Goldilocks::from_u8));
            assert!(matches!(
                opening.assign(fixture.view(), &mut rows),
                Err(OpeningError::InvalidAmount(_))
            ));
        }

        for pair in 0..512 {
            for bytes in [[1, 13, 0], [0, 16, 208]] {
                let mut fixture = OpeningFixture::new(0);
                fixture.input[140 + pair * 3..143 + pair * 3]
                    .copy_from_slice(&bytes.map(Goldilocks::from_u8));
                assert!(matches!(
                    opening.assign(fixture.view(), &mut rows),
                    Err(OpeningError::InvalidRecipient(_))
                ));
            }
        }

        let mut fixture = OpeningFixture::new(0);
        fixture.input[0] = Goldilocks::NEG_ONE;
        for length in [0, 1, rows.len() - 1] {
            assert_eq!(
                opening.assign(fixture.view(), &mut rows[..length]),
                Err(OpeningError::ShapeMismatch)
            );
        }

        assert!(rows.iter().all(|value| *value == Goldilocks::NEG_ONE));
    }

    /// Immutable pair metadata covers every polynomial byte once, including adjacent-row triples.
    #[test]
    fn coefficient_sources_cover_the_complete_absorbed_key() {
        let opening = Opening::new();
        let mut expected = Vec::new();
        for (phase, block) in opening.recipient.blocks().iter().enumerate() {
            for (local, part, offset) in block.input_positions() {
                if part == 2 && offset < 1536 {
                    assert_eq!(expected.len(), offset);
                    expected.push((phase, local));
                }
            }
        }

        assert_eq!(expected.len(), 1536);
        assert!(
            opening
                .pairs
                .iter()
                .any(|pair| pair.positions[0].0 != pair.positions[2].0)
        );
        for (index, pair) in opening.pairs.iter().enumerate() {
            assert_eq!(pair.positions, expected[index * 3..index * 3 + 3]);
            assert_eq!(pair.phase, pair.positions[0].0);
            assert!(pair.slot < opening.pair_counts[pair.phase]);
        }

        for phase in 0..35 {
            let slots: Vec<_> = opening
                .pairs
                .iter()
                .filter(|pair| pair.phase == phase)
                .map(|pair| pair.slot)
                .collect();
            assert_eq!(slots, (0..opening.pair_counts[phase]).collect::<Vec<_>>());
        }
    }

    /// Recomputing both hashes cannot bypass canonical coefficients or substitute the private digest.
    #[test]
    fn coordinated_hashes_still_require_key_validity_and_binding() {
        let air = OpeningAir::new();
        let crossing = air
            .opening
            .pairs
            .iter()
            .position(|pair| pair.positions[0].0 != pair.positions[2].0)
            .unwrap();
        for pair in [0, crossing, 511] {
            for bytes in [[1, 13, 0], [0, 16, 208]] {
                let mut fixture = OpeningFixture::new(0);
                let mut rows = vec![Goldilocks::ZERO; 128 * Opening::WIDTH];
                air.opening.assign(fixture.view(), &mut rows).unwrap();
                fixture.input[140 + pair * 3..143 + pair * 3]
                    .copy_from_slice(&bytes.map(Goldilocks::from_u8));
                fixture.rehash(&air.opening, &mut rows, false);

                assert!(
                    !air.valid_row(&rows, &fixture.public, air.opening.pairs[pair].phase),
                    "pair {pair}"
                );
                assert!(air.valid_row(&rows, &fixture.public, 60));
            }
        }

        let mut fixture = OpeningFixture::new(0);
        let mut rows = vec![Goldilocks::ZERO; 128 * Opening::WIDTH];
        air.opening.assign(fixture.view(), &mut rows).unwrap();
        fixture.rehash(&air.opening, &mut rows, true);
        assert!(!air.valid_row(&rows, &fixture.public, 36));
        assert!(air.valid_row(&rows, &fixture.public, 60));
    }

    /// A coordinated hash of zero or excessive amount still violates the independent amount phase.
    #[test]
    fn coordinated_hashes_still_require_positive_bounded_amounts() {
        let air = OpeningAir::new();
        for atoms in [0, houseki_types::Amount::MAX_ATOMS + 1, u128::MAX] {
            let mut fixture = OpeningFixture::new(0);
            let mut rows = vec![Goldilocks::ZERO; 128 * Opening::WIDTH];
            air.opening.assign(fixture.view(), &mut rows).unwrap();
            fixture.input[1708..1724]
                .copy_from_slice(&atoms.to_le_bytes().map(Goldilocks::from_u8));
            fixture.rehash(&air.opening, &mut rows, false);

            assert!(!air.valid_row(&rows, &fixture.public, 76));
            assert!(air.valid_row(&rows, &fixture.public, 60));
        }
    }

    /// Public endpoints, private continuity, transcript links and idle storage cannot be substituted.
    #[test]
    fn opening_rejects_changed_endpoints_links_and_idle_cells() {
        let air = OpeningAir::new();
        let fixture = OpeningFixture::new(0);
        let mut rows = vec![Goldilocks::ZERO; 128 * Opening::WIDTH];
        air.opening.assign(fixture.view(), &mut rows).unwrap();
        for index in 0..144 {
            let mut public = fixture.public;
            public[index] += Goldilocks::ONE;
            let phase = if index < 64 {
                air.opening
                    .recipient
                    .blocks()
                    .iter()
                    .position(|block| {
                        block
                            .input_positions()
                            .any(|(_, part, offset)| part == 0 && offset == index)
                    })
                    .unwrap()
            } else if index < 80 {
                76
            } else {
                60 + (index - 80) / 4
            };
            assert!(!air.valid_row(&rows, &public, phase), "public byte {index}");
        }

        for (phase, column) in [
            (0, 0),
            (51, 64),
            (52, 80),
            (59, 112),
            (75, 175),
            (126, 0),
            (0, 219),
            (34, 267),
            (52, 219),
            (58, 267),
            (36, 1033),
            (76, 176),
            (77, 1085),
            (127, 1492),
            (127, 176),
        ] {
            let index = phase * Opening::WIDTH + column;
            rows[index] += Goldilocks::ONE;
            assert!(
                !air.valid_row(&rows, &fixture.public, phase),
                "cell {phase}:{column}"
            );
            rows[index] -= Goldilocks::ONE;
        }
    }

    /// Private continuity ends only at the trusted cycle boundary between independent openings.
    #[test]
    fn independent_cycles_do_not_share_private_prefixes() {
        let air = OpeningAir::new();
        let fixture = OpeningFixture::new(0);
        let mut rows = vec![Goldilocks::ZERO; 256 * Opening::WIDTH];
        air.opening.assign(fixture.view(), &mut rows).unwrap();
        rows[128 * Opening::WIDTH] += Goldilocks::ONE;

        assert!(air.valid_row(&rows, &fixture.public, 127));
        assert!(!air.valid_row(&rows, &fixture.public, 128));
    }
}
