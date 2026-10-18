//! Payment-specific compact note opening using already constrained key bits.

#[cfg(test)]
mod air;
#[cfg(any(test, feature = "prover"))]
mod assignment;
mod coefficient;
#[cfg(test)]
mod fixture;

use super::{Selectors, key_pair::KeyPair};
use crate::gadgets::{eval_amount, poseidon2::CompactHash};
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
pub(crate) struct CompactOpening {
    /// Complete network, suite and key transcript.
    recipient: CompactHash<35>,

    /// Complete network, version, ownership, recipient, amount and blinding transcript.
    commitment: CompactHash<7>,

    /// Exact once-only coverage of all canonical coefficient pairs in the key hash.
    pairs: [KeyPair; 512],

    /// Number of difference slots occupied in each recipient absorption row.
    pair_counts: [usize; 35],
}

impl CompactOpening {
    /// Ownership, amount, blinding, recipient digest, hash work and shared bound auxiliaries.
    pub(crate) const WIDTH: usize = 1001;

    /// Fixed circuit-selected cycle containing all phases and an idle suffix.
    pub(crate) const CYCLE: usize = 128;

    /// Seventy-seven active phase selectors followed by the cycle's last-row selector.
    pub(crate) const SELECTORS: usize = 78;

    /// Constructs public metadata without reading or allocating witness storage.
    pub(crate) fn new() -> Self {
        let recipient =
            CompactHash::<35>::new(b"houseki/v1/recipient/kem-key", &[64, 4, 1568]).unwrap();
        let commitment =
            CompactHash::<7>::new(b"houseki/v1/note/commitment", &[64, 4, 64, 64, 16, 32]).unwrap();
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
    pub(crate) fn amount<T>(row: &[T; 1001]) -> &[T; 16] {
        row[64..80].try_into().unwrap()
    }

    /// Enforces one complete opening under the caller's trusted 128-row cycle selectors.
    ///
    /// Selectors 0 through 76 identify their corresponding cycle rows, and selector 77 marks
    /// row 127 so independent openings may occupy consecutive cycles without sharing secrets.
    ///
    /// Expected network and commitment expressions must retain their intended values throughout
    /// the operation, whether sourced from public statement fields or other private constraints.
    #[cfg(test)]
    pub(crate) fn eval<AB: AirBuilder<F = Goldilocks>>(
        &self,
        builder: &mut AB,
        row: &[AB::Var; 1001],
        next: &[AB::Var; 1001],
        selectors: &[AB::Expr],
        network: &[AB::Expr; 64],
        commitment: &[AB::Expr; 64],
    ) {
        self.eval_selected(
            builder,
            row,
            next,
            Selectors {
                phases: selectors,
                active: AB::Expr::ONE,
            },
            network,
            commitment,
        );
    }

    /// Constrains an opening only during its trusted invocation without multiplying every equation.
    ///
    /// Inactive phases contribute no opening constraints, so the caller may reuse the work cells
    /// for other operations and must constrain them through those operations or padding rules.
    pub(crate) fn eval_selected<AB: AirBuilder<F = Goldilocks>>(
        &self,
        builder: &mut AB,
        row: &[AB::Var; 1001],
        next: &[AB::Var; 1001],
        selected: Selectors<'_, AB::Expr>,
        network: &[AB::Expr; 64],
        commitment: &[AB::Expr; 64],
    ) {
        let selectors = selected.phases;
        assert_eq!(selectors.len(), Self::SELECTORS);
        for index in 0..176 {
            builder
                .when_transition()
                .when(selected.active.clone() - selectors[77].clone())
                .assert_eq(row[index], next[index]);
        }

        let hash = row[176..967].try_into().unwrap();
        let next_hash = next[176..967].try_into().unwrap();
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
            self.eval_pair(
                pair,
                builder,
                hash,
                next_hash,
                row[967..].try_into().unwrap(),
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
                    .assert_eq(row[373 + byte], row[112 + word * 4 + byte]);
                builder
                    .when(selectors[60 + word].clone())
                    .assert_eq(row[373 + byte], commitment[word * 4 + byte].clone());
            }
        }

        let auxiliary = &row[176..465];
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
            for value in &row[967 + count * 2..] {
                builder.when(selectors[phase].clone()).assert_zero(*value);
            }
        }

        for value in &row[465..967] {
            builder.when(selectors[76].clone()).assert_zero(*value);
        }

        let bounding: AB::Expr = selectors[..35].iter().cloned().sum();
        for value in &row[967..] {
            builder
                .when(selected.active.clone() - bounding.clone())
                .assert_zero(*value);
        }

        let hashing: AB::Expr = selectors[..76].iter().cloned().sum();
        for value in &row[176..967] {
            builder
                .when(selected.active.clone() - hashing.clone() - selectors[76].clone())
                .assert_zero(*value);
        }
    }

    /// Reuses the canonical absorption bits to bound both packed twelve-bit coefficients.
    fn eval_pair<AB: AirBuilder<F = Goldilocks>>(
        &self,
        pair: &KeyPair,
        builder: &mut AB,
        row: &[AB::Var; 791],
        next: &[AB::Var; 791],
        helpers: &[AB::Var; 34],
        selector: AB::Expr,
    ) {
        let bytes: [[AB::Var; 8]; 3] = std::array::from_fn(|byte| {
            let (phase, local) = pair.positions[byte];
            let source = if phase == pair.phase { row } else { next };
            std::array::from_fn(|bit| source[92 + local * 8 + bit])
        });
        let first = std::array::from_fn(|bit| {
            if bit < 8 {
                bytes[0][bit]
            } else {
                bytes[1][bit - 8]
            }
        });
        let second = std::array::from_fn(|bit| {
            if bit < 4 {
                bytes[1][bit + 4]
            } else {
                bytes[2][bit - 4]
            }
        });
        coefficient::eval(
            &mut builder.when(selector.clone()),
            &first,
            helpers[pair.slot * 2],
        );
        coefficient::eval(
            &mut builder.when(selector),
            &second,
            helpers[pair.slot * 2 + 1],
        );
    }
}

/// Differential and independent validity checks for the compact payment opening.
#[cfg(test)]
mod tests {
    use super::{CompactOpening, air::CompactOpeningAir};
    use crate::gadgets::OpeningFixture;
    use p3_air::check_all_constraints;
    use p3_field::PrimeCharacteristicRing;
    use p3_goldilocks::Goldilocks;
    use p3_matrix::dense::RowMajorMatrix;

    /// Every retained native commitment vector satisfies the narrower complete relation.
    #[test]
    fn compact_opening_preserves_native_vectors() {
        let air = CompactOpeningAir::new();
        assert_eq!(CompactOpening::WIDTH, 1001);
        for case in 0..3 {
            let fixture = OpeningFixture::new(case);
            let mut rows = vec![Goldilocks::ZERO; 128 * CompactOpening::WIDTH];
            let (result, allocations, bytes) =
                crate::test_allocator::measure(|| air.opening.assign(fixture.view(), &mut rows));
            result.unwrap();
            assert_eq!((allocations, bytes), (0, 0));
            assert!(
                check_all_constraints(
                    &air,
                    &RowMajorMatrix::new(rows, CompactOpening::WIDTH),
                    &fixture.public,
                    Some(10)
                )
                .is_ok()
            );
        }
    }

    /// Recomputing both hashes cannot bypass canonical coefficients or substitute the private digest.
    #[test]
    fn coordinated_hashes_still_require_key_validity_and_binding() {
        let air = CompactOpeningAir::new();
        let crossing = air
            .opening
            .pairs
            .iter()
            .position(|pair| pair.positions[0].0 != pair.positions[2].0)
            .unwrap();
        for pair in [0, crossing, 511] {
            for bytes in [[1, 13, 0], [0, 16, 208]] {
                let mut fixture = OpeningFixture::new(0);
                let mut rows = vec![Goldilocks::ZERO; 128 * CompactOpening::WIDTH];
                air.opening.assign(fixture.view(), &mut rows).unwrap();
                fixture.input[140 + pair * 3..143 + pair * 3]
                    .copy_from_slice(&bytes.map(Goldilocks::from_u8));
                fixture.rehash_compact(&air.opening, &mut rows, false);

                assert!(
                    !air.valid_row(&rows, &fixture.public, air.opening.pairs[pair].phase),
                    "pair {pair}"
                );
                assert!(air.valid_row(&rows, &fixture.public, 60));
            }
        }

        let mut fixture = OpeningFixture::new(0);
        let mut rows = vec![Goldilocks::ZERO; 128 * CompactOpening::WIDTH];
        air.opening.assign(fixture.view(), &mut rows).unwrap();
        fixture.rehash_compact(&air.opening, &mut rows, true);
        assert!(!air.valid_row(&rows, &fixture.public, 36));
        assert!(air.valid_row(&rows, &fixture.public, 60));
    }

    /// A coordinated hash of zero or excessive amount still violates the independent amount phase.
    #[test]
    fn coordinated_hashes_still_require_positive_bounded_amounts() {
        let air = CompactOpeningAir::new();
        for atoms in [0, houseki_types::Amount::MAX_ATOMS + 1, u128::MAX] {
            let mut fixture = OpeningFixture::new(0);
            let mut rows = vec![Goldilocks::ZERO; 128 * CompactOpening::WIDTH];
            air.opening.assign(fixture.view(), &mut rows).unwrap();
            fixture.input[1708..1724]
                .copy_from_slice(&atoms.to_le_bytes().map(Goldilocks::from_u8));
            fixture.rehash_compact(&air.opening, &mut rows, false);

            assert!(!air.valid_row(&rows, &fixture.public, 76));
            assert!(air.valid_row(&rows, &fixture.public, 60));
        }
    }
}
