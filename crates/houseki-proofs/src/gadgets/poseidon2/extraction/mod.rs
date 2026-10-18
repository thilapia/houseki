//! Canonical low 512 bits of the integer represented by eleven base modulus samples.

#[cfg(test)]
mod air;
mod coefficients;
mod profile;
#[cfg(test)]
mod row_air;
mod samples;
mod word;

#[cfg(test)]
pub(crate) use row_air::ExtractionRowAir;
pub(super) use samples::eval as eval_samples;
pub(super) use word::{carry, eval as eval_word, eval_encoded_bytes as eval_word_bytes};

#[cfg(any(test, feature = "prover"))]
pub(super) use samples::assign as assign_samples;
#[cfg(any(test, feature = "prover"))]
pub(super) use word::assign as assign_word;

use super::profile::SAMPLES;
use p3_air::AirBuilder;
use p3_field::PrimeCharacteristicRing;
use p3_goldilocks::Goldilocks;
use profile::{CARRY_BITS, DIGEST_BYTES, ENCODING, WORDS};
#[cfg(any(test, feature = "prover"))]
use zeroize::Zeroizing;

/// Constrains the little endian low 512 bits of the eleven canonical base modulus digits.
///
/// All canonical sample bounds, output byte ranges and signed carries belong to this relation.
///
/// The initial carry is zero and the carry above bit 511 is discarded only after its equation
/// has been enforced, preserving native truncation rather than requiring no overflow.
///
/// Callers own trace storage and must link the supplied samples to the sponge's exact outputs.
pub(super) fn eval<AB: AirBuilder<F = Goldilocks>>(
    builder: &mut AB,
    values: &[AB::Var; SAMPLES],
    encodings: &[[AB::Var; ENCODING]; SAMPLES],
    digest: &[AB::Var; DIGEST_BYTES],
    bits: &[[AB::Var; 8]; DIGEST_BYTES],
    carries: &[[AB::Var; CARRY_BITS]; WORDS],
) {
    samples::eval(builder, values, encodings);

    let mut incoming = AB::Expr::ZERO;
    for (column, carry) in carries.iter().enumerate() {
        incoming = word::eval(
            builder,
            encodings,
            column,
            incoming,
            &digest.as_chunks::<4>().0[column],
            &bits.as_chunks::<4>().0[column],
            carry,
        );
    }
}

/// Assigns canonical samples, output bytes and signed carries into caller owned cells.
///
/// Every field input is accepted and every destination is overwritten without allocation.
///
/// Integer temporaries clear on return, while the caller retains cleanup responsibility for
/// borrowed sample and destination storage.
///
/// Assignment does not establish constraints, so the consuming AIR must also call [`eval`].
#[cfg(any(test, feature = "prover"))]
pub(super) fn assign(
    values: &[Goldilocks; SAMPLES],
    encodings: &mut [[Goldilocks; ENCODING]; SAMPLES],
    digest: &mut [Goldilocks; DIGEST_BYTES],
    bits: &mut [[Goldilocks; 8]; DIGEST_BYTES],
    carries: &mut [[Goldilocks; CARRY_BITS]; WORDS],
) {
    samples::assign(values, encodings);

    let mut incoming = Zeroizing::new(0_i64);
    for (column, carry) in carries.iter_mut().enumerate() {
        word::assign(
            values,
            column,
            &mut incoming,
            &mut digest.as_chunks_mut::<4>().0[column],
            &mut bits.as_chunks_mut::<4>().0[column],
            carry,
        );
    }
}

/// Independent integer vectors with carries and deliberate truncation above bit 511.
#[cfg(test)]
mod tests {
    use super::air::ExtractionAir;
    use super::*;
    use p3_air::{ConstraintReport, check_all_constraints};
    use p3_field::{Field, PrimeCharacteristicRing, PrimeField64};
    use p3_matrix::dense::RowMajorMatrix;

    /// Checks supplied witnesses with public endpoints following any attempted forgery.
    fn evaluate(row: &[Goldilocks; 1641]) -> ConstraintReport {
        let public: Vec<_> = row[..11].iter().chain(&row[825..889]).copied().collect();
        let matrix = RowMajorMatrix::new(row.repeat(2), 1641);

        check_all_constraints(&ExtractionAir, &matrix, &public, Some(128))
    }

    /// Starts all cells occupied to detect assignment omissions independently of default zeros.
    fn assigned(values: [u64; 11]) -> [Goldilocks; 1641] {
        let mut row = [Goldilocks::NEG_ONE; 1641];
        ExtractionAir::assign_row(&values.map(Goldilocks::from_u64), &mut row);

        row
    }

    /// Rewrites one public fixture byte and its bits without changing other witnesses.
    fn write_byte(row: &mut [Goldilocks; 1641], byte: usize, bits: usize, value: u8) {
        row[byte] = Goldilocks::from_u8(value);
        for index in 0..8 {
            row[bits + index] = Goldilocks::from_u8((value >> index) & 1);
        }
    }

    /// Recomputes integer outputs from deliberately noncanonical public test integers.
    fn rewrite_tail(row: &mut [Goldilocks; 1641], values: &[u64; 11]) {
        let mut incoming = 0_i64;
        for column in 0..16 {
            let mut total = incoming;
            for (sample, value) in values.iter().enumerate() {
                for half in 0..2 {
                    if column >= half {
                        total += i64::from(coefficients::coefficient(sample, column - half))
                            * ((*value >> (half * 32)) as u32 as i64);
                    }
                }
            }

            for (byte, value) in (total.rem_euclid(profile::RADIX) as u32)
                .to_le_bytes()
                .iter()
                .enumerate()
            {
                write_byte(
                    row,
                    825 + column * 4 + byte,
                    889 + (column * 4 + byte) * 8,
                    *value,
                );
            }

            incoming = total.div_euclid(profile::RADIX);
            for bit in 0..15 {
                row[1401 + column * 15 + bit] =
                    Goldilocks::from_i64(((incoming + profile::BIAS) >> bit) & 1);
            }
        }
    }

    /// Canonicality rejects modulus aliases even with completely consistent integer outputs.
    #[test]
    fn noncanonical_samples_cannot_change_the_integer_digest() {
        for sample in 0..11 {
            for alias in [Goldilocks::ORDER_U64, Goldilocks::ORDER_U64 + 1, u64::MAX] {
                let mut values = [0; 11];
                values[sample] = alias;
                let mut row = assigned(values);
                let start = 11 + sample * 74;
                for (index, byte) in alias.to_le_bytes().iter().enumerate() {
                    write_byte(&mut row, start + index, start + 8 + index * 8, *byte);
                }

                row[start + 72] = Goldilocks::ONE;
                row[start + 73] = Goldilocks::ZERO;
                rewrite_tail(&mut row, &values);
                let report = evaluate(&row);

                assert!(!report.is_ok());
                assert!(
                    report
                        .failures
                        .iter()
                        .all(|failure| failure.constraint == sample * 78 + 76)
                );
            }
        }
    }

    /// Modular carry forgeries can satisfy every arithmetic equality but fail Boolean bounds.
    #[test]
    fn coordinated_modular_carries_cannot_forge_a_digest_byte() {
        let original = assigned([Goldilocks::ORDER_U64 - 1; 11]);
        let inverse = Goldilocks::from_i64(profile::RADIX).inverse();
        for column in 0..16 {
            let mut row = original;
            let old = row[825 + column * 4].as_canonical_u64() as u8;
            let new = if old == 0 { 1 } else { old - 1 };
            write_byte(&mut row, 825 + column * 4, 889 + column * 32, new);
            let mut delta = -Goldilocks::from_i64(i64::from(new) - i64::from(old));
            for later in column..16 {
                delta *= inverse;
                row[1401 + later * 15] += delta;
            }

            let report = evaluate(&row);

            assert!(!report.is_ok());
            assert!(report.failures.iter().all(|failure| {
                failure.constraint >= 858 && (36..51).contains(&((failure.constraint - 858) % 52))
            }));
        }
    }

    /// All sample, canonical byte, helper, digest and carry cells affect the relation.
    #[test]
    fn every_extraction_cell_is_constrained() {
        for values in [
            [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
            [Goldilocks::ORDER_U64 - 1; 11],
        ] {
            let original = assigned(values);
            assert!(evaluate(&original).is_ok());

            for index in 0..original.len() {
                let mut row = original;
                row[index] += Goldilocks::ONE;

                assert!(!evaluate(&row).is_ok(), "cell {index}");
            }
        }
    }

    /// Native redundant field representations are canonicalized before integer extraction.
    #[test]
    fn zero_aliases_and_final_overflow_follow_native_semantics() {
        for word in [
            0,
            Goldilocks::ORDER_U64,
            Goldilocks::ORDER_U64 - 1,
            u64::MAX,
        ] {
            let row = assigned([word; 11]);

            assert!(evaluate(&row).is_ok());
            if word == 0 || word == Goldilocks::ORDER_U64 {
                assert_eq!(&row[825..889], &[Goldilocks::ZERO; 64]);
            }
        }

        let row = assigned([Goldilocks::ORDER_U64 - 1; 11]);
        assert_ne!(
            word::carry::<Goldilocks>(row[1626..1641].try_into().unwrap()),
            Goldilocks::ZERO
        );
    }

    /// Matches the native committed Python big-integer vectors rather than field concatenation.
    #[test]
    fn extraction_matches_independent_integer_vectors() {
        let modulus = Goldilocks::ORDER_U64;
        for (values, expected) in [
            (
                [modulus - 1; 11],
                concat!(
                    "00000000f5ffffff41000000edfeffff6f0300001bf7ffff34130000aedcffff",
                    "1238000071b2ffff035e0000cb9bffff035e000071b2ffff12380000aedcffff"
                ),
            ),
            (
                [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
                concat!(
                    "370000007ffeffffa80600009aeaffffa7360000048dffff92cc0000bfc7feff",
                    "3a9d01002e23feff56e10100d556fefffd4701002524ffff087f00008cc1ffff"
                ),
            ),
            (
                [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, modulus - 1],
                concat!(
                    "00000000ffffffff0a000000bfffffff08010000c7fcffff1208000032efffff",
                    "a51d00000fd3ffff0a3b000069bcffff96430000f5c4fffff02c00005ae2ffff"
                ),
            ),
        ] {
            let mut encodings = [[Goldilocks::NEG_ONE; 74]; 11];
            let mut digest = [Goldilocks::NEG_ONE; 64];
            let mut bits = [[Goldilocks::NEG_ONE; 8]; 64];
            let mut carries = [[Goldilocks::NEG_ONE; 15]; 16];
            assign(
                &values.map(Goldilocks::from_u64),
                &mut encodings,
                &mut digest,
                &mut bits,
                &mut carries,
            );
            let actual: String = digest
                .iter()
                .map(|value| format!("{:02x}", value.as_canonical_u64()))
                .collect();

            assert_eq!(actual, expected);
        }
    }
}
