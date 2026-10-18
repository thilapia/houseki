//! Test composition sharing exact block cells between transcript framing and the sponge.

use super::SpongeAir;
use crate::gadgets::poseidon2::Frame;
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_goldilocks::Goldilocks;

/// Composes an eight byte part under a registered application hash domain.
pub(crate) struct FramedSpongeAir;

impl FramedSpongeAir {
    /// Selects immutable test metadata with two complete padded input blocks.
    fn frame() -> Frame {
        Frame::new(b"houseki/v1/recipient/kem-key", &[8]).unwrap()
    }

    /// Copies public fixture bytes and assigns framing and sponge cells without duplicates.
    pub(crate) fn assign_row(input: &[Goldilocks; 8], row: &mut [Goldilocks]) {
        let (bytes, rest) = row.split_at_mut(8);
        bytes.copy_from_slice(input);

        let (bits, rest) = rest.split_at_mut(64);
        let (words, tail) = rest.split_at_mut(14);
        Self::frame()
            .assign(&[bytes], &mut [bits.as_chunks_mut::<8>().0], words)
            .unwrap();

        SpongeAir::new(2).assign_tail(words, tail);
    }

    /// Reassigns all sponge witnesses after a public test deliberately forges a framed word.
    pub(crate) fn reassign_sponge(row: &mut [Goldilocks]) {
        let (frame, tail) = row.split_at_mut(86);
        SpongeAir::new(2).assign_tail(&frame[72..], tail);
    }
}

impl BaseAir<Goldilocks> for FramedSpongeAir {
    /// Stores eight bytes, their bits, fourteen shared words and three permutations.
    fn width(&self) -> usize {
        72 + SpongeAir::new(2).width()
    }

    /// Keeps the composed test relation entirely within one row.
    fn main_next_row_columns(&self) -> Vec<usize> {
        Vec::new()
    }

    /// Reserves the permutation's cubic equations alongside quadratic byte ranges.
    fn max_constraint_degree(&self) -> Option<usize> {
        Some(3)
    }

    /// Exposes input bytes and eleven field samples without intermediate hash state.
    fn num_public_values(&self) -> usize {
        19
    }
}

impl<AB: AirBuilder<F = Goldilocks>> Air<AB> for FramedSpongeAir {
    /// Constrains framing and absorption over the same cells before binding both endpoints.
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let row = main.current_slice();

        Self::frame().eval(
            builder,
            &[&row[..8]],
            &[row[8..72].as_chunks::<8>().0],
            &row[72..86],
        );
        SpongeAir::new(2).eval_row(builder, &row[72..]);

        for (index, value) in row[..8].iter().chain(&row[1034..]).enumerate() {
            let expected = builder.public_values()[index];
            builder.assert_eq(*value, expected);
        }
    }
}

/// Shared cell linkage under adversarial reassignment of the downstream sponge.
#[cfg(test)]
mod tests {
    use super::*;
    use p3_air::check_all_constraints;
    use p3_field::PrimeCharacteristicRing;
    use p3_matrix::dense::RowMajorMatrix;

    /// Checks the composed relation with public endpoints following the supplied witness.
    fn accepted(row: &[Goldilocks]) -> bool {
        let public: Vec<_> = row[..8].iter().chain(&row[1034..]).copied().collect();
        let matrix = RowMajorMatrix::new(row.repeat(2), 1045);

        check_all_constraints(&FramedSpongeAir, &matrix, &public, Some(8)).is_ok()
    }

    /// Metadata and padding forgeries cannot be hidden by an otherwise valid sponge witness.
    #[test]
    fn reframing_cannot_be_bypassed_by_reassigning_the_sponge() {
        let mut original = vec![Goldilocks::NEG_ONE; 1045];
        FramedSpongeAir::assign_row(&[Goldilocks::from_u8(0xa3); 8], &mut original);
        assert!(accepted(&original));

        for index in 72..86 {
            let mut row = original.clone();
            row[index] += Goldilocks::ONE;
            FramedSpongeAir::reassign_sponge(&mut row);

            assert!(!accepted(&row), "word {}", index - 72);
        }
    }

    /// A valid replacement byte and its bit decomposition cannot reuse old framed words.
    #[test]
    fn changed_byte_is_linked_to_the_absorbed_words() {
        let mut row = vec![Goldilocks::ZERO; 1045];
        FramedSpongeAir::assign_row(&[Goldilocks::ZERO; 8], &mut row);
        row[0] = Goldilocks::ONE;
        row[8] = Goldilocks::ONE;

        assert!(!accepted(&row));
    }
}
