//! Immutable coordinates for a packed key coefficient pair across absorption rows.

use super::super::eval_recipient_pair;
use p3_air::AirBuilder;
use p3_goldilocks::Goldilocks;

/// Links coefficient validity directly to the three byte cells absorbed into the key hash.
pub(super) struct KeyPair {
    /// Absorption phase containing the first byte and the comparison witnesses.
    pub(super) phase: usize,

    /// Difference witness slot among the pairs beginning in that phase.
    pub(super) slot: usize,

    /// Absolute absorption phase and local byte position for each packed source byte.
    pub(super) positions: [(usize, usize); 3],
}

impl KeyPair {
    /// Constrains a pair under its trusted selector without introducing duplicate source cells.
    pub(super) fn eval<AB: AirBuilder<F = Goldilocks>>(
        &self,
        builder: &mut AB,
        row: &[AB::Var; 909],
        next: &[AB::Var; 909],
        differences: &[AB::Var; 408],
        selector: AB::Expr,
    ) {
        let bytes = std::array::from_fn(|index| {
            let (phase, local) = self.positions[index];
            if phase == self.phase {
                row[43 + local]
            } else {
                next[43 + local]
            }
        });
        let bits = std::array::from_fn(|index| {
            let (phase, local) = self.positions[index];
            let source = if phase == self.phase { row } else { next };
            source[92 + local * 8..100 + local * 8].try_into().unwrap()
        });
        eval_recipient_pair(
            &mut builder.when(selector),
            &bytes,
            &bits,
            differences[self.slot * 24..(self.slot + 1) * 24]
                .as_chunks::<12>()
                .0
                .try_into()
                .unwrap(),
        );
    }
}
