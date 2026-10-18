//! Exact ML-KEM coefficient bound using Boolean bits already constrained by absorption.

use p3_air::AirBuilder;
use p3_goldilocks::Goldilocks;

/// Requires a twelve-bit integer at most 3328 with one product helper.
///
/// Values below 3072 pass directly. For larger values bit nine must be zero, and bit eight
/// may be one only when all eight lower bits are zero, yielding exactly the interval to 3328.
pub(super) fn eval<AB: AirBuilder<F = Goldilocks>>(
    builder: &mut AB,
    bits: &[AB::Var; 12],
    helper: AB::Var,
) {
    builder.assert_eq(helper, bits[11] * bits[10]);
    builder.assert_zero(helper * bits[9]);
    let low: AB::Expr = bits[..8].iter().map(|bit| (*bit).into()).sum();
    builder.assert_zero(helper * bits[8] * low);
}

/// Exhaustive synthetic-bit checks for the complete twelve-bit input space.
#[cfg(test)]
mod tests {
    use super::*;
    use p3_air::DebugConstraintBuilder;
    use p3_field::PrimeCharacteristicRing;
    use p3_matrix::{dense::RowMajorMatrixView, stack::ViewPair};

    /// The reused Boolean bits admit exactly the native interval and fix the helper uniquely.
    #[test]
    fn compact_coefficient_bound_is_exact_for_every_twelve_bit_value() {
        for value in 0..4096 {
            let bits = std::array::from_fn(|bit| Goldilocks::from_bool(value & (1 << bit) != 0));
            for changed in [false, true] {
                let empty = RowMajorMatrixView::new_row(&[]);
                let mut builder = DebugConstraintBuilder::new(
                    0,
                    ViewPair::new(empty, empty),
                    ViewPair::new(empty, empty),
                    &[],
                    Goldilocks::ONE,
                    Goldilocks::ZERO,
                    Goldilocks::ONE,
                    &[],
                );
                let helper = bits[11] * bits[10] + Goldilocks::from_bool(changed);
                eval(&mut builder, &bits, helper);
                assert_eq!(
                    builder.failures().is_empty(),
                    value <= 3328 && !changed,
                    "value {value}, changed {changed}"
                );
            }
        }
    }
}
