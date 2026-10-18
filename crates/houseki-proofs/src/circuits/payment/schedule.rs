//! Trusted operation selectors derived solely from checked public counts.

use crate::profile::payment::SupportedPaymentShape;
use p3_field::PrimeCharacteristicRing;
use p3_goldilocks::Goldilocks;

/// One contiguous operation sequence for exactly the actual input and output occurrences.
pub(super) struct Schedule {
    /// Validated counts independent of proof and private witness data.
    shape: SupportedPaymentShape,
}

impl Schedule {
    /// Complete opening, authority, membership and one accumulation for each input.
    pub(super) const INPUT_ROWS: usize = 1733;

    /// One complete opening and one accumulation for each output.
    pub(super) const OUTPUT_ROWS: usize = 129;

    /// First selector reserved for actual ordered note slots.
    pub(super) const SLOTS: usize = 301;

    /// Selects a complete bounded sequence without inspecting witness data.
    pub(super) const fn new(shape: SupportedPaymentShape) -> Self {
        Self { shape }
    }

    /// Returns the selected public counts.
    pub(super) const fn shape(&self) -> SupportedPaymentShape {
        self.shape
    }

    /// Counts all real note operations and exactly one final fee addition.
    pub(super) const fn active_rows(&self) -> usize {
        Self::INPUT_ROWS * self.shape.inputs() + Self::OUTPUT_ROWS * self.shape.outputs() + 1
    }

    /// Includes reusable gadget phases and exactly one selector per actual note occurrence.
    pub(super) const fn selectors(&self) -> usize {
        Self::SLOTS + self.shape.inputs() + self.shape.outputs()
    }

    /// Computes public selectors for one original trace row, leaving padding fully inactive.
    pub(super) fn values(&self, row: usize) -> Vec<Goldilocks> {
        let mut values = vec![Goldilocks::ZERO; self.selectors()];
        let input_rows = self.shape.inputs() * Self::INPUT_ROWS;
        let output_rows = self.shape.outputs() * Self::OUTPUT_ROWS;
        if row < input_rows {
            values[Self::SLOTS + row / Self::INPUT_ROWS] = Goldilocks::ONE;
            let phase = row % Self::INPUT_ROWS;
            if phase < 128 {
                opening(&mut values, phase);
            } else if phase < 216 {
                values[79 + phase - 128] = Goldilocks::ONE;
            } else if phase < 1732 {
                membership(&mut values[167..298], phase - 216);
            } else {
                values[298] = Goldilocks::ONE;
            }
        } else if row < input_rows + output_rows {
            let row = row - input_rows;
            values[Self::SLOTS + self.shape.inputs() + row / Self::OUTPUT_ROWS] = Goldilocks::ONE;
            let phase = row % Self::OUTPUT_ROWS;
            if phase < 128 {
                opening(&mut values, phase);
            } else {
                values[299] = Goldilocks::ONE;
            }
        } else if row == input_rows + output_rows {
            values[300] = Goldilocks::ONE;
        }

        values
    }
}

/// Selects complete opening phases and the end of its 128-row private-field lifetime.
fn opening(values: &mut [Goldilocks], phase: usize) {
    values[78] = Goldilocks::ONE;
    if phase < 77 {
        values[phase] = Goldilocks::ONE;
    } else if phase == 127 {
        values[77] = Goldilocks::ONE;
    }
}

/// Reuses parent hash phases with an exact trusted level selector for every tree level.
fn membership(values: &mut [Goldilocks], phase: usize) {
    if phase == 0 {
        values[130] = Goldilocks::ONE;
        return;
    }

    let phase = phase - 1;
    if phase < 21 {
        values[phase] = Goldilocks::ONE;
    } else if phase < 1493 {
        values[21 + (phase - 21) % 23] = Goldilocks::ONE;
        values[66 + (phase - 21) / 23] = Goldilocks::ONE;
    } else {
        values[44 + phase - 1493] = Goldilocks::ONE;
    }
}
