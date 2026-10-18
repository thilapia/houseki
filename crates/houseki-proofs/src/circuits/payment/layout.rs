//! Exact geometry selected from the trusted payment schedule.

use super::{PaymentLayoutError, schedule::Schedule};
use crate::{backend::Layout, gadgets::CompactOpening, profile::payment::SupportedPaymentShape};

/// Complete public schedule and bounded codec geometry for one actual count pair.
pub(crate) struct PaymentLayout {
    /// Public operation and slot selectors owned by the selected shape.
    pub(super) schedule: Schedule,

    /// Original power-of-two trace height before hiding interleaving.
    rows: usize,
}

impl PaymentLayout {
    /// Two totals and linked note fields preceding the shared operation work region.
    pub(super) const WORK: usize = 184;

    /// Live registers plus the largest shared gadget region.
    pub(super) const WIDTH: usize = Self::WORK + CompactOpening::WIDTH;

    /// Resolves bounded geometry without allocating any private trace.
    pub(crate) fn for_shape(shape: SupportedPaymentShape) -> Result<Self, PaymentLayoutError> {
        let schedule = Schedule::new(shape);
        let rows = schedule
            .active_rows()
            .checked_next_power_of_two()
            .ok_or(PaymentLayoutError::InvalidGeometry)?;
        if !(512..=8192).contains(&rows) {
            return Err(PaymentLayoutError::InvalidGeometry);
        }

        let layout = Self { schedule, rows };
        if layout
            .codec()
            .encoded_upper_bound()
            .map_err(|_| PaymentLayoutError::InvalidGeometry)?
            > crate::profile::MAX_PROOF_BYTES
            || layout
                .codec()
                .decoded_upper_bound()
                .map_err(|_| PaymentLayoutError::InvalidGeometry)?
                > crate::backend::MAX_DECODED_BYTES
        {
            return Err(PaymentLayoutError::InvalidGeometry);
        }

        Ok(layout)
    }

    /// Returns the exact supported public count pair.
    pub(crate) const fn shape(&self) -> SupportedPaymentShape {
        self.schedule.shape()
    }

    /// Returns original rows, excluding the hiding PCS expansion.
    pub(crate) const fn rows(&self) -> usize {
        self.rows
    }

    /// Returns live registers plus shared operation cells.
    pub(crate) const fn width(&self) -> usize {
        Self::WIDTH
    }

    /// Returns immutable encoding dimensions independently of proof bytes.
    pub(crate) fn codec(&self) -> Layout {
        Layout {
            log_rows: self.rows.ilog2() as usize,
            width: Self::WIDTH,
            quotient_chunks: 8,
            main_next: true,
        }
    }

    /// Returns the exact union of global continuity and each gadget's next-row reads.
    pub(crate) fn next_columns(&self) -> Vec<usize> {
        (0..515).chain([608, 624, 632]).collect()
    }
}
