//! Bounded field storage with explicit cleanup before the allocator releases it.

use p3_field::PrimeCharacteristicRing;
use p3_goldilocks::Goldilocks;
use std::sync::atomic::{Ordering, compiler_fence};

use super::BackendError;

/// A single bounded field allocation without cloning or value diagnostics.
pub(crate) struct Trace {
    /// Initialized cells whose entire allocation is cleared on drop.
    values: Vec<Goldilocks>,

    /// Nonzero number of columns in the owned row major storage.
    width: usize,
}

impl Trace {
    /// Checks the trusted cell budget before reserving exactly the requested storage.
    pub(crate) fn new(rows: usize, width: usize, max_cells: usize) -> Result<Self, BackendError> {
        let cells = rows
            .checked_mul(width)
            .filter(|cells| *cells > 0 && *cells <= max_cells)
            .ok_or(BackendError::InvalidTrace)?;
        let mut values = Vec::new();
        values
            .try_reserve_exact(cells)
            .map_err(|_| BackendError::AllocationFailed)?;
        values.resize(cells, Goldilocks::ZERO);
        Ok(Self { values, width })
    }

    /// Borrows initialized cells without transferring their cleanup responsibility.
    pub(crate) fn values(&self) -> &[Goldilocks] {
        &self.values
    }

    /// Borrows cells for bounded construction while retaining the original owner.
    pub(crate) fn values_mut(&mut self) -> &mut [Goldilocks] {
        &mut self.values
    }

    /// Returns the selected public row width.
    pub(crate) fn width(&self) -> usize {
        self.width
    }

    /// Returns the exact number of initialized rows.
    pub(crate) fn height(&self) -> usize {
        self.values.len() / self.width
    }
}

impl Drop for Trace {
    /// Clears all allocated cells, including unused capacity, before Vec releases the storage.
    fn drop(&mut self) {
        for index in 0..self.values.capacity() {
            // Safety: Every pointer lies in the allocation and writing initializes any spare capacity.
            unsafe {
                self.values
                    .as_mut_ptr()
                    .add(index)
                    .write_volatile(Goldilocks::ZERO)
            };
        }
        compiler_fence(Ordering::SeqCst);
    }
}

/// Trace cleanup and checked dimension properties.
#[cfg(test)]
mod tests {
    use super::*;
    use p3_field::PrimeCharacteristicRing;

    /// Observes cleared live bytes before freeing an untagged trace allocation.
    #[test]
    fn trace_owner_clears_on_drop() {
        let mut trace = Trace::new(4, 3, 12).unwrap();
        trace.values_mut().fill(Goldilocks::from_u64(0x12345678));
        let pointer = trace.values().as_ptr().cast();
        // Safety: All watched cells are initialized and remain live until the closure drops their owner.
        assert!(unsafe {
            crate::test_allocator::observes_zeroed_drop(pointer, 12 * 8, || drop(trace))
        });
    }

    /// Rejects multiplication overflow and caller budget excess before allocation.
    #[test]
    fn trace_dimensions_respect_the_selected_budget() {
        for (rows, width, budget) in [
            (0, 1, 1),
            (1, 0, 1),
            (usize::MAX, 2, usize::MAX),
            (4, 3, 11),
        ] {
            assert!(Trace::new(rows, width, budget).is_err());
        }
    }
}
