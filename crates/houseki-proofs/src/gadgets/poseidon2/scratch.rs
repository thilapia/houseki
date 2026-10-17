//! Temporary backend field storage with the same explicit clearing contract as the trace.

use p3_field::PrimeCharacteristicRing;
use p3_goldilocks::Goldilocks;
use std::ops::{Deref, DerefMut};
use std::sync::atomic::{Ordering, compiler_fence};

/// Owns initialized temporary cells without cloning or value diagnostics.
///
/// Drop clears this storage on normal return and unwinding, but does not promise erasure of
/// compiler generated arithmetic copies or registers.
pub(super) struct Scratch<const N: usize> {
    /// Cells retained until the assignment operation finishes.
    values: [Goldilocks; N],
}

impl<const N: usize> Default for Scratch<N> {
    /// Initializes public zeros before private values are borrowed into this owner.
    fn default() -> Self {
        Self {
            values: [Goldilocks::ZERO; N],
        }
    }
}

impl<const N: usize> Deref for Scratch<N> {
    /// Fixed field array available only through a borrow.
    type Target = [Goldilocks; N];

    /// Borrows cells without transferring their cleanup responsibility.
    fn deref(&self) -> &Self::Target {
        &self.values
    }
}

impl<const N: usize> DerefMut for Scratch<N> {
    /// Borrows initialized cells for in place assignment.
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.values
    }
}

impl<const N: usize> Drop for Scratch<N> {
    /// Clears every cell through volatile writes before releasing the owner.
    fn drop(&mut self) {
        for value in &mut self.values {
            // Safety: Each pointer refers to a uniquely borrowed initialized field cell.
            unsafe { std::ptr::write_volatile(value, Goldilocks::ZERO) };
        }

        compiler_fence(Ordering::SeqCst);
    }
}

/// Observes cleanup while the allocation is still live, including unwinding.
#[cfg(test)]
mod tests {
    use super::*;

    /// Neither an ordinary return nor a panic leaves the owned cells uncleared.
    #[test]
    fn scratch_clears_before_release() {
        for unwind in [false, true] {
            let mut scratch = Box::new(Scratch::<16>::default());
            scratch.fill(Goldilocks::NEG_ONE);
            let pointer = scratch.as_ptr().cast();
            // Safety: The initialized boxed cells remain live until the observed drop.
            assert!(unsafe {
                crate::test_allocator::observes_zeroed_drop(pointer, 16 * 8, || {
                    let result = std::panic::catch_unwind(move || {
                        let _owner = scratch;
                        assert!(!unwind, "exercise scratch cleanup during unwinding");
                    });

                    assert_eq!(result.is_err(), unwind);
                })
            });
        }
    }
}
