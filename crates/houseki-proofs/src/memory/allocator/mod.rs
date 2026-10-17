//! Allocator forwarding with per allocation attempt ownership and volatile release cleanup.

mod header;

use super::{ACTIVE, Account};
use header::{Header, expanded};
use std::alloc::{GlobalAlloc, Layout};
use std::ptr;
use std::sync::{
    Arc,
    atomic::{Ordering, compiler_fence},
};

/// An allocator adapter that clears heap blocks owned by a proving attempt before release.
///
/// Applications enabling proving install this adapter around their chosen global allocator.
///
/// Every allocation carries a small ownership header, including allocations outside proving.
///
/// The adapter preserves the inner allocator's alignment and failure behavior, while reallocations
/// allocate and copy before clearing the original block.
///
/// Memory outside tagged heap blocks, including caller buffers and compiler copies, is not covered.
///
/// ```
/// use houseki_proofs::ProofAllocator;
/// use std::alloc::System;
/// #[global_allocator]
/// static ALLOCATOR: ProofAllocator<System> = ProofAllocator::new(System);
/// houseki_proofs::ProofRuntime::new().check_prover_allocator().unwrap();
/// ```
pub struct ProofAllocator<A> {
    /// Allocator receiving the expanded layout and cleared released payloads.
    inner: A,
}

impl<A> ProofAllocator<A> {
    /// Wraps an allocator without allocating or initializing a proving attempt.
    pub const fn new(inner: A) -> Self {
        Self { inner }
    }
}

/// Clears exactly the live payload using volatile stores and an optimization fence.
unsafe fn wipe(pointer: *mut u8, size: usize) {
    let words = size / size_of::<usize>();
    for index in 0..words {
        // Safety: The header layout guarantees word alignment and the caller owns this payload.
        unsafe { pointer.cast::<usize>().add(index).write_volatile(0) };
    }

    for index in words * size_of::<usize>()..size {
        // Safety: Remaining bytes are within the same live allocation.
        unsafe { pointer.add(index).write_volatile(0) };
    }

    compiler_fence(Ordering::SeqCst);
}

impl<A: GlobalAlloc> ProofAllocator<A> {
    /// Allocates a tagged payload while retaining accounting independently of thread lifetime.
    unsafe fn allocate(&self, layout: Layout, account: *const Account) -> *mut u8 {
        let Some((combined, offset)) = expanded(layout) else {
            return ptr::null_mut();
        };

        // Safety: The expanded layout is valid and nonzero because it includes a header.
        let base = unsafe { self.inner.alloc(combined) };

        if base.is_null() {
            return base;
        }

        if !account.is_null() {
            // Safety: ACTIVE or the original allocation retains a live strong owner throughout this call.
            unsafe { Arc::increment_strong_count(account) };

            // Safety: The incremented reference keeps the shared atomic accounting alive.
            unsafe { &*account }.allocated(layout.size());
        }

        // Safety: The fresh aligned allocation has room for both the header and the payload.
        unsafe {
            base.cast::<Header>().write(Header { account });
            base.add(offset)
        }
    }
}

// Safety: Layout expansion preserves alignment, every allocation retains its original owner,
// and release reconstructs the exact underlying layout before forwarding it to the inner allocator.
unsafe impl<A: GlobalAlloc> GlobalAlloc for ProofAllocator<A> {
    /// Tags successful allocations with the calling thread's current attempt.
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let account = ACTIVE
            .try_with(|active| active.get())
            .unwrap_or(ptr::null());

        // Safety: The allocator caller supplies a valid layout and ACTIVE retains its owner.
        unsafe { self.allocate(layout, account) }
    }

    /// Clears tagged payloads before releasing storage and their retained accounting owner.
    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        let Some((combined, offset)) = expanded(layout) else {
            std::process::abort()
        };

        // Safety: The caller returns the original payload with its matching allocation layout.
        let base = unsafe { pointer.sub(offset) };

        // Safety: Every allocation through this adapter initialized this header.
        let account = unsafe { base.cast::<Header>().read().account };

        if !account.is_null() {
            // Safety: The original payload remains exclusively owned until inner deallocation.
            unsafe { wipe(pointer, layout.size()) };

            // Safety: The header owns one strong reference, transferred back exactly once here.
            let account = unsafe { Arc::from_raw(account) };

            account.released(layout.size());
            drop(account);
        }

        // Safety: This is the exact base pointer and layout returned by the inner allocator.
        unsafe { self.inner.dealloc(base, combined) };
    }

    /// Initializes the complete requested payload without changing its ownership tag.
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // Safety: This method receives the same valid layout contract as alloc.
        let pointer = unsafe { self.alloc(layout) };

        if !pointer.is_null() {
            // Safety: A successful allocation contains layout.size writable bytes.
            unsafe { pointer.write_bytes(0, layout.size()) };
        }

        pointer
    }

    /// Preserves allocation ownership across growth, shrinkage and changes of worker thread.
    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        let Some((_, offset)) = expanded(layout) else {
            return ptr::null_mut();
        };

        let Ok(replacement_layout) = Layout::from_size_align(size, layout.align()) else {
            return ptr::null_mut();
        };

        // Safety: The original live allocation has the header written by allocate.
        let account = unsafe { (*pointer.sub(offset).cast::<Header>()).account };

        // Safety: The original header retains account until the old allocation is released.
        let replacement = unsafe { self.allocate(replacement_layout, account) };

        if !replacement.is_null() {
            // Safety: The new allocation is distinct and has room for the copied initialized prefix.
            unsafe {
                ptr::copy_nonoverlapping(pointer, replacement, layout.size().min(size));
                self.dealloc(pointer, layout);
            }
        }

        replacement
    }
}
