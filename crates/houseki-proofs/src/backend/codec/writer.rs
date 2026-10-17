//! Checked canonical proof output sized before a single final byte allocation.

use p3_field::{BasedVectorSpace, PrimeField64};
use p3_goldilocks::Goldilocks;
use p3_symmetric::MerkleCap;

use super::CodecError;
use crate::{backend::config::Challenge, profile::MAX_PROOF_BYTES};

/// Size only or retaining output with a fixed complete proof cap.
pub(super) struct Writer {
    /// Bytes retained only after the size only pass succeeds.
    pub(super) bytes: Vec<u8>,

    /// Total canonical bytes, independent of the retention mode.
    pub(super) length: usize,

    /// Whether writes append to the preallocated output.
    materialize: bool,
}

impl Writer {
    /// Creates a sizing pass or fallibly reserves its exact validated output length.
    pub(super) fn new(capacity: Option<usize>) -> Result<Self, CodecError> {
        let mut bytes = Vec::new();
        if let Some(capacity) = capacity {
            if capacity > MAX_PROOF_BYTES {
                return Err(CodecError::ProofTooLarge);
            }
            bytes
                .try_reserve_exact(capacity)
                .map_err(|_| CodecError::AllocationFailed)?;
        }

        Ok(Self {
            bytes,
            length: 0,
            materialize: capacity.is_some(),
        })
    }

    /// Enforces the complete byte bound before retaining any additional output.
    pub(super) fn bytes(&mut self, bytes: &[u8]) -> Result<(), CodecError> {
        self.length = self
            .length
            .checked_add(bytes.len())
            .ok_or(CodecError::ProofTooLarge)?;
        if self.length > MAX_PROOF_BYTES {
            return Err(CodecError::ProofTooLarge);
        }

        if self.materialize {
            self.bytes.extend_from_slice(bytes);
        }

        Ok(())
    }

    /// Writes one complete fixed width count.
    pub(super) fn u32(&mut self, value: u32) -> Result<(), CodecError> {
        self.bytes(&value.to_le_bytes())
    }

    /// Serializes a base field value only in its canonical representation.
    pub(super) fn field(&mut self, value: Goldilocks) -> Result<(), CodecError> {
        self.bytes(&value.as_canonical_u64().to_le_bytes())
    }

    /// Serializes all extension coefficients in the pinned basis order.
    pub(super) fn extension(&mut self, value: Challenge) -> Result<(), CodecError> {
        for coefficient in value.as_basis_coefficients_slice() {
            self.field(*coefficient)?;
        }

        Ok(())
    }

    /// Retains every digest word, including values above the base field modulus.
    pub(super) fn digest(&mut self, digest: &[u64; 8]) -> Result<(), CodecError> {
        for value in digest {
            self.bytes(&value.to_le_bytes())?;
        }

        Ok(())
    }

    /// Requires the configured zero height cap before writing its only root.
    pub(super) fn commitment(
        &mut self,
        cap: &MerkleCap<Goldilocks, [u64; 8]>,
    ) -> Result<(), CodecError> {
        exact(cap.roots().len(), 1)?;

        self.digest(&cap.roots()[0])
    }

    /// Writes a fixed expected number of base field values.
    pub(super) fn fields(&mut self, values: &[Goldilocks], count: usize) -> Result<(), CodecError> {
        exact(values.len(), count)?;
        for value in values {
            self.field(*value)?;
        }

        Ok(())
    }

    /// Writes a fixed expected number of extension field values.
    pub(super) fn extensions(
        &mut self,
        values: &[Challenge],
        count: usize,
    ) -> Result<(), CodecError> {
        exact(values.len(), count)?;
        for value in values {
            self.extension(*value)?;
        }

        Ok(())
    }

    /// Emits a bounded frontier count and every sibling in upstream frontier order.
    pub(super) fn siblings(
        &mut self,
        values: &[[u64; 8]],
        maximum: usize,
    ) -> Result<(), CodecError> {
        if values.len() > maximum {
            return Err(CodecError::InvalidShape);
        }

        self.u32(u32::try_from(values.len()).map_err(|_| CodecError::InvalidShape)?)?;
        for value in values {
            self.digest(value)?;
        }

        Ok(())
    }
}

/// Rejects a structural mismatch before traversing caller supplied nested vectors.
pub(super) fn exact(actual: usize, expected: usize) -> Result<(), CodecError> {
    if actual != expected {
        return Err(CodecError::InvalidShape);
    }

    Ok(())
}
