//! Fallible complete-width canonical record writer.

use crate::ArtifactError;

/// Owned canonical output that reserves storage before every append.
pub(super) struct Writer {
    /// Complete prefix produced so far, returned only after success.
    bytes: Vec<u8>,
}

impl Writer {
    /// Starts an empty canonical record.
    pub(super) fn new() -> Self {
        Self { bytes: Vec::new() }
    }

    /// Appends complete bytes after checking allocation.
    pub(super) fn raw(&mut self, bytes: &[u8]) -> Result<(), ArtifactError> {
        self.bytes
            .try_reserve(bytes.len())
            .map_err(|_| ArtifactError::Allocation)?;
        self.bytes.extend_from_slice(bytes);
        Ok(())
    }

    /// Appends a complete little endian tag.
    pub(super) fn u32(&mut self, value: u32) -> Result<(), ArtifactError> {
        self.raw(&value.to_le_bytes())
    }

    /// Appends a complete little endian sequence or length.
    pub(super) fn u64(&mut self, value: u64) -> Result<(), ArtifactError> {
        self.raw(&value.to_le_bytes())
    }

    /// Appends a complete little endian amount or note count.
    pub(super) fn u128(&mut self, value: u128) -> Result<(), ArtifactError> {
        self.raw(&value.to_le_bytes())
    }

    /// Emits one length prefixed byte record.
    pub(super) fn blob(&mut self, bytes: &[u8]) -> Result<(), ArtifactError> {
        self.u64(u64::try_from(bytes.len()).map_err(|_| ArtifactError::Bound)?)?;
        self.raw(bytes)
    }

    /// Emits an ordered list with a count and separate complete record prefixes.
    pub(super) fn list<T>(
        &mut self,
        values: &[T],
        encode: impl Fn(&T) -> Result<Vec<u8>, ArtifactError>,
    ) -> Result<(), ArtifactError> {
        self.u64(u64::try_from(values.len()).map_err(|_| ArtifactError::Bound)?)?;
        for value in values {
            self.blob(&encode(value)?)?;
        }
        Ok(())
    }

    /// Returns the complete successfully encoded record.
    pub(super) fn finish(self) -> Vec<u8> {
        self.bytes
    }
}
