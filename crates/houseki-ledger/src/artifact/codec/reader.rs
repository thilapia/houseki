//! Checked input slicing before every conversion and collection allocation.

use super::DecodeLimits;
use crate::ArtifactError;

/// A bounded borrowed canonical record cursor.
pub(super) struct Reader<'a> {
    /// Unconsumed complete input suffix.
    bytes: &'a [u8],

    /// Local bounds inherited by every nested record.
    limits: DecodeLimits,
}

impl<'a> Reader<'a> {
    /// Rejects the complete input size before examining its contents.
    pub(super) fn new(bytes: &'a [u8], limits: DecodeLimits) -> Result<Self, ArtifactError> {
        if bytes.len() > limits.max_bytes {
            return Err(ArtifactError::Bound);
        }

        Ok(Self { bytes, limits })
    }

    /// Takes an exact prefix without narrowing untrusted indexes.
    pub(super) fn take(&mut self, len: usize) -> Result<&'a [u8], ArtifactError> {
        let (head, tail) = self
            .bytes
            .split_at_checked(len)
            .ok_or(ArtifactError::Truncated)?;
        self.bytes = tail;
        Ok(head)
    }

    /// Copies an exact fixed width field.
    pub(super) fn fixed<const N: usize>(&mut self) -> Result<[u8; N], ArtifactError> {
        Ok(self.take(N)?.try_into().expect("exact prefix width"))
    }

    /// Reads a complete little endian tag.
    pub(super) fn u32(&mut self) -> Result<u32, ArtifactError> {
        Ok(u32::from_le_bytes(self.fixed()?))
    }

    /// Reads a complete little endian sequence or length.
    pub(super) fn u64(&mut self) -> Result<u64, ArtifactError> {
        Ok(u64::from_le_bytes(self.fixed()?))
    }

    /// Reads a complete little endian amount or count.
    pub(super) fn u128(&mut self) -> Result<u128, ArtifactError> {
        Ok(u128::from_le_bytes(self.fixed()?))
    }

    /// Reads a bounded length prefixed slice without copying its contents.
    pub(super) fn blob(&mut self) -> Result<&'a [u8], ArtifactError> {
        let len = usize::try_from(self.u64()?).map_err(|_| ArtifactError::Bound)?;
        if len > self.limits.max_bytes {
            return Err(ArtifactError::Bound);
        }

        self.take(len)
    }

    /// Reserves a bounded collection only after its count and minimal framing fit the
    /// input.
    pub(super) fn list<T>(
        &mut self,
        max: usize,
        decode: impl Fn(&[u8]) -> Result<T, ArtifactError>,
    ) -> Result<Vec<T>, ArtifactError> {
        let count = usize::try_from(self.u64()?).map_err(|_| ArtifactError::Bound)?;
        if count > max
            || count > self.limits.max_records
            || count > self.bytes.len() / 8
            || count
                .checked_mul(size_of::<T>())
                .ok_or(ArtifactError::Bound)?
                > self.limits.max_bytes
        {
            return Err(ArtifactError::Bound);
        }

        let mut values = Vec::new();
        values
            .try_reserve_exact(count)
            .map_err(|_| ArtifactError::Allocation)?;
        for _ in 0..count {
            values.push(decode(self.blob()?)?);
        }

        Ok(values)
    }

    /// Rejects unconsumed extension bytes.
    pub(super) fn finish(self) -> Result<(), ArtifactError> {
        if self.bytes.is_empty() {
            Ok(())
        } else {
            Err(ArtifactError::Invalid)
        }
    }
}
