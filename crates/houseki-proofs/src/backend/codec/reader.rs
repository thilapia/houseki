//! Allocation free structural scanning followed by fallible decoded allocation.

use super::{CodecError, MAX_DECODED_BYTES};
use crate::backend::config::Challenge;
use p3_field::{BasedVectorSpace, PrimeCharacteristicRing};
use p3_goldilocks::Goldilocks;
use p3_symmetric::MerkleCap;

/// A fixed SHA3-512 commitment represented without truncation.
type Commitment = MerkleCap<Goldilocks, [u64; 8]>;

/// Checked cursor whose first pass accounts for allocation without performing it.
pub(super) struct Reader<'a> {
    /// Remaining bytes bounded by the complete envelope length.
    bytes: &'a [u8],

    /// Whether validated structures should be retained in allocated vectors.
    materialize: bool,

    /// Sum of requested decoded vector storage, including nested vector headers.
    allocated: usize,
}

impl<'a> Reader<'a> {
    /// Starts a scan or materialization pass over an already bounded payload.
    pub(super) fn new(bytes: &'a [u8], materialize: bool) -> Self {
        Self {
            bytes,
            materialize,
            allocated: 0,
        }
    }

    /// Borrows the next exact bytes before any conversion or allocation.
    fn take<const N: usize>(&mut self) -> Result<[u8; N], CodecError> {
        let bytes = self.bytes.get(..N).ok_or(CodecError::Truncated)?;
        let result = bytes.try_into().map_err(|_| CodecError::Truncated)?;
        self.bytes = &self.bytes[N..];

        Ok(result)
    }

    /// Reads a complete little endian shape or bounded multiproof count.
    pub(super) fn u32(&mut self) -> Result<u32, CodecError> {
        Ok(u32::from_le_bytes(self.take()?))
    }

    /// Rejects noncanonical field words instead of reducing them modulo the field.
    pub(super) fn field(&mut self) -> Result<Goldilocks, CodecError> {
        let value = u64::from_le_bytes(self.take()?);
        if value >= 18_446_744_069_414_584_321 {
            return Err(CodecError::NonCanonicalField);
        }

        Ok(Goldilocks::from_u64(value))
    }

    /// Reads all three canonical basis coefficients in the pinned extension order.
    pub(super) fn extension(&mut self) -> Result<Challenge, CodecError> {
        let coefficients = [self.field()?, self.field()?, self.field()?];

        Ok(Challenge::from_basis_coefficients_fn(|index| {
            coefficients[index]
        }))
    }

    /// Reads all 512 digest bits without treating digest words as field elements.
    pub(super) fn digest(&mut self) -> Result<[u64; 8], CodecError> {
        let mut result = [0; 8];
        for value in &mut result {
            *value = u64::from_le_bytes(self.take()?);
        }

        Ok(result)
    }

    /// Accounts for every requested allocation before optionally reserving storage.
    fn reserve<T>(&mut self, count: usize) -> Result<Vec<T>, CodecError> {
        let bytes = count
            .checked_mul(size_of::<T>())
            .ok_or(CodecError::AllocationLimit)?;
        self.allocated = self
            .allocated
            .checked_add(bytes)
            .ok_or(CodecError::AllocationLimit)?;
        if self.allocated > MAX_DECODED_BYTES {
            return Err(CodecError::AllocationLimit);
        }

        let mut values = Vec::new();
        if self.materialize {
            values
                .try_reserve_exact(count)
                .map_err(|_| CodecError::AllocationFailed)?;
        }

        Ok(values)
    }

    /// Applies a fixed trusted dimension while retaining no values during a scan.
    pub(super) fn list<T>(
        &mut self,
        count: usize,
        mut element: impl FnMut(&mut Self, usize) -> Result<T, CodecError>,
    ) -> Result<Vec<T>, CodecError> {
        let mut values = self.reserve(count)?;
        for index in 0..count {
            let value = element(self, index)?;
            if self.materialize {
                values.push(value);
            }
        }

        Ok(values)
    }

    /// Reads an exact vector of canonical base field values.
    pub(super) fn fields(&mut self, count: usize) -> Result<Vec<Goldilocks>, CodecError> {
        self.list(count, |reader, _| reader.field())
    }

    /// Reads an exact vector of canonical extension field values.
    pub(super) fn extensions(&mut self, count: usize) -> Result<Vec<Challenge>, CodecError> {
        self.list(count, |reader, _| reader.extension())
    }

    /// Builds the single root cap only after accounting for its allocation in both passes.
    pub(super) fn commitment(&mut self) -> Result<Option<Commitment>, CodecError> {
        let digest = self.digest()?;

        let mut roots = self.reserve(1)?;
        if self.materialize {
            roots.push(digest);

            Ok(Some(MerkleCap::new(roots)))
        } else {
            Ok(None)
        }
    }

    /// Reads fixed round commitments without allocating intermediate digest vectors.
    pub(super) fn commitments(&mut self, count: usize) -> Result<Vec<Commitment>, CodecError> {
        let mut values = self.reserve(count)?;
        for _ in 0..count {
            if let Some(commitment) = self.commitment()? {
                values.push(commitment);
            }
        }

        Ok(values)
    }

    /// Reads the only variable payload count under its trusted Merkle frontier bound.
    pub(super) fn siblings(&mut self, maximum: usize) -> Result<Vec<[u64; 8]>, CodecError> {
        let count = self.u32()? as usize;
        if count > maximum {
            return Err(CodecError::InvalidShape);
        }

        let bytes = count.checked_mul(64).ok_or(CodecError::InvalidShape)?;
        if bytes > self.bytes.len() {
            return Err(CodecError::Truncated);
        }

        self.list(count, |reader, _| reader.digest())
    }

    /// Requires exact payload consumption and returns the planned vector storage.
    pub(super) fn finish(&self) -> Result<usize, CodecError> {
        if !self.bytes.is_empty() {
            return Err(CodecError::TrailingBytes);
        }

        #[cfg(test)]
        super::DECODED_VECTOR_BYTES.with(|bytes| bytes.set(self.allocated));

        Ok(self.allocated)
    }
}

/// Canonical scalar vectors and checked allocation accounting.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::codec::writer::Writer;
    use crate::test_allocator as allocation;
    use p3_field::PrimeField64;

    /// Preserves extension basis order and full digest bits under independent literal bytes.
    #[test]
    fn scalar_vectors_preserve_canonical_words_and_basis_order() {
        let mut bytes = [0_u8; 88];
        bytes[..8].copy_from_slice(&1_u64.to_le_bytes());
        bytes[8..16].copy_from_slice(&2_u64.to_le_bytes());
        bytes[16..24].copy_from_slice(&18_446_744_069_414_584_320_u64.to_le_bytes());
        bytes[24..].fill(255);

        let mut reader = Reader::new(&bytes, false);
        let extension = reader.extension().unwrap();
        let digest = reader.digest().unwrap();

        assert_eq!(reader.finish().unwrap(), 0);
        assert_eq!(
            extension
                .as_basis_coefficients_slice()
                .iter()
                .map(|x: &Goldilocks| x.as_canonical_u64())
                .collect::<Vec<_>>(),
            [1, 2, 18_446_744_069_414_584_320]
        );
        assert_eq!(digest, [u64::MAX; 8]);

        let mut writer = Writer::new(Some(bytes.len())).unwrap();
        writer.extension(extension).unwrap();
        writer.digest(&digest).unwrap();

        assert_eq!(writer.bytes, bytes);
    }

    /// Rejects overflow and the cumulative requested storage limit before allocating.
    #[test]
    fn allocation_budget_rejects_checked_and_cumulative_overflow() {
        for materialize in [false, true] {
            let mut reader = Reader::new(&[], materialize);
            let (result, calls, bytes) = allocation::measure(|| reader.reserve::<u64>(usize::MAX));

            assert!(matches!(result, Err(CodecError::AllocationLimit)));
            assert_eq!((calls, bytes), (0, 0));
        }

        let mut reader = Reader::new(&[], false);

        assert!(reader.reserve::<u8>(MAX_DECODED_BYTES).unwrap().is_empty());
        assert_eq!(reader.finish().unwrap(), MAX_DECODED_BYTES);
        assert!(matches!(
            reader.reserve::<u8>(1),
            Err(CodecError::AllocationLimit)
        ));
    }
}
