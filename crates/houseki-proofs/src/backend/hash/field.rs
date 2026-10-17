//! Domain separated hashing of canonical field elements.

use super::{ByteHash, words};
use p3_field::PrimeField64;
use p3_goldilocks::Goldilocks;
use p3_symmetric::CryptographicHasher;

/// Domain separated hashing of canonical field words for leaf commitments.
#[derive(Clone, Debug)]
pub(in crate::backend) struct FieldHash;

impl CryptographicHasher<Goldilocks, [u64; 8]> for FieldHash {
    /// Encodes every canonical field representative as eight little endian bytes.
    fn hash_iter<I: IntoIterator<Item = Goldilocks>>(&self, input: I) -> [u64; 8] {
        words(
            ByteHash.hash_iter(
                b"houseki/proofs/leaf/v1".iter().copied().chain(
                    input
                        .into_iter()
                        .flat_map(|value| value.as_canonical_u64().to_le_bytes()),
                ),
            ),
        )
    }
}
