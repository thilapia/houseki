//! Domain separated hashing of complete commitment digests.

use p3_symmetric::CryptographicHasher;

use super::{ByteHash, words};

/// Domain separated hashing of complete digest words for internal tree nodes.
#[derive(Clone, Debug)]
pub(in crate::backend) struct WordHash;

impl CryptographicHasher<u64, [u64; 8]> for WordHash {
    /// Preserves all child digest bits without field reduction or truncation.
    fn hash_iter<I: IntoIterator<Item = u64>>(&self, input: I) -> [u64; 8] {
        words(
            ByteHash.hash_iter(
                b"houseki/proofs/node/v1"
                    .iter()
                    .copied()
                    .chain(input.into_iter().flat_map(u64::to_le_bytes)),
            ),
        )
    }
}
