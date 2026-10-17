//! Complete byte hashing with guarded streaming scratch.

use p3_symmetric::CryptographicHasher;
use sha3::{Digest, Sha3_512};
use zeroize::Zeroizing;

/// Byte hashing that preserves the complete SHA3-512 output.
#[derive(Clone, Debug)]
pub(in crate::backend) struct ByteHash;

impl CryptographicHasher<u8, [u8; 64]> for ByteHash {
    /// Streams through guarded scratch without collecting a private input vector.
    fn hash_iter<I: IntoIterator<Item = u8>>(&self, input: I) -> [u8; 64] {
        p3_util::prover_runtime::checkpoint(p3_util::prover_runtime::Phase::Commitment);

        let mut hash = Sha3_512::new();
        let mut buffer = Zeroizing::new([0_u8; 128]);
        let mut used = 0;
        for byte in input {
            buffer[used] = byte;
            used += 1;
            if used == buffer.len() {
                p3_util::prover_runtime::checkpoint(p3_util::prover_runtime::Phase::Commitment);
                hash.update(buffer.as_slice());
                used = 0;
            }
        }

        hash.update(&buffer[..used]);

        hash.finalize().into()
    }
}
