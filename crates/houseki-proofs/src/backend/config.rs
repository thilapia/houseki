//! Pinned hiding backend types that never cross the public crate interface.

use p3_challenger::{HashChallenger, SerializingChallenger64};
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_field::{PrimeField64, extension::CubicTrinomialExtensionField};
use p3_fri::{FriParameters, HidingFriPcs};
use p3_goldilocks::Goldilocks;
use p3_merkle_tree::MerkleTreeHidingMmcs;
use p3_symmetric::{CompressionFunctionFromHasher, CryptographicHasher};
use p3_uni_stark::{Proof, StarkConfig};
use sha3::{Digest, Sha3_512};
use zeroize::Zeroizing;

use super::random::BackendRng;

/// Number of queries in the internally evaluated candidate.
pub(super) const QUERIES: usize = 128;

/// Logarithm of the fixed FRI blowup.
pub(super) const LOG_BLOWUP: usize = 3;

/// Degree of the challenge extension and number of masking codewords.
pub(super) const EXTENSION_DEGREE: usize = 3;

/// Number of random base field values appended to every MMCS leaf.
pub(super) const SALT_ELEMENTS: usize = 4;

/// Byte hashing that preserves the complete SHA3-512 output.
#[derive(Clone, Debug)]
pub(super) struct ByteHash;

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

/// Domain separated hashing of canonical field words for leaf commitments.
#[derive(Clone, Debug)]
pub(super) struct FieldHash;

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

/// Domain separated hashing of complete digest words for internal tree nodes.
#[derive(Clone, Debug)]
pub(super) struct WordHash;

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

/// Reinterprets the complete digest as eight portable little endian words.
fn words(bytes: [u8; 64]) -> [u64; 8] {
    std::array::from_fn(|index| {
        u64::from_le_bytes(
            bytes[index * 8..index * 8 + 8]
                .try_into()
                .expect("fixed word"),
        )
    })
}

/// Cubic Goldilocks extension used by the candidate's random challenges.
pub(crate) type Challenge = CubicTrinomialExtensionField<Goldilocks>;

/// Hiding base field commitments with separately salted leaves.
pub(super) type HidingMmcs = MerkleTreeHidingMmcs<
    Goldilocks,
    u64,
    FieldHash,
    CompressionFunctionFromHasher<WordHash, 2, 8>,
    BackendRng,
    2,
    8,
    SALT_ELEMENTS,
>;

/// Hiding extension field commitments for the FRI layers.
pub(super) type FriMmcs = ExtensionMmcs<Goldilocks, Challenge, HidingMmcs>;

/// Canonical field observations over a byte challenger.
type Challenger = SerializingChallenger64<Goldilocks, HashChallenger<u8, ByteHash, 64>>;

/// The pinned PCS hides both commitments and all queried codewords.
type Pcs = HidingFriPcs<Goldilocks, Radix2DitParallel<Goldilocks>, HidingMmcs, FriMmcs, BackendRng>;

/// Private backend configuration with no public arbitrary AIR registration route.
pub(crate) type Config = StarkConfig<Pcs, Challenge, Challenger>;

/// Internal decoded proof before family verification creates any scoped evidence.
pub(crate) type BackendProof = Proof<Config>;

/// Constructs one fresh configuration from a complete public prefix and owned generators.
pub(super) fn assemble(prefix: &[u8], generators: [BackendRng; 3]) -> Config {
    let [input_rng, fri_rng, pcs_rng] = generators;
    let input = HidingMmcs::new(
        FieldHash,
        CompressionFunctionFromHasher::new(WordHash),
        0,
        input_rng,
    );
    let fri = FriParameters {
        log_blowup: LOG_BLOWUP,
        log_final_poly_len: 0,
        max_log_arity: 1,
        num_queries: QUERIES,
        batch_proof_of_work_bits: 0,
        commit_proof_of_work_bits: 0,
        query_proof_of_work_bits: 0,
        mmcs: FriMmcs::new(HidingMmcs::new(
            FieldHash,
            CompressionFunctionFromHasher::new(WordHash),
            0,
            fri_rng,
        )),
    };
    let pcs = Pcs::new(
        Radix2DitParallel::default(),
        input,
        fri,
        EXTENSION_DEGREE,
        pcs_rng,
    );
    let challenger = Challenger::new(HashChallenger::new(prefix.to_vec(), ByteHash));
    Config::new(pcs, challenger)
}
