//! Pinned hiding backend types that never cross the public crate interface.

use p3_challenger::{HashChallenger, SerializingChallenger64};
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_field::extension::CubicTrinomialExtensionField;
use p3_fri::{FriParameters, HidingFriPcs};
use p3_goldilocks::Goldilocks;
use p3_merkle_tree::MerkleTreeHidingMmcs;
use p3_symmetric::CompressionFunctionFromHasher;
use p3_uni_stark::{Proof, StarkConfig};

use super::{
    hash::{ByteHash, FieldHash, WordHash},
    random::BackendRng,
};

/// Number of queries in the internally evaluated candidate.
pub(super) const QUERIES: usize = 128;

/// Logarithm of the fixed FRI blowup.
pub(super) const LOG_BLOWUP: usize = 3;

/// Degree of the challenge extension and number of masking codewords.
pub(super) const EXTENSION_DEGREE: usize = 3;

/// Number of random base field values appended to every MMCS leaf.
pub(super) const SALT_ELEMENTS: usize = 4;

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
