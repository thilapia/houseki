//! Unpredictable per-attempt generators and an entropy-free verification mode.

use std::{convert::Infallible, fmt};

use chacha20::ChaCha12Rng;
use rand::{Rng, SeedableRng, TryCryptoRng, TryRng};
use zeroize::Zeroize;
use zeroize::Zeroizing;

#[cfg(any(test, feature = "prover"))]
use super::BackendError;

/// Private generator whose verification mode cannot produce even predictable bytes.
pub(super) struct BackendRng {
    /// Seeded state present only for a proving attempt or a derived private stream.
    generator: Option<ChaCha12Rng>,
}

impl BackendRng {
    /// Constructs a verifier marker that panics if backend code incorrectly asks for entropy.
    pub(super) fn verification() -> Self {
        Self { generator: None }
    }

    /// Borrows the private generator without allowing a deterministic verification fallback.
    fn seeded(&mut self) -> &mut ChaCha12Rng {
        self.generator
            .as_mut()
            .expect("verification must not request randomness")
    }
}

impl fmt::Debug for BackendRng {
    /// Omits all seed and generator state from formatting.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("BackendRng([REDACTED])")
    }
}

impl TryRng for BackendRng {
    /// Seed acquisition fails before constructing an infallible private stream.
    type Error = Infallible;

    /// Samples a full word only from a seeded private stream.
    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        p3_util::prover_runtime::checkpoint(p3_util::prover_runtime::Phase::Random);
        Ok(self.seeded().next_u32())
    }

    /// Samples a full word only from a seeded private stream.
    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        p3_util::prover_runtime::checkpoint(p3_util::prover_runtime::Phase::Random);
        Ok(self.seeded().next_u64())
    }

    /// Fills backend scratch only from a seeded private stream.
    fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), Self::Error> {
        for chunk in destination.chunks_mut(4096) {
            p3_util::prover_runtime::checkpoint(p3_util::prover_runtime::Phase::Random);
            self.seeded().fill_bytes(chunk);
        }
        Ok(())
    }
}

impl TryCryptoRng for BackendRng {}

impl SeedableRng for BackendRng {
    /// Full cryptographic seed passed by protected acquisition or upstream stream derivation.
    type Seed = Zeroizing<[u8; 32]>;

    /// Creates a private stream without retaining the input seed array separately.
    fn from_seed(mut seed: Self::Seed) -> Self {
        let generator = ChaCha12Rng::from_seed(*seed);
        seed.zeroize();
        Self {
            generator: Some(generator),
        }
    }
}

/// Acquires all three independent seeds before allowing backend construction.
#[cfg(any(test, feature = "prover"))]
pub(super) fn generators_with(
    mut fill: impl FnMut(&mut [u8; 32]) -> Result<(), BackendError>,
) -> Result<[BackendRng; 3], BackendError> {
    let mut generators = std::array::from_fn(|_| BackendRng::verification());
    for generator in &mut generators {
        let mut seed = Zeroizing::new([0; 32]);
        fill(&mut seed)?;
        *generator = BackendRng::from_seed(seed);
    }
    Ok(generators)
}

/// Uses operating system entropy without a deterministic retry or fallback.
#[cfg(any(test, feature = "prover"))]
pub(super) fn fresh_generators() -> Result<[BackendRng; 3], BackendError> {
    generators_with(|seed| getrandom::fill(seed).map_err(|_| BackendError::EntropyUnavailable))
}

/// Pinned private generator and hash state cleanup contracts.
#[cfg(test)]
mod tests {
    use super::*;

    /// Keeps upstream derived stream seeds under a guarded associated seed type.
    #[test]
    fn derived_generators_require_guarded_seed_storage() {
        let seed: <BackendRng as SeedableRng>::Seed = Zeroizing::new([83; 32]);
        let mut actual = BackendRng::from_seed(seed);
        let mut expected = rand::rngs::StdRng::from_seed([83; 32]);
        let mut derived = BackendRng::from_rng(&mut actual);
        let mut expected_derived = rand::rngs::StdRng::from_rng(&mut expected);
        for _ in 0..1024 {
            assert_eq!(derived.try_next_u64().unwrap(), expected_derived.next_u64());
        }
    }

    /// Requires drop cleanup from both stack state implementations and preserves the pinned stream.
    #[test]
    fn private_random_and_hash_state_support_drop_cleanup() {
        /// Checks the upstream type's explicit destructor cleanup contract.
        fn clears_on_drop<T: zeroize::ZeroizeOnDrop>() {}
        clears_on_drop::<chacha20::ChaCha12Rng>();
        clears_on_drop::<sha3::Sha3_512>();
        let mut expected = rand::rngs::StdRng::from_seed([0x74; 32]);
        let mut actual = BackendRng::from_seed(Zeroizing::new([0x74; 32]));
        for _ in 0..1024 {
            assert_eq!(actual.try_next_u64().unwrap(), expected.next_u64());
        }
        assert_eq!(format!("{actual:?}"), "BackendRng([REDACTED])");
    }
}
