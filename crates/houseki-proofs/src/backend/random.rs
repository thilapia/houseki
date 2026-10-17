//! Unpredictable per-attempt generators and an entropy-free verification mode.

use std::{convert::Infallible, fmt};

use rand::{Rng, SeedableRng, TryCryptoRng, TryRng, rngs::StdRng};
#[cfg(any(test, feature = "prover"))]
use zeroize::Zeroizing;

#[cfg(any(test, feature = "prover"))]
use super::BackendError;

/// Private generator whose verification mode cannot produce even predictable bytes.
pub(super) struct BackendRng {
    /// Seeded state present only for a proving attempt or a derived private stream.
    generator: Option<StdRng>,
}

impl BackendRng {
    /// Constructs a verifier marker that panics if backend code incorrectly asks for entropy.
    pub(super) fn verification() -> Self {
        Self { generator: None }
    }

    /// Borrows the private generator without allowing a deterministic verification fallback.
    fn seeded(&mut self) -> &mut StdRng {
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
        Ok(self.seeded().next_u32())
    }

    /// Samples a full word only from a seeded private stream.
    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        Ok(self.seeded().next_u64())
    }

    /// Fills backend scratch only from a seeded private stream.
    fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), Self::Error> {
        self.seeded().fill_bytes(destination);

        Ok(())
    }
}

impl TryCryptoRng for BackendRng {}

impl SeedableRng for BackendRng {
    /// Full cryptographic seed passed by protected acquisition or upstream stream derivation.
    type Seed = [u8; 32];

    /// Creates a private stream without retaining the input seed array separately.
    fn from_seed(seed: Self::Seed) -> Self {
        Self {
            generator: Some(StdRng::from_seed(seed)),
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
        *generator = BackendRng::from_seed(*seed);
    }

    Ok(generators)
}

/// Uses operating system entropy without a deterministic retry or fallback.
#[cfg(any(test, feature = "prover"))]
pub(super) fn fresh_generators() -> Result<[BackendRng; 3], BackendError> {
    generators_with(|seed| getrandom::fill(seed).map_err(|_| BackendError::EntropyUnavailable))
}
