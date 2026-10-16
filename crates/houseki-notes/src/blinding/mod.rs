//! Protected fresh randomness for private note commitments.

mod error;

pub use error::NoteBlindingError;

use getrandom::{SysRng, rand_core::TryCryptoRng};
use std::fmt;
use zeroize::{Zeroize, Zeroizing};

/// A protected 32 byte blinding value freshly sampled for one private note.
///
/// [`Self::generate`] obtains independent bytes from the system random source rather than
/// deriving them from public note fields or reusing another cryptographic role's material.
///
/// The type keeps its bytes private and redacts diagnostics, with no import, export, cloning,
/// equality or serialization interface.
///
/// Stored bytes are zeroized when dropped, including during unwinding, although cleanup cannot
/// erase every copy made by the compiler or operating system or run after process termination.
///
/// Storage alone does not validate a note or enable commitment derivation.
pub struct NoteBlinding(
    /// Owned blinding bytes cleared when the value is dropped.
    [u8; 32],
);

impl NoteBlinding {
    /// Number of fresh bytes in a complete note blinding value.
    pub const LENGTH: usize = 32;

    /// Generates fresh note blinding using the system's cryptographic random source.
    ///
    /// Entropy is acquired into guarded storage that is cleared on success or failure, with
    /// no blinding value returned if acquisition reports an error after a partial or full write.
    ///
    /// # Errors
    ///
    /// Returns [`NoteBlindingError::RandomnessUnavailable`] if the source fails to supply the
    /// complete fresh value.
    pub fn generate() -> Result<Self, NoteBlindingError> {
        Self::generate_with_rng(&mut SysRng)
    }

    /// Borrows stored bytes only inside crate tests that check exact opening retention.
    #[cfg(test)]
    pub(crate) fn test_bytes(&self) -> &[u8; Self::LENGTH] {
        &self.0
    }

    /// Acquires the complete blinding value through guarded temporary storage.
    ///
    /// Only internal tests can substitute a deterministic source for the system generator.
    fn generate_with_rng<R: TryCryptoRng + ?Sized>(rng: &mut R) -> Result<Self, NoteBlindingError> {
        let mut bytes = Zeroizing::new([0; Self::LENGTH]);
        rng.try_fill_bytes(bytes.as_mut())
            .map_err(|_| NoteBlindingError::RandomnessUnavailable)?;

        Ok(Self(*bytes))
    }
}

impl fmt::Debug for NoteBlinding {
    /// Writes a fixed redacted label without inspecting the private bytes.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("NoteBlinding([REDACTED])")
    }
}

impl Drop for NoteBlinding {
    /// Clears the owned blinding buffer before its storage is released.
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// Complete entropy acquisition, failure handling and private material redaction.
#[cfg(test)]
mod tests {
    use getrandom::rand_core::{TryCryptoRng, TryRng};

    use super::{NoteBlinding, NoteBlindingError};

    /// Checks that every sampled byte is retained without rejecting any complete bit pattern.
    #[test]
    fn generation_retains_all_32_bytes_from_the_source() {
        for expected in [
            [0; 32],
            [0xff; 32],
            std::array::from_fn(|index| u8::try_from(index).unwrap()),
        ] {
            let mut rng = FixtureRng {
                bytes: expected,
                written: 0,
                fail_after: None,
            };

            let blinding = NoteBlinding::generate_with_rng(&mut rng).unwrap();

            assert_eq!(blinding.0, expected);
            assert_eq!(rng.written, 32);
        }
    }

    /// Checks that no blinding escapes when entropy fails before, during or after a full write.
    #[test]
    fn generation_rejects_every_reported_entropy_failure() {
        for fail_after in 0..=32 {
            let mut rng = FixtureRng {
                bytes: [0xa5; 32],
                written: 0,
                fail_after: Some(fail_after),
            };

            let result = NoteBlinding::generate_with_rng(&mut rng);

            assert!(matches!(
                result,
                Err(NoteBlindingError::RandomnessUnavailable)
            ));
            assert_eq!(rng.written, fail_after);
        }
    }

    /// Checks fixed redaction in ordinary and alternate debug output for distinct secrets.
    #[test]
    fn diagnostics_never_include_blinding_bytes() {
        for bytes in [[0; 32], [0xff; 32]] {
            let blinding = NoteBlinding(bytes);

            assert_eq!(format!("{blinding:?}"), "NoteBlinding([REDACTED])");
            assert_eq!(format!("{blinding:#?}"), "NoteBlinding([REDACTED])");
        }
    }

    /// Checks that successive public generation calls obtain independent system randomness.
    #[test]
    fn system_generation_produces_distinct_blinding_values() {
        let first = NoteBlinding::generate().unwrap();
        let second = NoteBlinding::generate().unwrap();

        assert_ne!(first.0, second.0);
    }

    /// Deterministic entropy source supporting partial and complete writes followed by failure.
    struct FixtureRng {
        /// Exact bytes supplied by a successful acquisition.
        bytes: [u8; 32],

        /// Number of bytes already written into the requested destination.
        written: usize,

        /// Optional write count at which the source reports failure.
        fail_after: Option<usize>,
    }

    // This predictable source is confined to tests and cannot replace public system generation.
    impl TryCryptoRng for FixtureRng {}

    impl TryRng for FixtureRng {
        /// Synthetic error returned when acquisition reaches its configured failure point.
        type Error = std::io::Error;

        /// Reads four fixture bytes as a little endian integer.
        fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
            let mut bytes = [0; 4];
            self.try_fill_bytes(&mut bytes)?;
            Ok(u32::from_le_bytes(bytes))
        }

        /// Reads eight fixture bytes as a little endian integer.
        fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
            let mut bytes = [0; 8];
            self.try_fill_bytes(&mut bytes)?;
            Ok(u64::from_le_bytes(bytes))
        }

        /// Fills the destination in order and reports any configured failure without rollback.
        fn try_fill_bytes(&mut self, output: &mut [u8]) -> Result<(), Self::Error> {
            for byte in output {
                if self.fail_after == Some(self.written) {
                    return Err(std::io::Error::other("fixture entropy unavailable"));
                }
                *byte = *self
                    .bytes
                    .get(self.written)
                    .ok_or_else(|| std::io::Error::other("fixture entropy exhausted"))?;
                self.written += 1;
            }
            if self.fail_after == Some(self.written) {
                return Err(std::io::Error::other("fixture entropy unavailable"));
            }

            Ok(())
        }
    }
}
