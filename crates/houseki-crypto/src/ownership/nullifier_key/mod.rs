//! Protected nullifier key material and internal commitment derivation.

#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "Ownership commitment composition is a separate increment."
    )
)]
mod commitment;
mod error;

pub use error::NullifierKeyError;

use crate::random::secret_bytes;
use getrandom::{SysRng, rand_core::TryCryptoRng};
use std::fmt;
use zeroize::Zeroize;

/// A protected 32 byte secret for Houseki's nullifier relation.
///
/// Generate fresh material with [`Self::generate`] or import an existing independent secret
/// with [`Self::from_bytes`], keeping it distinct from spending, encryption and signing keys.
///
/// The ownership design permits a full viewer to hold this secret without the spending key,
/// so possession alone does not confer spending authority.
///
/// The type keeps its bytes private and redacts debug output, with no cloning, equality or
/// serialization interface.
///
/// Stored bytes are zeroized on drop, although this cannot erase the caller's imported buffer
/// or every copy made by the compiler or operating system.
pub struct NullifierKey(
    /// Owned nullifier key bytes cleared when the key is dropped.
    [u8; 32],
);

impl NullifierKey {
    /// Number of bytes in a complete nullifier secret.
    pub const LENGTH: usize = 32;

    /// Generates an independent key using the system's cryptographic random source.
    ///
    /// Temporary entropy stays in guarded storage until copied into the key and is zeroized
    /// when dropped, including after a partial acquisition failure.
    ///
    /// # Errors
    ///
    /// Returns [`NullifierKeyError::RandomnessUnavailable`] without a key if the source cannot
    /// supply all 32 bytes.
    pub fn generate() -> Result<Self, NullifierKeyError> {
        Self::generate_with_rng(&mut SysRng)
    }

    /// Imports a complete nullifier secret without deriving or transforming its bytes.
    ///
    /// Every 32 byte value is representable, so the caller must supply independently sampled
    /// key material rather than a password, public commitment or secret reused from another role.
    ///
    /// Import cannot establish entropy or provenance and copies the borrowed bytes, leaving
    /// their original storage under the caller's ownership and cleanup responsibility.
    pub fn from_bytes(bytes: &[u8; Self::LENGTH]) -> Self {
        Self(*bytes)
    }

    /// Acquires the complete key through guarded storage using an internal entropy source.
    ///
    /// Incomplete acquisition returns an error without constructing a key.
    fn generate_with_rng<R: TryCryptoRng + ?Sized>(rng: &mut R) -> Result<Self, NullifierKeyError> {
        let bytes = secret_bytes::<{ Self::LENGTH }, _>(rng)
            .map_err(|_| NullifierKeyError::RandomnessUnavailable)?;
        Ok(Self::from_bytes(&bytes))
    }
}

impl fmt::Debug for NullifierKey {
    /// Writes a fixed redacted label without inspecting secret bytes.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("NullifierKey([REDACTED])")
    }
}

impl Drop for NullifierKey {
    /// Clears the owned nullifier secret before its storage is released.
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// Exact key import, complete entropy acquisition and redacted diagnostics.
#[cfg(test)]
mod tests {
    use getrandom::rand_core::{TryCryptoRng, TryRng};

    use super::{NullifierKey, NullifierKeyError};

    /// Checks exact import and independent ownership for representative complete byte values.
    #[test]
    fn import_preserves_all_bytes_without_borrowing_caller_storage() {
        assert_eq!(NullifierKey::LENGTH, 32);
        for expected in [
            [0; 32],
            [0xff; 32],
            std::array::from_fn(|i| u8::try_from(i).unwrap()),
        ] {
            let mut source = expected;
            let key = NullifierKey::from_bytes(&source);
            source.fill(0xa5);
            assert_eq!(key.0, expected);
            assert_eq!(source, [0xa5; 32]);
        }
    }

    /// Checks that generation consumes exactly 32 bytes without changing their order or value.
    #[test]
    fn generation_retains_all_requested_entropy_bytes() {
        let mut rng = FixtureRng::default();
        let key = NullifierKey::generate_with_rng(&mut rng).unwrap();
        assert_eq!(rng.position, 32);
        assert_eq!(key.0, std::array::from_fn(|i| u8::try_from(i).unwrap()));
    }

    /// Checks every partial entropy failure without accepting incomplete key material.
    #[test]
    fn generation_rejects_every_incomplete_entropy_fill() {
        for fail_after in 0..32 {
            let mut rng = FixtureRng {
                position: 0,
                fail_after: Some(fail_after),
            };
            assert!(matches!(
                NullifierKey::generate_with_rng(&mut rng),
                Err(NullifierKeyError::RandomnessUnavailable)
            ));
            assert_eq!(rng.position, fail_after);
        }
    }

    /// Checks that public generation obtains fresh material on successive calls.
    #[test]
    fn system_generation_produces_distinct_keys() {
        let first = NullifierKey::generate().unwrap();
        let second = NullifierKey::generate().unwrap();
        assert_ne!(first.0, second.0);
    }

    /// Checks fixed redaction in ordinary and alternate debug output for different secrets.
    #[test]
    fn diagnostics_never_include_key_bytes() {
        for bytes in [[0; 32], [0xff; 32]] {
            let key = NullifierKey::from_bytes(&bytes);
            assert_eq!(format!("{key:?}"), "NullifierKey([REDACTED])");
            assert_eq!(format!("{key:#?}"), "NullifierKey([REDACTED])");
        }
    }

    /// Predictable key material source with a configurable partial failure.
    #[derive(Default)]
    struct FixtureRng {
        /// Number of bytes successfully written by the source.
        position: usize,

        /// Optional byte count at which acquisition fails.
        fail_after: Option<usize>,
    }

    // This predictable source is confined to tests and cannot be supplied to public generation.
    impl TryCryptoRng for FixtureRng {}

    impl TryRng for FixtureRng {
        /// Synthetic error used for incomplete entropy acquisition.
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

        /// Writes the key fixture until its configured failure point or final byte.
        fn try_fill_bytes(&mut self, output: &mut [u8]) -> Result<(), Self::Error> {
            for byte in output {
                if self.position == self.fail_after.unwrap_or(32) {
                    return Err(std::io::Error::other("fixture entropy exhausted"));
                }
                *byte = u8::try_from(self.position).unwrap();
                self.position += 1;
            }
            Ok(())
        }
    }
}
