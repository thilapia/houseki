//! Internal V1 AEAD operations; payload headers and randomness belong to the suite.

mod error;

pub(super) use error::NoteAeadError;

use super::key_derivation::NoteEncryptionMaterial;
use aes_gcm_siv::{AeadInOut, Aes256GcmSiv, KeyInit};
use zeroize::Zeroizing;

impl NoteEncryptionMaterial {
    /// Consumes one derived key to return ciphertext followed by its 16-byte tag.
    ///
    /// The caller supplies canonical padded note bytes and an active inclusive
    /// plaintext limit. This is not the complete suite payload or envelope.
    ///
    /// The nonce is the one retained during derivation, not a new caller input.
    pub(super) fn seal(
        self,
        plaintext: &[u8],
        max_plaintext_bytes: usize,
    ) -> Result<Vec<u8>, NoteAeadError> {
        let length = sealed_length(
            plaintext.len(),
            self.associated_data.len(),
            max_plaintext_bytes,
        )?;
        // Reserve once, before copying plaintext, so growing for the tag never
        // reallocates a buffer that previously held plaintext.
        let mut buffer = Zeroizing::new(Vec::with_capacity(length));
        buffer.extend_from_slice(plaintext);
        let cipher = Aes256GcmSiv::new((&*self.key).into());
        let tag = cipher
            .encrypt_inout_detached(
                (&self.nonce).into(),
                &self.associated_data,
                buffer.as_mut_slice().into(),
            )
            .map_err(|_| NoteAeadError::EncryptionFailed)?;
        buffer.extend_from_slice(&tag);

        // Only ciphertext and its tag leave the guarded working buffer.
        Ok(std::mem::take(&mut *buffer))
    }

    /// Consumes one derived key and returns only authenticated plaintext.
    ///
    /// Short inputs and tag failures share an error. Size limits are checked
    /// before copying input; failed authentication drops the private guarded
    /// buffer.
    ///
    /// The caller's ciphertext is never modified. Success does not establish
    /// note validity, commitment agreement or transaction finality.
    pub(super) fn open(
        self,
        ciphertext: &[u8],
        max_plaintext_bytes: usize,
    ) -> Result<Zeroizing<Vec<u8>>, NoteAeadError> {
        let length = ciphertext
            .len()
            .checked_sub(16)
            .ok_or(NoteAeadError::AuthenticationFailed)?;
        sealed_length(length, self.associated_data.len(), max_plaintext_bytes)?;
        let (message, tag) = ciphertext.split_at(length);
        let tag: &[u8; 16] = tag.try_into().expect("exactly sixteen trailing tag bytes");
        let mut buffer = Zeroizing::new(message.to_vec());
        let cipher = Aes256GcmSiv::new((&*self.key).into());
        cipher
            .decrypt_inout_detached(
                (&self.nonce).into(),
                &self.associated_data,
                buffer.as_mut_slice().into(),
                tag.into(),
            )
            .map_err(|_| NoteAeadError::AuthenticationFailed)?;
        Ok(buffer)
    }
}

/// RFC 8452 per-message ceilings, not an aggregate security or usage budget.
fn sealed_length(plaintext: usize, aad: usize, maximum: usize) -> Result<usize, NoteAeadError> {
    if plaintext > maximum {
        return Err(NoteAeadError::PlaintextTooLong {
            actual: plaintext,
            maximum,
        });
    }
    let plaintext_u64 = u64::try_from(plaintext).map_err(|_| NoteAeadError::LengthLimitExceeded)?;
    let aad_u64 = u64::try_from(aad).map_err(|_| NoteAeadError::LengthLimitExceeded)?;
    if plaintext_u64 > aes_gcm_siv::P_MAX || aad_u64 > aes_gcm_siv::A_MAX {
        return Err(NoteAeadError::LengthLimitExceeded);
    }
    let length = plaintext
        .checked_add(16)
        .ok_or(NoteAeadError::LengthLimitExceeded)?;
    isize::try_from(length).map_err(|_| NoteAeadError::LengthLimitExceeded)?;
    Ok(length)
}

#[cfg(test)]
mod tests {
    use super::{NoteAeadError, NoteEncryptionMaterial, Zeroizing, sealed_length};

    fn material(aad: &[u8]) -> NoteEncryptionMaterial {
        let mut key = [0; 32];
        key[0] = 1;
        let mut nonce = [0; 12];
        nonce[0] = 3;
        NoteEncryptionMaterial {
            key: Zeroizing::new(key),
            associated_data: aad.to_vec(),
            nonce,
        }
    }

    fn decode(hex: &str) -> Vec<u8> {
        hex.as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect()
    }

    #[test]
    fn seal_and_open_match_rfc8452_aes256_vectors() {
        // RFC 8452 Appendix C.2: empty, partial and full blocks, with/without AAD.
        for (plaintext, aad, sealed) in [
            ("", "", "07f5f4169bbf55a8400cd47ea6fd400f"),
            (
                "0100000000000000",
                "",
                "c2ef328e5c71c83b843122130f7364b761e0b97427e3df28",
            ),
            (
                "0200000000000000",
                "01",
                "1de22967237a813291213f267e3b452f02d01ae33e4ec854",
            ),
            (
                "02000000000000000000000000000000",
                "01",
                "c91545823cc24f17dbb0e9e807d5ec17b292d28ff61189e8e49f3875ef91aff7",
            ),
        ] {
            let plaintext = decode(plaintext);
            let aad = decode(aad);
            let sealed = decode(sealed);
            assert_eq!(
                material(&aad).seal(&plaintext, plaintext.len()).unwrap(),
                sealed
            );
            assert_eq!(
                *material(&aad).open(&sealed, plaintext.len()).unwrap(),
                plaintext
            );
        }
    }

    #[test]
    fn every_ciphertext_and_tag_byte_is_authenticated() {
        let sealed = material(b"bound context")
            .seal(b"private note bytes", 18)
            .unwrap();
        for i in 0..sealed.len() {
            let mut altered = sealed.clone();
            altered[i] ^= 1;
            let before = altered.clone();
            assert_eq!(
                material(b"bound context").open(&altered, 100).unwrap_err(),
                NoteAeadError::AuthenticationFailed
            );
            assert_eq!(altered, before);
        }
        for length in 0..sealed.len() {
            assert_eq!(
                material(b"bound context")
                    .open(&sealed[..length], 100)
                    .unwrap_err(),
                NoteAeadError::AuthenticationFailed
            );
        }
        let mut extended = sealed;
        extended.push(0);
        assert_eq!(
            material(b"bound context").open(&extended, 100).unwrap_err(),
            NoteAeadError::AuthenticationFailed
        );
    }

    #[test]
    fn altered_key_nonce_and_associated_data_release_no_plaintext() {
        let sealed = material(b"context").seal(b"note", 4).unwrap();
        for index in 0..32 {
            let mut changed = material(b"context");
            changed.key[index] ^= 1;
            assert_eq!(
                changed.open(&sealed, 4).unwrap_err(),
                NoteAeadError::AuthenticationFailed
            );
        }
        for index in 0..12 {
            let mut changed = material(b"context");
            changed.nonce[index] ^= 1;
            assert_eq!(
                changed.open(&sealed, 4).unwrap_err(),
                NoteAeadError::AuthenticationFailed
            );
        }
        assert_eq!(
            material(b"contexu").open(&sealed, 4).unwrap_err(),
            NoteAeadError::AuthenticationFailed
        );
    }

    #[test]
    fn caller_limits_are_inclusive_and_empty_plaintext_is_authenticated() {
        assert_eq!(
            material(b"").seal(b"note", 3).unwrap_err(),
            NoteAeadError::PlaintextTooLong {
                actual: 4,
                maximum: 3
            }
        );
        let sealed = material(b"").seal(b"note", 4).unwrap();
        assert_eq!(
            material(b"").open(&sealed, 3).unwrap_err(),
            NoteAeadError::PlaintextTooLong {
                actual: 4,
                maximum: 3
            }
        );
        assert_eq!(&**material(b"").open(&sealed, 4).unwrap(), b"note");
        let empty = material(b"").seal(b"", 0).unwrap();
        assert_eq!(empty.len(), 16);
        assert!(material(b"").open(&empty, 0).unwrap().is_empty());
    }

    #[test]
    fn algorithm_and_host_length_limits_are_checked_without_large_allocations() {
        assert_eq!(sealed_length(0, 0, 0), Ok(16));
        assert_eq!(sealed_length(16, 1949, 16), Ok(32));
        assert_eq!(
            sealed_length(17, 1949, 16),
            Err(NoteAeadError::PlaintextTooLong {
                actual: 17,
                maximum: 16
            })
        );
        assert_eq!(
            sealed_length(usize::MAX, 0, usize::MAX),
            Err(NoteAeadError::LengthLimitExceeded)
        );
        if let Ok(limit) = usize::try_from(1_u64 << 36) {
            assert_eq!(sealed_length(limit, limit, limit), Ok(limit + 16));
            assert_eq!(
                sealed_length(limit + 1, 0, usize::MAX),
                Err(NoteAeadError::LengthLimitExceeded)
            );
            assert_eq!(
                sealed_length(0, limit + 1, usize::MAX),
                Err(NoteAeadError::LengthLimitExceeded)
            );
        }
    }
}
