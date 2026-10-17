//! Fixed transcription checksums for complete binary recipient descriptors.

use crate::CryptoFramingError;

/// Derives the eight byte transcription checksum for all 1704 descriptor bytes.
///
/// The fixed SHA3-512 frame contains one complete binary descriptor and truncates the digest
/// to its first eight stored bytes, independently of any text alphabet.
///
/// A checksum establishes neither valid descriptor encoding nor recipient identity.
///
/// # Errors
///
/// Returns the original framing failure without a checksum, although the part length is fixed.
pub fn recipient_descriptor_checksum(bytes: &[u8; 1704]) -> Result<[u8; 8], CryptoFramingError> {
    let digest = crate::hash::sha3_512(|sink| {
        let mut frame = crate::domain::Frame::new(crate::domain::Domain::AddressChecksum, 1, sink);
        frame.part(bytes)?;
        frame.finish()
    })?;

    Ok(digest[..8]
        .try_into()
        .expect("fixed checksum prefix length"))
}
