//! Protected random buffers shared by cryptographic operations.

use getrandom::rand_core::TryCryptoRng;
use zeroize::Zeroizing;

/// Fills a secret buffer completely or propagates the source's error.
///
/// Storage is zeroized when dropped, including after a partial fill fails.
pub(crate) fn secret_bytes<const N: usize, R: TryCryptoRng + ?Sized>(
    rng: &mut R,
) -> Result<Zeroizing<[u8; N]>, R::Error> {
    let mut bytes = Zeroizing::new([0; N]);
    rng.try_fill_bytes(bytes.as_mut())?;

    Ok(bytes)
}
