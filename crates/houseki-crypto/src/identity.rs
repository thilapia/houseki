//! Fixed identifiers derived from actual typed canonical bodies and operational public keys.

use crate::{CryptoFramingError, MlDsa87VerificationKey};
use houseki_types::{
    BodyCodecError, BodyCodecLimits, NetworkId, PaymentBody, RewardAccountId, RewardWithdrawalBody,
    TransactionId,
};
use thiserror::Error;

/// A failure to encode or frame the actual body for transaction identification.
#[derive(Debug, Error)]
pub enum BodyHashError {
    /// Active bounds or canonical representation prevented complete body encoding.
    #[error("could not encode transaction body: {0}")]
    Encoding(
        /// Original bounded canonical codec failure.
        #[from]
        BodyCodecError,
    ),

    /// Fixed domain framing failed without returning an identifier.
    #[error("could not frame transaction identity: {0}")]
    Framing(
        /// Original safe framing failure.
        #[from]
        CryptoFramingError,
    ),
}

/// Derives payment identity from the complete V1 body and its fixed operation tag.
///
/// Ordered envelopes are included, while proofs are excluded by the typed input boundary.
///
/// # Errors
///
/// Rechecks active canonical encoding limits before framing the complete body under SHA3-512.
pub fn payment_transaction_id(
    body: &PaymentBody,
    limits: BodyCodecLimits,
) -> Result<TransactionId, BodyHashError> {
    identifier(1, &body.to_bytes(limits)?)
}

/// Derives withdrawal identity from its complete V1 body and fixed operation tag.
///
/// Proofs and signatures are excluded, with authority, nonce, amounts and full output included.
///
/// # Errors
///
/// Rechecks active canonical encoding limits and preserves safe codec and framing failures.
pub fn withdrawal_transaction_id(
    body: &RewardWithdrawalBody,
    limits: BodyCodecLimits,
) -> Result<TransactionId, BodyHashError> {
    identifier(2, &body.to_bytes(limits)?)
}

impl MlDsa87VerificationKey {
    /// Derives the immutable account identifier for this operational authority under one network.
    ///
    /// The fixed Poseidon2 transcript binds the complete network, scheme 1 for ML-DSA-87 and
    /// all 2592 public key bytes, independently of balance and nonce.
    ///
    /// This establishes neither possession, registration, account state nor withdrawal authority.
    ///
    /// # Errors
    ///
    /// Returns the original framing failure without a digest, although input lengths are fixed.
    pub fn reward_account_id(
        &self,
        network: NetworkId,
    ) -> Result<RewardAccountId, CryptoFramingError> {
        let encoded = self.to_encoded();
        let digest = crate::hash::poseidon2(
            crate::domain::Domain::RewardAccountIdentity,
            &[network.as_bytes(), &1_u32.to_le_bytes(), encoded.as_bytes()],
        )?;
        Ok(RewardAccountId::from_bytes(digest))
    }
}

/// Hashes only an internally encoded body and the operation fixed by its typed caller.
fn identifier(kind: u32, bytes: &[u8]) -> Result<TransactionId, BodyHashError> {
    let digest = crate::hash::sha3_512(|sink| {
        let mut frame =
            crate::domain::Frame::new(crate::domain::Domain::TransactionIdentity, 2, sink);
        frame.part(&kind.to_le_bytes())?;
        frame.part(bytes)?;
        frame.finish()
    })?;
    Ok(TransactionId::from_bytes(digest))
}

/// Independent canonical identity fixtures and exact role and field binding.
#[cfg(test)]
mod tests {
    use crate::{
        BodyHashError, MlDsa87VerificationKey, payment_transaction_id, withdrawal_transaction_id,
    };
    use houseki_types::*;

    /// Returns bounds that admit the complete independently specified public fixtures.
    fn limits() -> BodyCodecLimits {
        BodyCodecLimits::new(PaymentCountLimits::new(2, 2).unwrap(), 3, 5000)
    }

    /// Produces public body bytes at independent offsets from the adopted codec tables.
    fn fixture(withdrawal: bool) -> Vec<u8> {
        let mut bytes = vec![0; if withdrawal { 4439 } else { 3610 }];
        bytes[0] = 1;
        bytes[4] = if withdrawal { 2 } else { 1 };
        bytes[8..72].fill(7);
        bytes[72] = 2;
        bytes[76] = 3;
        bytes[80] = 4;
        bytes[84] = 5;
        bytes[92] = 8;
        let offsets: &[usize] = if withdrawal {
            bytes[100..164].fill(13);
            bytes[164..2756].fill(14);
            bytes[2756..2764].fill(255);
            bytes[2764..2780].copy_from_slice(&((1_u128 << 64) + 3).to_le_bytes());
            bytes[2780] = 17;
            &[2796]
        } else {
            bytes[100..164].fill(8);
            bytes[164] = 2;
            bytes[172..236].fill(9);
            bytes[236..300].fill(10);
            bytes[300] = 17;
            bytes[316] = 2;
            &[324, 1967]
        };
        for &start in offsets {
            bytes[start..start + 64].fill(11);
            bytes[start + 64..start + 1632].fill(12);
            bytes[start + 1632] = 3;
            bytes[start + 1640..start + 1643].copy_from_slice(&[0, 1, 2]);
        }
        bytes
    }

    /// Formats only public digests for independent known answer comparison.
    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// Checks both complete body identifiers against Python hashlib and explicit Frame encoding.
    #[test]
    fn transaction_identifiers_match_independent_vectors() {
        let payment = PaymentBody::from_bytes(&fixture(false), limits()).unwrap();
        let withdrawal = RewardWithdrawalBody::from_bytes(&fixture(true), limits()).unwrap();
        assert_eq!(
            hex(payment_transaction_id(&payment, limits())
                .unwrap()
                .as_bytes()),
            "38e6bd1f36bf43b8783d3ea463858deca2fc09b37f1a230593615ad4ee415c88cfa473860ba099ecfb21f41ea2698c0134ea4e1b5ec02684cb660da38e24396b"
        );
        assert_eq!(
            hex(withdrawal_transaction_id(&withdrawal, limits())
                .unwrap()
                .as_bytes()),
            "2052fccd53daab1cc37be64b275eddb0da26dcede38bb7785f76ad12bfd9bebe9be49c7579dd48b94b73e2de75291ab1d343823abda08e47bfeea0552bea613b"
        );
        let loose = BodyCodecLimits::new(PaymentCountLimits::new(3, 3).unwrap(), 99, 9999);
        assert_eq!(
            payment_transaction_id(&payment, limits()).unwrap(),
            payment_transaction_id(&payment, loose).unwrap()
        );
    }

    /// Checks full context, lists, authority and envelope coverage with each field remaining representable.
    #[test]
    fn body_identifiers_bind_all_public_effect_fields_and_active_limits() {
        let original = fixture(false);
        let body = PaymentBody::from_bytes(&original, limits()).unwrap();
        let expected = payment_transaction_id(&body, limits()).unwrap();
        for offset in [
            8, 71, 72, 75, 76, 79, 80, 83, 84, 99, 100, 163, 172, 235, 236, 299, 300, 312, 324,
            387, 388, 1955, 1964, 1966, 1967, 2030, 2031, 3598, 3607, 3609,
        ] {
            let mut bytes = original.clone();
            bytes[offset] ^= 1;
            let changed = PaymentBody::from_bytes(&bytes, limits()).unwrap();
            assert_ne!(
                payment_transaction_id(&changed, limits()).unwrap(),
                expected,
                "offset {offset}"
            );
        }
        let original = fixture(true);
        let body = RewardWithdrawalBody::from_bytes(&original, limits()).unwrap();
        let expected = withdrawal_transaction_id(&body, limits()).unwrap();
        for offset in [
            8, 71, 72, 76, 80, 84, 92, 100, 163, 164, 2755, 2756, 2763, 2764, 2772, 2780, 2796,
            2859, 2860, 4427, 4436, 4438,
        ] {
            let mut bytes = original.clone();
            bytes[offset] ^= 1;
            let changed = RewardWithdrawalBody::from_bytes(&bytes, limits()).unwrap();
            assert_ne!(
                withdrawal_transaction_id(&changed, limits()).unwrap(),
                expected,
                "offset {offset}"
            );
        }
        let tight = BodyCodecLimits::new(limits().payment_counts(), 2, 5000);
        assert!(matches!(
            withdrawal_transaction_id(&body, tight),
            Err(BodyHashError::Encoding(
                BodyCodecError::PayloadTooLong { .. }
            ))
        ));
    }

    /// Checks a complete account transcript with independent integer Poseidon2 and full input binding.
    #[test]
    fn account_identifiers_match_independent_vectors_and_bind_network_and_key() {
        let network = NetworkId::from_bytes([7; 64]);
        let encoded = EncodedMlDsa87PublicKey::from_bytes([14; 2592]);
        let key = MlDsa87VerificationKey::from_encoded(&encoded);
        let expected = key.reward_account_id(network).unwrap();
        assert_eq!(
            hex(expected.as_bytes()),
            "2deed4beb8cc9a66425049ef33a0e1639b43da6657810edea2885197800f9eff972f04a1e95b97fad1e1c9432474709bb3e355712b834ead7e239c5f1e5aee29"
        );
        for index in 0..64 {
            let mut bytes = [7; 64];
            bytes[index] ^= 1;
            assert_ne!(
                key.reward_account_id(NetworkId::from_bytes(bytes)).unwrap(),
                expected
            );
        }
        for index in [0, 31, 32, 33, 511, 1023, 2047, 2591] {
            let mut bytes = [14; 2592];
            bytes[index] ^= 1;
            let changed =
                MlDsa87VerificationKey::from_encoded(&EncodedMlDsa87PublicKey::from_bytes(bytes));
            assert_ne!(changed.reward_account_id(network).unwrap(), expected);
        }
        assert_eq!(key.to_encoded(), encoded);
        assert_eq!(key.reward_account_id(network).unwrap(), expected);
    }
}
