//! Fixed identifiers derived from actual typed canonical bodies and operational public keys.

mod account;
mod error;

pub use error::BodyHashError;

use houseki_types::{BodyCodecLimits, PaymentBody, RewardWithdrawalBody, TransactionId};

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
    use crate::{BodyHashError, payment_transaction_id, withdrawal_transaction_id};
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
}
