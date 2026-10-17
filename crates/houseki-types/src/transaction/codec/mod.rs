//! Exact canonical transaction body version 1 with caller supplied allocation bounds.

mod error;
mod limits;
mod payment;
mod reader;
mod withdrawal;
mod writer;

pub use error::BodyCodecError;
pub use limits::BodyCodecLimits;

/// Rejects an excessive complete byte count before reading or allocating a body.
fn bound_body(actual: usize, limits: BodyCodecLimits) -> Result<usize, BodyCodecError> {
    if actual > limits.max_body_bytes() {
        return Err(BodyCodecError::BodyTooLong {
            actual,
            maximum: limits.max_body_bytes(),
        });
    }

    Ok(actual)
}

/// Rejects excessive opaque payload bytes before copying them.
fn bound_payload(actual: usize, limits: BodyCodecLimits) -> Result<(), BodyCodecError> {
    if actual > limits.max_payload_bytes() {
        return Err(BodyCodecError::PayloadTooLong {
            actual,
            maximum: limits.max_payload_bytes(),
        });
    }

    Ok(())
}

/// Reserves a bounded list without returning partially populated storage on failure.
fn reserve<T>(length: usize) -> Result<Vec<T>, BodyCodecError> {
    let mut values = Vec::new();
    values
        .try_reserve_exact(length)
        .map_err(|_| BodyCodecError::AllocationFailed)?;

    Ok(values)
}

/// Independent offset fixtures and adversarial length and invariant checks.
#[cfg(test)]
mod tests {
    use crate::*;

    /// Permits the complete independent fixtures and arbitrary opaque payload contents.
    fn limits() -> BodyCodecLimits {
        BodyCodecLimits::new(PaymentCountLimits::new(2, 2).unwrap(), 3, 5000)
    }

    /// Fills the common header using fixed byte offsets from the adopted codec table.
    fn header(bytes: &mut [u8], kind: u8) {
        bytes[0] = 1;
        bytes[4] = kind;
        bytes[8..72].fill(7);
        bytes[72] = 2;
        bytes[76] = 3;
        bytes[80] = 4;
        bytes[84] = 5;
        bytes[92] = 8;
    }

    /// Fills a complete output at an independently specified offset with a three byte payload.
    fn output(bytes: &mut [u8], start: usize) {
        bytes[start..start + 64].fill(11);
        bytes[start + 64..start + 1632].fill(12);
        bytes[start + 1632] = 3;
        bytes[start + 1640..start + 1643].copy_from_slice(&[0, 1, 2]);
    }

    /// Builds independent payment bytes with distinct inputs and repeated ordinary outputs.
    fn payment() -> Vec<u8> {
        let mut bytes = vec![0; 3610];
        header(&mut bytes, 1);
        bytes[100..164].fill(8);
        bytes[164] = 2;
        bytes[172..236].fill(9);
        bytes[236..300].fill(10);
        bytes[300] = 17;
        bytes[316] = 2;
        output(&mut bytes, 324);
        output(&mut bytes, 1967);

        bytes
    }

    /// Builds independent withdrawal bytes with a full authority key and separate amount and fee.
    fn withdrawal() -> Vec<u8> {
        let mut bytes = vec![0; 4439];
        header(&mut bytes, 2);
        bytes[100..164].fill(13);
        bytes[164..2756].fill(14);
        bytes[2756..2764].copy_from_slice(&u64::MAX.to_le_bytes());
        bytes[2764..2780].copy_from_slice(&((1_u128 << 64) + 3).to_le_bytes());
        bytes[2780] = 17;
        output(&mut bytes, 2796);

        bytes
    }

    /// Checks exact fields, multiplicity, complete envelopes and byte stability against fixed offsets.
    #[test]
    fn body_codecs_match_independent_offset_fixtures() {
        let bytes = payment();

        let body = PaymentBody::from_bytes(&bytes, limits()).unwrap();

        assert_eq!(body.context().network_id(), NetworkId::from_bytes([7; 64]));
        assert_eq!(body.context().validity_checkpoint_range().end().value(), 8);
        assert_eq!(body.inputs().anchor(), NoteRoot::from_bytes([8; 64]));
        assert_eq!(
            body.inputs().nullifiers(),
            &[
                Nullifier::from_bytes([9; 64]),
                Nullifier::from_bytes([10; 64])
            ]
        );
        assert_eq!(body.public_fee().atoms(), 17);
        assert_eq!(body.outputs().output_count(), 2);
        assert_eq!(body.outputs().outputs()[0], body.outputs().outputs()[1]);
        assert_eq!(body.outputs().outputs()[0].envelope().payload(), &[0, 1, 2]);
        assert_eq!(body.to_bytes(limits()).unwrap(), bytes);
        assert_eq!(body.encoded_len(limits()).unwrap(), bytes.len());

        let bytes = withdrawal();

        let body = RewardWithdrawalBody::from_bytes(&bytes, limits()).unwrap();

        assert_eq!(
            body.reward_account_id(),
            RewardAccountId::from_bytes([13; 64])
        );
        assert_eq!(body.withdrawal_public_key().as_bytes(), &[14; 2592]);
        assert_eq!(body.nonce().value(), u64::MAX);
        assert_eq!(body.public_amount().atoms(), (1_u128 << 64) + 3);
        assert_eq!(body.public_fee().atoms(), 17);
        assert_eq!(body.to_bytes(limits()).unwrap(), bytes);
        assert_eq!(body.encoded_len(limits()).unwrap(), bytes.len());
    }

    /// Rejects every incomplete prefix, extensions and full width unsupported header values.
    #[test]
    fn body_decoders_require_exact_complete_supported_records() {
        for bytes in [payment(), withdrawal()] {
            for length in 0..bytes.len() {
                let result = if bytes[4] == 1 {
                    PaymentBody::from_bytes(&bytes[..length], limits()).map(|_| ())
                } else {
                    RewardWithdrawalBody::from_bytes(&bytes[..length], limits()).map(|_| ())
                };

                assert!(result.is_err(), "accepted truncated body at {length}");
            }

            let mut trailing = bytes.clone();
            trailing.push(0);

            let result = if bytes[4] == 1 {
                PaymentBody::from_bytes(&trailing, limits()).map(|_| ())
            } else {
                RewardWithdrawalBody::from_bytes(&trailing, limits()).map(|_| ())
            };

            assert!(matches!(result, Err(BodyCodecError::TrailingBytes)));
        }

        for value in [0_u32, 2, 257, 0x0100_0001, u32::MAX] {
            let mut bytes = payment();
            bytes[..4].copy_from_slice(&value.to_le_bytes());

            assert!(
                matches!(PaymentBody::from_bytes(&bytes, limits()), Err(BodyCodecError::UnsupportedVersion {version}) if version == value)
            );
        }

        for value in [0_u32, 2, 257, u32::MAX] {
            let mut bytes = payment();
            bytes[4..8].copy_from_slice(&value.to_le_bytes());

            assert!(
                matches!(PaymentBody::from_bytes(&bytes, limits()), Err(BodyCodecError::UnexpectedKind {actual, expected:1}) if actual == value)
            );
        }

        assert!(matches!(
            RewardWithdrawalBody::from_bytes(&payment(), limits()),
            Err(BodyCodecError::UnexpectedKind {
                actual: 1,
                expected: 2
            })
        ));
    }

    /// Bounds declared lengths and actual encoding before allocations and preserves body values.
    #[test]
    fn body_codec_limits_and_declared_lengths_are_checked() {
        let bytes = payment();

        let body = PaymentBody::from_bytes(&bytes, limits()).unwrap();

        for maximum in [0, bytes.len() - 1] {
            let bound = BodyCodecLimits::new(limits().payment_counts(), 3, maximum);

            assert!(matches!(
                body.to_bytes(bound),
                Err(BodyCodecError::BodyTooLong { .. })
            ));
            assert!(matches!(
                PaymentBody::from_bytes(&bytes, bound),
                Err(BodyCodecError::BodyTooLong { .. })
            ));
        }

        let exact = BodyCodecLimits::new(limits().payment_counts(), 3, bytes.len());

        assert_eq!(body.to_bytes(exact).unwrap(), bytes);

        let payload_bound = BodyCodecLimits::new(limits().payment_counts(), 2, 5000);

        assert!(matches!(
            body.to_bytes(payload_bound),
            Err(BodyCodecError::PayloadTooLong {
                actual: 3,
                maximum: 2
            })
        ));
        assert!(matches!(
            PaymentBody::from_bytes(&bytes, payload_bound),
            Err(BodyCodecError::PayloadTooLong {
                actual: 3,
                maximum: 2
            })
        ));

        for offset in [164, 316, 1956, 3599] {
            let mut changed = bytes.clone();
            changed[offset..offset + 8].copy_from_slice(&u64::MAX.to_le_bytes());

            assert!(PaymentBody::from_bytes(&changed, limits()).is_err());
        }

        let loose = BodyCodecLimits::new(
            PaymentCountLimits::new(usize::MAX, usize::MAX).unwrap(),
            usize::MAX,
            usize::MAX,
        );

        for offset in [164, 316] {
            let mut changed = bytes.clone();
            changed[offset..offset + 8].copy_from_slice(&u64::MAX.to_le_bytes());

            assert!(PaymentBody::from_bytes(&changed, loose).is_err());
        }

        let restricted = BodyCodecLimits::new(PaymentCountLimits::new(1, 1).unwrap(), 3, 5000);

        assert!(body.to_bytes(restricted).is_err());
        assert!(PaymentBody::from_bytes(&bytes, restricted).is_err());

        assert_eq!(body.to_bytes(limits()).unwrap(), bytes);
    }

    /// Reuses amount, validity and ordered list invariants without treating opaque payloads as valid crypto.
    #[test]
    fn decoded_body_invariants_reject_malformed_public_values() {
        let bytes = payment();

        for offset in [164, 316] {
            let mut changed = bytes.clone();
            changed[offset..offset + 8].fill(0);

            assert!(PaymentBody::from_bytes(&changed, limits()).is_err());
        }

        let mut changed = bytes.clone();
        changed[236..300].fill(9);

        assert!(matches!(
            PaymentBody::from_bytes(&changed, limits()),
            Err(BodyCodecError::Inputs(
                PaymentInputsError::DuplicateNullifier { .. }
            ))
        ));

        let mut changed = bytes.clone();
        changed[300..316].copy_from_slice(&(Amount::MAX_ATOMS + 1).to_le_bytes());

        assert!(matches!(
            PaymentBody::from_bytes(&changed, limits()),
            Err(BodyCodecError::Amount(_))
        ));

        let mut changed = bytes;
        changed[84] = 9;

        assert!(matches!(
            PaymentBody::from_bytes(&changed, limits()),
            Err(BodyCodecError::Validity(_))
        ));

        for atoms in [0, Amount::MAX_ATOMS + 1] {
            let mut changed = withdrawal();
            changed[2764..2780].copy_from_slice(&atoms.to_le_bytes());

            assert!(RewardWithdrawalBody::from_bytes(&changed, limits()).is_err());
        }

        for atoms in [1, Amount::MAX_ATOMS] {
            let mut changed = withdrawal();
            changed[2764..2780].copy_from_slice(&atoms.to_le_bytes());

            let body = RewardWithdrawalBody::from_bytes(&changed, limits()).unwrap();

            assert_eq!(body.to_bytes(limits()).unwrap(), changed);
        }
    }
}
