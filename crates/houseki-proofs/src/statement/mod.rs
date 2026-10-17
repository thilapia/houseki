//! Reconstructs semantic public values and complete transcript binding from native bodies.

mod error;
mod payment;
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "family AIR endpoint consumers follow")
)]
mod payment_values;
mod withdrawal;
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "family AIR endpoint consumers follow")
)]
mod withdrawal_values;

pub use error::StatementError;

pub(crate) use payment_values::PaymentValues;
pub(crate) use withdrawal_values::WithdrawalValues;

use crate::profile::{ExpectedIdentity, Relation};
use houseki_types::{BodyCodecError, TransactionContext};
use p3_field::PrimeCharacteristicRing;
use p3_goldilocks::Goldilocks;

/// Independently reconstructed public effects and their complete transcript binding.
pub(crate) struct Statement {
    /// Byte valued semantic inputs in the selected family's exact order.
    pub(crate) public_values: Vec<Goldilocks>,

    /// Complete initial challenger state including the canonical body.
    pub(crate) prefix: Vec<u8>,
}

/// Prevents the expected statement from crossing a profile, operation or layout boundary.
fn require_identity(
    identity: &ExpectedIdentity,
    expected: TransactionContext,
    relation: Relation,
    shape: u32,
) -> Result<(), StatementError> {
    if identity.profile != expected.proof_profile_id()
        || identity.relation != relation
        || identity.shape != shape
    {
        return Err(StatementError::IdentityMismatch);
    }

    Ok(())
}

/// Reserves already bounded public storage and propagates allocation failure.
fn reserve<T>(count: usize) -> Result<Vec<T>, StatementError> {
    let mut values = Vec::new();
    values
        .try_reserve_exact(count)
        .map_err(|_| BodyCodecError::AllocationFailed)?;

    Ok(values)
}

/// Binds the complete body and expected effects before the first backend challenge.
fn bind(
    identity: &ExpectedIdentity,
    body: &[u8],
    metadata: &[u8],
    public: &[u8],
) -> Result<Statement, StatementError> {
    let domain = b"houseki/proofs/statement/v1";
    let length = 2 + domain.len() + 88 + 8 + body.len() + 4 + metadata.len() + 4 + 8 * public.len();

    let mut prefix = reserve(length)?;
    prefix.extend_from_slice(&(domain.len() as u16).to_le_bytes());
    prefix.extend_from_slice(domain);
    prefix.extend_from_slice(&identity.to_bytes());
    prefix.extend_from_slice(&(body.len() as u64).to_le_bytes());
    prefix.extend_from_slice(body);
    prefix.extend_from_slice(&(metadata.len() as u32).to_le_bytes());
    prefix.extend_from_slice(metadata);
    prefix.extend_from_slice(&(public.len() as u32).to_le_bytes());

    let mut public_values = reserve(public.len())?;
    for byte in public {
        prefix.extend_from_slice(&u64::from(*byte).to_le_bytes());
        public_values.push(Goldilocks::from_u8(*byte));
    }

    Ok(Statement {
        public_values,
        prefix,
    })
}

/// Native body binding and trusted identity properties.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::{ExpectedIdentity, Relation};
    use houseki_types::*;
    use sha3::{Digest, Sha3_512};

    /// Relation, counts, anchor count, lengths and expected digest of one public fixture.
    type Case = (u32, usize, usize, u128, usize, usize, usize, &'static str);

    /// Expected digest records from independently encoded Stage 03 public fixtures.
    const CASES: &[Case] = &[
        (
            1,
            1,
            1,
            137,
            3,
            1903,
            288,
            "b533690ce34c42e0ac8a19aa373f1af884afdda948daab79e2f13afd668be2e99945a4a06c84e689f95e0e2773a25c0d9fd1cec00570a56734cb46d22e64ab19",
        ),
        (
            1,
            1,
            2,
            137,
            3,
            3546,
            352,
            "70af2111a546749d63b008dd9f25ea095559d407afc909e0f08ba06c2ca2c514f3d3dd67ded2dda84a99251746aa817d560642dddcd40fee2a9beab91c7e3bee",
        ),
        (
            1,
            2,
            1,
            137,
            3,
            1967,
            352,
            "f1b95442afed4c40aaff9c9f2d1e0bb2b645759687b80f6f0b83b588384508e7c507655825486ef0e5994fc4215852f9d19975a8cc85d2082c08228fdcb83c96",
        ),
        (
            1,
            2,
            2,
            137,
            3,
            3610,
            416,
            "baa0e78025edfa0c5e595c78f07749a659e9a2487f7746bbc7188779aa1c5e380417def7f5478dbc96c88a0448452e2dd59304febdc66af8754017281df13128",
        ),
        (
            1,
            1,
            1,
            1,
            3,
            1903,
            288,
            "bb990e36c05a23ee1b47f2748a309fb24b5f1ca81991c1ee062bedf31457d66a265c8f4021aa2871e625b632eefeb9d55d491b73ab4e11de8636d439fd64579a",
        ),
        (
            1,
            1,
            1,
            18446744073709551616,
            3,
            1903,
            288,
            "f0344c86902ebf21deba8f157375ae762b8e9677d08f0dec1c1adcd1dae7ac36587f9771cb16bf0a00ddc686429c3760e3431c2b979bb9cea9ebce6c8fb141b1",
        ),
        (
            2,
            0,
            1,
            0,
            3,
            4439,
            144,
            "0be8e620bff0016bb76f26e3ec18dc5e14b458db7359efddc5a84b48f5ea06f88a18161680a4ec4299afd0c1f2ca7fbcea1d78e1cbdccf9c2844fea356892e24",
        ),
        (
            1,
            2,
            2,
            137,
            0,
            3604,
            416,
            "f216d39f688b0d8d804b75f2e76bee268f29c051d5ba0d225919d58a0e9c6941085243f67cca5a1e8e8ae1358d722f68a9ac08f004c1c5d3c7beaa66b4ab5125",
        ),
        (
            2,
            0,
            1,
            0,
            0,
            4436,
            144,
            "4bc635df6b257cb83ddef986e54d4466aca378f4730d082a6e872f96404402efdb641bdf4a9066f2fd72f8fba0bc21c06aade15491e89cf17d3a8fe6ddf5357d",
        ),
        (
            1,
            2,
            2,
            137,
            4096,
            11796,
            416,
            "2794d2e7e334c6ba8defd0c8914b11a0b41773e2b5a90cac4f2d17e75f6071b0fa404db637adf09aebdb42cfd88348022e7fb8563ca2a1bcfc22bbde8f6c998f",
        ),
        (
            2,
            0,
            1,
            0,
            4096,
            8532,
            144,
            "c4054f9d483563fc866678652d843cc7842a23d857354fd1bfd8bdc6234dc089625ee0718620baaa37e1e963965e395a40c0593181d6f5204aac4965e2cbb563",
        ),
    ];

    /// Encodes synthetic public bodies with fixed offsets independently of the statement builder.
    fn body_bytes(relation: u32, inputs: usize, outputs: usize, payload_len: usize) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&1_u32.to_le_bytes());
        bytes.extend_from_slice(&relation.to_le_bytes());
        bytes.extend_from_slice(&[7; 64]);
        for value in [1_u32, 0xffff0003, 4] {
            bytes.extend_from_slice(&value.to_le_bytes());
        }

        bytes.extend_from_slice(&5_u64.to_le_bytes());
        bytes.extend_from_slice(&8_u64.to_le_bytes());

        if relation == 1 {
            bytes.extend_from_slice(&[8; 64]);
            bytes.extend_from_slice(&(inputs as u64).to_le_bytes());
            for index in 0..inputs {
                bytes.extend_from_slice(&[9 + index as u8; 64]);
            }

            bytes.extend_from_slice(&17_u128.to_le_bytes());
            bytes.extend_from_slice(&(outputs as u64).to_le_bytes());
        } else {
            bytes.extend_from_slice(&[13; 64]);
            bytes.extend_from_slice(&[14; 2592]);
            bytes.extend_from_slice(&u64::MAX.to_le_bytes());
            bytes.extend_from_slice(&((1_u128 << 64) + 3).to_le_bytes());
            bytes.extend_from_slice(&17_u128.to_le_bytes());
        }

        for index in 0..outputs {
            bytes.extend_from_slice(&[11 + index as u8; 64]);
            bytes.extend_from_slice(&[21 + index as u8; 1568]);
            bytes.extend_from_slice(&(payload_len as u64).to_le_bytes());
            if payload_len == 3 {
                bytes.extend_from_slice(&[0, 1, 2]);
            } else {
                bytes.extend(std::iter::repeat_n(255, payload_len));
            }
        }

        bytes
    }

    /// Constructs the test identity without adding it to production profile recognition.
    fn identity(relation: u32, inputs: usize, outputs: usize) -> ExpectedIdentity {
        ExpectedIdentity {
            profile: ProofProfileId::new(0xffff0003),
            relation: if relation == 1 {
                Relation::Payment
            } else {
                Relation::RewardWithdrawal
            },
            shape: if relation == 1 {
                ((inputs as u32) << 8) | outputs as u32
            } else {
                1
            },
            manifest: Sha3_512::digest(b"houseki/experiment/03/toy-square/v1").into(),
        }
    }

    /// Reproduces native bytes, public value placement and initial transcript golden digests.
    #[test]
    fn statements_match_native_codec_and_independent_vectors() {
        let limits = BodyCodecLimits::new(PaymentCountLimits::new(2, 2).unwrap(), 4096, 16384);
        for &(relation, inputs, outputs, count, payload, length, public_count, digest) in CASES {
            let bytes = body_bytes(relation, inputs, outputs, payload);

            assert_eq!(bytes.len(), length);

            let id = identity(relation, inputs, outputs);
            let statement = if relation == 1 {
                let body = PaymentBody::from_bytes(&bytes, limits).unwrap();
                let anchor = NoteTreeAnchor::new(
                    body.context().network_id(),
                    NoteCount::new(count).unwrap(),
                    body.inputs().anchor(),
                );

                Statement::payment(&body, &anchor, body.context(), &id).unwrap()
            } else {
                let body = RewardWithdrawalBody::from_bytes(&bytes, limits).unwrap();

                Statement::withdrawal(&body, body.context(), &id).unwrap()
            };

            assert_eq!(statement.public_values.len(), public_count);

            let actual: String = Sha3_512::digest(&statement.prefix)
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect();

            assert_eq!(actual, digest);
        }
    }

    /// Binds public body metadata even when it does not change semantic AIR inputs.
    #[test]
    fn complete_body_metadata_changes_the_transcript() {
        let limits = crate::profile::body_limits();
        for (relation, offsets) in [(1, vec![1902, 400]), (2, vec![100, 164, 2756, 2780, 4438])] {
            let bytes = body_bytes(relation, 1, 1, 3);
            let make = |bytes: &[u8]| {
                if relation == 1 {
                    let body = PaymentBody::from_bytes(bytes, limits).unwrap();
                    let anchor = NoteTreeAnchor::new(
                        body.context().network_id(),
                        NoteCount::new(137).unwrap(),
                        body.inputs().anchor(),
                    );

                    Statement::payment(&body, &anchor, body.context(), &identity(1, 1, 1)).unwrap()
                } else {
                    let body = RewardWithdrawalBody::from_bytes(bytes, limits).unwrap();

                    Statement::withdrawal(&body, body.context(), &identity(2, 0, 1)).unwrap()
                }
            };

            let original = make(&bytes);

            for offset in offsets {
                let mut changed = bytes.clone();
                changed[offset] ^= 1;

                let changed = make(&changed);

                assert_eq!(changed.public_values, original.public_values);
                assert_ne!(changed.prefix, original.prefix);
            }
        }
    }

    /// Rejects a trusted operation identity incompatible with the typed body.
    #[test]
    fn wrong_relation_is_rejected() {
        let limits = BodyCodecLimits::new(PaymentCountLimits::new(2, 2).unwrap(), 4096, 16384);
        let body = PaymentBody::from_bytes(&body_bytes(1, 1, 1, 3), limits).unwrap();
        let anchor = NoteTreeAnchor::new(
            body.context().network_id(),
            NoteCount::new(137).unwrap(),
            body.inputs().anchor(),
        );

        assert!(matches!(
            Statement::payment(&body, &anchor, body.context(), &identity(2, 0, 1)),
            Err(StatementError::IdentityMismatch)
        ));
    }

    /// Refuses unsupported counts even if native body construction allowed larger limits.
    #[test]
    fn unsupported_shape_is_rejected_before_decode() {
        let limits = BodyCodecLimits::new(PaymentCountLimits::new(3, 2).unwrap(), 4096, 16384);
        let body = PaymentBody::from_bytes(&body_bytes(1, 3, 1, 3), limits).unwrap();
        let anchor = NoteTreeAnchor::new(
            body.context().network_id(),
            NoteCount::new(137).unwrap(),
            body.inputs().anchor(),
        );

        assert!(matches!(
            Statement::payment(&body, &anchor, body.context(), &identity(1, 3, 1)),
            Err(StatementError::UnsupportedShape)
        ));
    }
}
