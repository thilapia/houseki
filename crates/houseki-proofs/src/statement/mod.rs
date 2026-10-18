//! Reconstructs semantic public values and complete transcript binding from native bodies.

mod error;
mod payment;
mod payment_values;
mod withdrawal;
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

                Statement::payment(&body, &anchor, body.context(), &id, limits).unwrap()
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
        let limits = crate::profile::reward_withdrawal::body_limits();
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

                    Statement::payment(&body, &anchor, body.context(), &identity(1, 1, 1), limits)
                        .unwrap()
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
            Statement::payment(&body, &anchor, body.context(), &identity(2, 0, 1), limits),
            Err(StatementError::IdentityMismatch)
        ));
    }

    /// Binds every input and output in the larger family, including the full anchor count.
    #[test]
    fn payment_statements_cover_four_inputs_and_full_envelopes() {
        let limits = crate::profile::payment::body_limits();
        for inputs in 1..=4 {
            for outputs in 1..=2 {
                let bytes = body_bytes(1, inputs, outputs, 3);
                let body = PaymentBody::from_bytes(&bytes, limits).unwrap();
                let id = identity(1, inputs, outputs);
                for count in [1_u128, 137, 1_u128 << 64] {
                    let anchor = NoteTreeAnchor::new(
                        body.context().network_id(),
                        NoteCount::new(count).unwrap(),
                        body.inputs().anchor(),
                    );
                    let statement =
                        Statement::payment(&body, &anchor, body.context(), &id, limits).unwrap();
                    let view =
                        PaymentValues::new(&statement.public_values, inputs, outputs).unwrap();
                    let limbs = |bytes: &[u8]| {
                        bytes
                            .iter()
                            .copied()
                            .map(Goldilocks::from_u8)
                            .collect::<Vec<_>>()
                    };

                    assert_eq!(statement.public_values.len(), 160 + 64 * (inputs + outputs));
                    assert_eq!(view.count().as_slice(), limbs(&count.to_le_bytes()));
                    assert_eq!(view.fee().as_slice(), limbs(&17_u128.to_le_bytes()));
                    for index in 0..inputs {
                        assert_eq!(
                            view.nullifier(index).unwrap().as_slice(),
                            limbs(&[9 + index as u8; 64])
                        );
                    }

                    for index in 0..outputs {
                        assert_eq!(
                            view.commitment(index).unwrap().as_slice(),
                            limbs(&[11 + index as u8; 64])
                        );
                        for offset in [64, 1631, 1640, 1642] {
                            let mut changed = bytes.clone();
                            changed[196 + 64 * inputs + 1643 * index + offset] ^= 1;
                            let changed = PaymentBody::from_bytes(&changed, limits).unwrap();
                            let changed =
                                Statement::payment(&changed, &anchor, body.context(), &id, limits)
                                    .unwrap();

                            assert_eq!(changed.public_values, statement.public_values);
                            assert_ne!(changed.prefix, statement.prefix);
                        }
                    }
                }
            }
        }
    }

    /// Equal semantic lengths cannot substitute a different exact count pair before allocation.
    #[test]
    fn payment_equal_lengths_require_the_exact_shape_identity() {
        let limits = crate::profile::payment::body_limits();
        for (inputs, outputs, other_inputs, other_outputs) in
            [(1, 2, 2, 1), (2, 2, 3, 1), (3, 2, 4, 1)]
        {
            let body = PaymentBody::from_bytes(&body_bytes(1, inputs, outputs, 3), limits).unwrap();
            let anchor = NoteTreeAnchor::new(
                body.context().network_id(),
                NoteCount::new(137).unwrap(),
                body.inputs().anchor(),
            );
            let (result, allocations, _) = crate::test_allocator::measure(|| {
                Statement::payment(
                    &body,
                    &anchor,
                    body.context(),
                    &identity(1, other_inputs, other_outputs),
                    limits,
                )
            });

            assert_eq!(inputs + outputs, other_inputs + other_outputs);
            assert!(matches!(result, Err(StatementError::IdentityMismatch)));
            assert_eq!(allocations, 0);
        }
    }

    /// Matches independently framed larger-shape vectors under a distinct unregistered test identity.
    #[test]
    fn payment_larger_shape_vectors_match_independent_framing() {
        let limits = crate::profile::payment::body_limits();
        for (inputs, outputs, digest) in [
            (
                3,
                1,
                "01bf1f5503562cf4c80ff8564f9cf3b05e07ba35b64379e459555745f2b431885e2740a1930ac5f9add03d4e2c438a0aec42513021043023b2cfbf551ed720be",
            ),
            (
                3,
                2,
                "ff39c8d7befa3dce4279be55db5d76d3b55de6af4b5dae28053607671fd2403ff09cbb10ed3f57c651cbc58845016d6a689bc200bc7aacb2443a7c17290b7029",
            ),
            (
                4,
                1,
                "47f51097f4f8b913daa7094528be91f85427cf0abb273f0c4439bebc050ee2f5a03c1c55ee4b2a05fa6a91a334fe812245ffde5701a1c2ea33cef94f474c1eee",
            ),
            (
                4,
                2,
                "f0b2f81debda2ca4af216169aa0b865fd1794b905b54c19254143ed846d78121478fdd0fac333ac7373c1a0d1bd811b85cc63398bfa719c5b6a6e4d3ed52af56",
            ),
        ] {
            let mut bytes = body_bytes(1, inputs, outputs, 3);
            bytes[76..80].copy_from_slice(&0xffff0008_u32.to_le_bytes());
            let body = PaymentBody::from_bytes(&bytes, limits).unwrap();
            let anchor = NoteTreeAnchor::new(
                body.context().network_id(),
                NoteCount::new(1 << 64).unwrap(),
                body.inputs().anchor(),
            );
            let id = ExpectedIdentity {
                profile: body.context().proof_profile_id(),
                relation: Relation::Payment,
                shape: ((inputs as u32) << 8) | outputs as u32,
                manifest: Sha3_512::digest(b"houseki/test/payment-n-to-m/statements/v1").into(),
            };
            let statement =
                Statement::payment(&body, &anchor, body.context(), &id, limits).unwrap();
            let actual: String = Sha3_512::digest(&statement.prefix)
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect();

            assert_eq!(actual, digest);
        }
    }

    /// Rejects context and anchor changes and empty or excessive shapes before allocating statements.
    #[test]
    fn payment_statement_rejections_precede_dependent_allocation() {
        let limits = crate::profile::payment::body_limits();
        let bytes = body_bytes(1, 4, 2, 3);
        let body = PaymentBody::from_bytes(&bytes, limits).unwrap();
        let id = identity(1, 4, 2);
        let anchor = NoteTreeAnchor::new(
            body.context().network_id(),
            NoteCount::new(137).unwrap(),
            body.inputs().anchor(),
        );
        for offset in [8, 71, 72, 76, 80, 84, 92] {
            let mut changed = bytes.clone();
            changed[offset] ^= 1;
            let changed = PaymentBody::from_bytes(&changed, limits).unwrap();
            let (result, allocations, _) = crate::test_allocator::measure(|| {
                Statement::payment(&changed, &anchor, body.context(), &id, limits)
            });

            assert!(matches!(result, Err(StatementError::ContextMismatch)));
            assert_eq!(allocations, 0);
        }

        for changed in [
            NoteTreeAnchor::new(
                NetworkId::from_bytes([6; 64]),
                anchor.count(),
                anchor.root(),
            ),
            NoteTreeAnchor::new(
                anchor.network_id(),
                anchor.count(),
                NoteRoot::from_bytes([6; 64]),
            ),
            NoteTreeAnchor::new(
                anchor.network_id(),
                NoteCount::new(0).unwrap(),
                anchor.root(),
            ),
        ] {
            let (result, allocations, _) = crate::test_allocator::measure(|| {
                Statement::payment(&body, &changed, body.context(), &id, limits)
            });

            assert!(matches!(
                result,
                Err(StatementError::AnchorMismatch | StatementError::EmptyAnchor)
            ));
            assert_eq!(allocations, 0);
        }

        let changed = NoteTreeAnchor::new(
            anchor.network_id(),
            NoteCount::new(138).unwrap(),
            anchor.root(),
        );
        let original = Statement::payment(&body, &anchor, body.context(), &id, limits).unwrap();
        let changed = Statement::payment(&body, &changed, body.context(), &id, limits).unwrap();

        assert_ne!(original.prefix, changed.prefix);
        assert_ne!(original.public_values, changed.public_values);
        for (inputs, outputs) in [(5, 1), (1, 3)] {
            let loose = BodyCodecLimits::new(PaymentCountLimits::new(5, 3).unwrap(), 4096, 16384);
            let body = PaymentBody::from_bytes(&body_bytes(1, inputs, outputs, 3), loose).unwrap();
            let id = identity(1, inputs, outputs);
            let (result, allocations, _) = crate::test_allocator::measure(|| {
                Statement::payment(&body, &anchor, body.context(), &id, limits)
            });

            assert!(matches!(result, Err(StatementError::UnsupportedShape)));
            assert_eq!(allocations, 0);
        }
    }

    /// Refuses unsupported counts even if native body construction allowed larger limits.
    #[test]
    fn unsupported_shape_is_rejected_before_decode() {
        let limits = BodyCodecLimits::new(PaymentCountLimits::new(5, 2).unwrap(), 4096, 16384);
        let body = PaymentBody::from_bytes(&body_bytes(1, 5, 1, 3), limits).unwrap();
        let anchor = NoteTreeAnchor::new(
            body.context().network_id(),
            NoteCount::new(137).unwrap(),
            body.inputs().anchor(),
        );

        assert!(matches!(
            Statement::payment(&body, &anchor, body.context(), &identity(1, 5, 1), limits),
            Err(StatementError::UnsupportedShape)
        ));
    }
}
