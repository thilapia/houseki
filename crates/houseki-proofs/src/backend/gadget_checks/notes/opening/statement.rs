//! Native body statements for complete-opening test identities only.

use crate::{
    gadgets::OpeningFixture,
    profile::{ExpectedIdentity, Relation, payment, reward_withdrawal},
    statement::Statement,
};
use houseki_types::{NoteCount, NoteTreeAnchor, PaymentBody, ProofProfileId, RewardWithdrawalBody};
use p3_field::PrimeField64;

/// Encodes public fixture bodies, then lets the real native codec and statement builder check them.
///
/// Zero inputs selects withdrawal while payment counts and output index are trusted test metadata.
pub(super) fn statement(
    fixture: &OpeningFixture,
    inputs: usize,
    outputs: usize,
    selected: usize,
    opaque: u8,
) -> (ExpectedIdentity, Statement) {
    let payment = inputs != 0;
    let limits = if payment {
        payment::body_limits()
    } else {
        reward_withdrawal::body_limits()
    };

    let identity = ExpectedIdentity {
        profile: ProofProfileId::new(0xffff000f),
        relation: if payment {
            Relation::Payment
        } else {
            Relation::RewardWithdrawal
        },
        shape: if payment {
            ((inputs as u32) << 8) | outputs as u32
        } else {
            1
        },
        manifest: [0x6f; 64],
    };
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&1_u32.to_le_bytes());
    bytes.extend_from_slice(&(if payment { 1_u32 } else { 2_u32 }).to_le_bytes());
    bytes.extend(
        fixture.public[..64]
            .iter()
            .map(|value| value.as_canonical_u64() as u8),
    );
    for value in [1_u32, 0xffff000f, 4] {
        bytes.extend_from_slice(&value.to_le_bytes());
    }

    bytes.extend_from_slice(&5_u64.to_le_bytes());
    bytes.extend_from_slice(&8_u64.to_le_bytes());
    if payment {
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
        bytes.extend_from_slice(&5_u64.to_le_bytes());
        bytes.extend(
            fixture.public[64..80]
                .iter()
                .map(|value| value.as_canonical_u64() as u8),
        );
        bytes.extend_from_slice(&17_u128.to_le_bytes());
    }

    for index in 0..outputs {
        if index == selected {
            bytes.extend(
                fixture.public[80..]
                    .iter()
                    .map(|value| value.as_canonical_u64() as u8),
            );
        } else {
            bytes.extend_from_slice(&[11 + index as u8; 64]);
        }

        bytes.extend_from_slice(&[21; 1568]);
        bytes.extend_from_slice(&1_u64.to_le_bytes());
        bytes.push(opaque);
    }

    let statement = if payment {
        let body = PaymentBody::from_bytes(&bytes, limits).unwrap();
        let anchor = NoteTreeAnchor::new(
            body.context().network_id(),
            NoteCount::new(1 << 64).unwrap(),
            body.inputs().anchor(),
        );
        Statement::payment(&body, &anchor, body.context(), &identity, limits).unwrap()
    } else {
        let body = RewardWithdrawalBody::from_bytes(&bytes, limits).unwrap();
        Statement::withdrawal(&body, body.context(), &identity).unwrap()
    };

    (identity, statement)
}
