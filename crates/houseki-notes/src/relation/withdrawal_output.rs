//! Equality checks for an ordinary withdrawal output and its protected opening.

use houseki_crypto::{CryptoFramingError, CryptoSuite};
use houseki_types::RewardWithdrawalBody;
use thiserror::Error;

use crate::{NoteFormat, NoteOpening};

/// A failure of the withdrawal output relation without private opening values.
#[derive(Debug, Error)]
pub enum WithdrawalOutputRelationError {
    /// The opening belongs to another network than the declared withdrawal.
    #[error("note opening network does not match the withdrawal")]
    NetworkMismatch,

    /// The opening does not derive the published output commitment.
    #[error("note opening does not match the withdrawal output commitment")]
    CommitmentMismatch,

    /// The matched opening amount differs from the positive public withdrawal amount.
    #[error("note opening amount does not match the public withdrawal amount")]
    AmountMismatch,

    /// Recipient binding or commitment framing failed without returning a digest.
    #[error("could not derive withdrawal output commitment: {0}")]
    CommitmentFraming(
        /// Original framing failure without private opening material.
        #[from]
        CryptoFramingError,
    ),
}

/// Checks supported output rules, network, commitment and positive public amount equality.
///
/// The opening's immutable format and recipient suite select the supported note rules.
///
/// Commitment derivation binds the retained ownership, recipient key, amount and blinding.
///
/// The fee is separate and does not reduce or increase the required output amount.
///
/// This native reference relation borrows the opening without exporting its private values.
///
/// It does not inspect or authenticate the envelope, verify source authority or a signature,
/// check nonce eligibility, gross balance or fee policy, or verify a proof, insertion or finality.
///
/// # Errors
///
/// Checks network before deriving the commitment, then checks commitment before amount equality.
///
/// Returns fixed mismatch errors without private values and preserves safe framing sources.
pub fn check_withdrawal_output(
    body: &RewardWithdrawalBody,
    opening: &NoteOpening,
) -> Result<(), WithdrawalOutputRelationError> {
    match (opening.format(), opening.recipient().suite()) {
        (NoteFormat::V1, CryptoSuite::V1) => {}
    }
    if opening.recipient().context().network_id() != body.context().network_id() {
        return Err(WithdrawalOutputRelationError::NetworkMismatch);
    }
    if opening.commitment()? != body.output().commitment() {
        return Err(WithdrawalOutputRelationError::CommitmentMismatch);
    }
    if opening.amount() != &body.public_amount() {
        return Err(WithdrawalOutputRelationError::AmountMismatch);
    }
    Ok(())
}

/// Positive output equality and the explicit separation from authenticated delivery.
#[cfg(test)]
mod tests {
    use std::error::Error;

    use houseki_crypto::{CryptoSuite, MlKem1024DecapsulationKey};
    use houseki_types::{
        AddressContext, AddressFormatVersion, Amount, CheckpointSequence, EncodedMlDsa87PublicKey,
        EncodedMlKem1024Ciphertext, EncryptedNoteEnvelope, FeeScheduleId, NetworkId,
        NoteCommitment, NoteOutput, OwnershipCommitment, ProofProfileId, ProtocolVersion,
        RecipientDescriptor, RewardAccountId, RewardWithdrawalBody, TransactionContext,
        ValidityCheckpointRange, WithdrawalNonce,
    };

    use crate::{
        NoteBlinding, NoteFormat, NoteOpening, NoteRecipient, WithdrawalOutputRelationError,
        check_withdrawal_output,
    };

    /// Creates a positive protected opening with distinctive full network and ownership values.
    fn opening(network: NetworkId, atoms: u128, blinding: u8) -> NoteOpening {
        let key = MlKem1024DecapsulationKey::from_seed(&[11; 64]);
        let recipient = NoteRecipient::validate(
            &RecipientDescriptor::new(
                AddressContext::new(network, AddressFormatVersion::new(1), CryptoSuite::V1.id()),
                OwnershipCommitment::from_bytes([12; 64]),
                key.encapsulation_key().to_encoded(),
            ),
            network,
        )
        .unwrap();
        NoteOpening::new(
            NoteFormat::V1,
            &recipient,
            Amount::from_atoms(atoms).unwrap(),
            NoteBlinding::from_bytes(&[blinding; 32]),
        )
        .unwrap()
    }

    /// Uses deliberately malformed public ciphertext to isolate the native equality relation.
    fn body(
        network: NetworkId,
        commitment: NoteCommitment,
        atoms: u128,
        fee: u128,
    ) -> RewardWithdrawalBody {
        RewardWithdrawalBody::new(
            TransactionContext::new(
                network,
                ProtocolVersion::new(1),
                ProofProfileId::new(2),
                FeeScheduleId::new(3),
                ValidityCheckpointRange::new(
                    CheckpointSequence::new(4),
                    CheckpointSequence::new(5),
                )
                .unwrap(),
            ),
            RewardAccountId::from_bytes([13; 64]),
            EncodedMlDsa87PublicKey::from_bytes([14; 2592]),
            WithdrawalNonce::new(u64::MAX),
            Amount::from_atoms(atoms).unwrap(),
            Amount::from_atoms(fee).unwrap(),
            NoteOutput::new(
                commitment,
                EncryptedNoteEnvelope::new(
                    EncodedMlKem1024Ciphertext::from_bytes([0; 1568]),
                    Vec::new(),
                    0,
                )
                .unwrap(),
            ),
        )
        .unwrap()
    }

    /// Accepts positive boundaries and independent fees without inspecting delivery or authority.
    #[test]
    fn withdrawal_relation_accepts_exact_values_with_an_opaque_invalid_envelope() {
        let network = NetworkId::from_bytes([7; 64]);
        for (atoms, fee) in [
            (1, 0),
            (1, Amount::MAX_ATOMS),
            ((1_u128 << 64) + 3, 17),
            (Amount::MAX_ATOMS, Amount::MAX_ATOMS),
        ] {
            let opening = opening(network, atoms, 0xa5);
            let commitment = opening.commitment().unwrap();
            let body = body(network, commitment, atoms, fee);
            let unchanged = body.clone();
            check_withdrawal_output(&body, &opening).unwrap();
            assert_eq!(body, unchanged);
            assert_eq!(opening.amount().atoms(), atoms);
            assert_eq!(opening.commitment().unwrap(), commitment);
            assert_eq!(opening.recipient().context().network_id(), network);
        }
    }

    /// Checks every network and commitment byte before amount equality without changing the opening.
    #[test]
    fn withdrawal_relation_preserves_network_and_commitment_failure_order() {
        let network = NetworkId::from_bytes([7; 64]);
        let opening = opening(network, 1, 0xa5);
        let commitment = opening.commitment().unwrap();
        for index in 0..64 {
            let mut bytes = *network.as_bytes();
            bytes[index] ^= 1;
            let body = body(
                NetworkId::from_bytes(bytes),
                NoteCommitment::from_bytes([0; 64]),
                2,
                17,
            );
            assert!(matches!(
                check_withdrawal_output(&body, &opening),
                Err(WithdrawalOutputRelationError::NetworkMismatch)
            ));
            let mut bytes = *commitment.as_bytes();
            bytes[index] ^= 1;
            let body = self::body(network, NoteCommitment::from_bytes(bytes), 2, 17);
            assert!(matches!(
                check_withdrawal_output(&body, &opening),
                Err(WithdrawalOutputRelationError::CommitmentMismatch)
            ));
        }
        let changed = self::opening(network, 1, 0xa4);
        let body = body(network, commitment, 1, 17);
        assert!(matches!(
            check_withdrawal_output(&body, &changed),
            Err(WithdrawalOutputRelationError::CommitmentMismatch)
        ));
        check_withdrawal_output(&body, &opening).unwrap();
    }

    /// Rejects exact positive amount disagreement with fixed diagnostics after commitment matching.
    #[test]
    fn withdrawal_relation_rejects_positive_amount_disagreement() {
        let network = NetworkId::from_bytes([7; 64]);
        for (private, public) in [
            (1, 2),
            (2, 1),
            (1_u128 << 64, (1_u128 << 64) + 1),
            (1, Amount::MAX_ATOMS),
            (Amount::MAX_ATOMS, 1),
        ] {
            let opening = opening(network, private, 0xa5);
            let commitment = opening.commitment().unwrap();
            let body = body(network, commitment, public, 17);
            let error = check_withdrawal_output(&body, &opening).unwrap_err();
            assert!(matches!(
                error,
                WithdrawalOutputRelationError::AmountMismatch
            ));
            assert_eq!(
                error.to_string(),
                "note opening amount does not match the public withdrawal amount"
            );
            assert!(error.source().is_none());
            assert_eq!(opening.amount().atoms(), private);
            assert_eq!(opening.commitment().unwrap(), commitment);
        }
    }
}
