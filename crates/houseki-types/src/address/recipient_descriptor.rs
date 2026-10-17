//! Public recipient information carried by an address.

use super::{AddressContext, EncodedMlKem1024PublicKey, OwnershipCommitment};

/// A declared recipient descriptor containing its context, ownership and KEM key.
///
/// The complete ML-KEM-1024 public key is carried locally alongside the network, address format
/// and suite context and the ownership commitment.
///
/// Interpreting the descriptor requires no recipient directory or external key lookup.
///
/// No private key, amount, fee or per-payment randomness belongs in this record.
///
/// Construction preserves the supplied values without validating the key, supported context or
/// relationship between ownership and encryption material.
///
/// Before encapsulation, senders must check the intended network, supported format and suite,
/// and the suite's public key validation requirements.
///
/// Note and proof consumers must enforce the prescribed ownership and encryption context binding
/// under the complete cryptographic profile.
///
/// This record does not establish the intended recipient's identity, possession of secret keys,
/// spending authority or successful note recovery.
///
/// It defines no text alphabet, checksum, QR transport or canonical byte encoding.
///
/// Address parsing and provenance checks remain responsibilities of consumers.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RecipientDescriptor {
    /// Declared network, address format and cryptographic suite.
    context: AddressContext,

    /// Declared recipient ownership commitment without proof of an opening.
    ownership_commitment: OwnershipCommitment,

    /// Complete encoded encapsulation public key without cryptographic validation.
    kem_public_key: EncodedMlKem1024PublicKey,
}

impl RecipientDescriptor {
    /// Groups declared recipient information without validating its relationships.
    pub const fn new(
        context: AddressContext,
        ownership_commitment: OwnershipCommitment,
        kem_public_key: EncodedMlKem1024PublicKey,
    ) -> Self {
        Self {
            context,
            ownership_commitment,
            kem_public_key,
        }
    }

    /// Returns the declared network, address format and suite context.
    pub const fn context(&self) -> AddressContext {
        self.context
    }

    /// Returns the declared ownership commitment without checking its opening.
    pub const fn ownership_commitment(&self) -> OwnershipCommitment {
        self.ownership_commitment
    }

    /// Borrows the complete encoded public encapsulation key.
    pub const fn kem_public_key(&self) -> &EncodedMlKem1024PublicKey {
        &self.kem_public_key
    }

    /// Consumes the descriptor and returns its context, commitment and public key.
    pub fn into_parts(
        self,
    ) -> (
        AddressContext,
        OwnershipCommitment,
        EncodedMlKem1024PublicKey,
    ) {
        (self.context, self.ownership_commitment, self.kem_public_key)
    }
}
