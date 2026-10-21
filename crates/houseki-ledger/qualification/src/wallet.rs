//! Original authority and delivery owners for one synthetic participant.

use houseki_crypto::{CryptoSuite, MlKem1024DecapsulationKey, NullifierKey, SpendingKey};
use houseki_notes::NoteRecipient;
use houseki_types::{AddressContext, AddressFormatVersion, NetworkId, RecipientDescriptor};
use std::error::Error;

/// A participant retains original secrets without cloning them into proof witnesses.
pub(crate) struct Owner {
    /// Original spending authority.
    pub(crate) spending: SpendingKey,

    /// Original position bound nullifier authority.
    pub(crate) nullifier: NullifierKey,

    /// Original recipient decapsulation owner.
    pub(crate) decryption: MlKem1024DecapsulationKey,

    /// Validated public delivery and ownership descriptor.
    pub(crate) recipient: NoteRecipient,
}

impl Owner {
    /// Generates fresh local authority and delivery secrets for the demonstration
    /// network.
    pub(crate) fn new(network: NetworkId) -> Result<Self, Box<dyn Error>> {
        let spending = SpendingKey::generate()?;
        let nullifier = NullifierKey::generate()?;
        let decryption = MlKem1024DecapsulationKey::generate()?;
        let recipient = NoteRecipient::validate(
            &RecipientDescriptor::new(
                AddressContext::new(network, AddressFormatVersion::new(1), CryptoSuite::V1.id()),
                spending.ownership_commitment(network, &nullifier)?,
                decryption.encapsulation_key().to_encoded(),
            ),
            network,
        )?;

        Ok(Self {
            spending,
            nullifier,
            decryption,
            recipient,
        })
    }
}
