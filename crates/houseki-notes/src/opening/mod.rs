//! Checked ownership and protected storage of private note opening material.

mod codec;
mod commitment;
mod error;

pub use error::NoteOpeningError;
pub(crate) use error::NotePlaintextError;

use crate::{NoteBlinding, NoteFormat, NoteRecipient};
use houseki_crypto::CryptoSuite;
use houseki_types::Amount;
use std::fmt;
use zeroize::Zeroizing;

/// An owned private opening with a supported format, compatible recipient and positive amount.
///
/// Construction consumes [`NoteBlinding`] and retains an independent immutable recipient
/// snapshot without requiring the recipient's spending, nullifier or decryption secrets.
///
/// The owned amount and blinding are zeroized when dropped, including during unwinding, while
/// independent caller copies and compiler or operating system copies remain outside that cleanup.
///
/// Holder access can borrow the private amount, but diagnostics reveal none of the stored fields.
///
/// Construction does not derive or match an output commitment, authenticate recovered plaintext
/// or establish membership, spending authority or protocol activation.
pub struct NoteOpening {
    /// Recognized immutable rules checked for compatibility with the recipient suite.
    format: NoteFormat,

    /// Independent validated recipient snapshot retained for commitment and delivery use.
    recipient: NoteRecipient,

    /// Positive private amount held in storage that clears its atom count when dropped.
    amount: Zeroizing<Amount>,

    /// Consumed blinding cleared by its owner when the opening is dropped.
    blinding: NoteBlinding,
}

impl NoteOpening {
    /// Checks an ordinary note's storage rules and retains its owned private material.
    ///
    /// The amount enters guarded storage before validation, with both it and the consumed blinding
    /// cleared on failure or unwinding without clearing independent caller copies.
    ///
    /// The recipient is cloned after the checks, so neither its original storage nor its source
    /// descriptor needs to outlive this opening.
    ///
    /// # Errors
    ///
    /// Returns [`NoteOpeningError::ZeroAmount`] if the supplied amount is zero, without returning
    /// either the opening or its consumed private material.
    pub fn new(
        format: NoteFormat,
        recipient: &NoteRecipient,
        amount: Amount,
        blinding: NoteBlinding,
    ) -> Result<Self, NoteOpeningError> {
        let amount = Zeroizing::new(amount);
        if amount.atoms() == 0 {
            return Err(NoteOpeningError::ZeroAmount);
        }

        // Require an explicit compatibility decision when another format or suite is added.
        match (format, recipient.suite()) {
            (NoteFormat::V1, CryptoSuite::V1) => {}
        }

        Ok(Self {
            format,
            recipient: recipient.clone(),
            amount,
            blinding,
        })
    }

    /// Returns the supported immutable note rules retained by this opening.
    pub const fn format(&self) -> NoteFormat {
        self.format
    }

    /// Borrows the owned validated recipient snapshot without asserting provenance or authority.
    pub const fn recipient(&self) -> &NoteRecipient {
        &self.recipient
    }

    /// Borrows the positive private amount without making another owned copy.
    pub fn amount(&self) -> &Amount {
        &self.amount
    }
}

impl fmt::Debug for NoteOpening {
    /// Writes a fixed redacted label without inspecting any stored field.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("NoteOpening([REDACTED])")
    }
}

/// Positive amount rules, complete retention, owned recipient lifetimes and fixed diagnostics.
#[cfg(test)]
mod tests {
    use houseki_crypto::CryptoSuite;
    use houseki_types::{
        AddressContext, AddressFormatVersion, Amount, EncodedMlKem1024PublicKey, NetworkId,
        OwnershipCommitment, RecipientDescriptor,
    };

    use crate::{NoteBlinding, NoteFormat, NoteOpening, NoteOpeningError, NoteRecipient};

    /// Builds a checked descriptor with distinctive network, ownership and key seed bytes.
    fn recipient(pattern: u8) -> NoteRecipient {
        let network = NetworkId::from_bytes([pattern; 64]);
        let context =
            AddressContext::new(network, AddressFormatVersion::new(1), CryptoSuite::V1.id());

        let mut key = [0; 1568];
        key[1536..].fill(pattern);

        let descriptor = RecipientDescriptor::new(
            context,
            OwnershipCommitment::from_bytes([pattern.wrapping_add(1); 64]),
            EncodedMlKem1024PublicKey::from_bytes(key),
        );

        NoteRecipient::validate(&descriptor, network).unwrap()
    }

    /// Checks positive boundary values and exact format, recipient, amount and blinding retention.
    #[test]
    fn construction_retains_positive_amounts_and_all_opening_fields() {
        let recipient = recipient(0x37);

        for atoms in [1, 2, 1_u128 << 64, Amount::MAX_ATOMS - 1, Amount::MAX_ATOMS] {
            let amount = Amount::from_atoms(atoms).unwrap();
            let blinding = NoteBlinding::generate().unwrap();
            let expected_blinding = *blinding.as_bytes();

            let opening = NoteOpening::new(NoteFormat::V1, &recipient, amount, blinding).unwrap();
            let borrowed_amount: &Amount = opening.amount();

            assert_eq!(opening.format(), NoteFormat::V1);
            assert_eq!(opening.recipient(), &recipient);
            assert_eq!(borrowed_amount.atoms(), atoms);
            assert_eq!(opening.blinding.as_bytes(), &expected_blinding);
        }
    }

    /// Checks zero rejection with fixed error diagnostics that carry no private material.
    #[test]
    fn construction_rejects_zero_without_returning_an_opening() {
        let recipient = recipient(0x59);
        let amount = Amount::from_atoms(0).unwrap();
        let blinding = NoteBlinding::generate().unwrap();

        let error = NoteOpening::new(NoteFormat::V1, &recipient, amount, blinding).unwrap_err();

        assert!(matches!(error, NoteOpeningError::ZeroAmount));
        assert_eq!(format!("{error:?}"), "ZeroAmount");
        assert_eq!(error.to_string(), "ordinary note amount must be positive");
    }

    /// Checks that source recipient storage can expire without changing the complete snapshot.
    #[test]
    fn opening_owns_its_recipient_after_the_source_is_dropped() {
        let expected = recipient(0xa7);
        let opening = {
            let source = expected.clone();
            let amount = Amount::from_atoms(1).unwrap();
            let blinding = NoteBlinding::generate().unwrap();

            NoteOpening::new(NoteFormat::V1, &source, amount, blinding).unwrap()
        };

        assert_eq!(opening.recipient(), &expected);
        assert_eq!(
            opening.recipient().kem_public_key(),
            expected.kem_public_key()
        );
    }

    /// Checks identical ordinary and alternate diagnostics across differing stored fields.
    #[test]
    fn diagnostics_redact_every_opening_field() {
        for (pattern, atoms) in [(0, 1), (0xff, Amount::MAX_ATOMS)] {
            let recipient = recipient(pattern);
            let amount = Amount::from_atoms(atoms).unwrap();
            let blinding = NoteBlinding::generate().unwrap();

            let opening = NoteOpening::new(NoteFormat::V1, &recipient, amount, blinding).unwrap();

            assert_eq!(format!("{opening:?}"), "NoteOpening([REDACTED])");
            assert_eq!(format!("{opening:#?}"), "NoteOpening([REDACTED])");
        }
    }
}
