//! Commitment derivation from retained validated context and borrowed private note material.

use houseki_crypto::{CryptoFramingError, CryptoSuite};
use houseki_types::NoteCommitment;

use super::NoteOpening;
use crate::NoteFormat;

impl NoteOpening {
    /// Derives the fixed commitment from this opening's retained fields.
    ///
    /// The resolved note format and recipient suite select compatible immutable rules, with
    /// crypto deriving recipient binding from the retained network and complete validated key.
    ///
    /// Amount and blinding remain borrowed from their original guarded owners through hashing,
    /// and repeated derivation returns the same public digest without acquiring randomness.
    ///
    /// The result does not establish an ownership opening, authenticated delivery, membership,
    /// insertion position, unspentness, spending authority or protocol activation.
    ///
    /// # Errors
    ///
    /// Returns the original [`CryptoFramingError`] if recipient binding or commitment framing
    /// fails, without returning a partial digest or including private opening material.
    pub fn commitment(&self) -> Result<NoteCommitment, CryptoFramingError> {
        let recipient = self.recipient();
        match (self.format(), recipient.suite()) {
            (NoteFormat::V1, CryptoSuite::V1) => recipient.suite().note_commitment(
                recipient.context().network_id(),
                self.format().version(),
                recipient.ownership_commitment(),
                recipient.kem_public_key(),
                self.amount(),
                self.blinding.as_bytes(),
            ),
        }
    }
}

/// Independent positive V1 vectors, complete retained context and borrowed private input checks.
#[cfg(test)]
mod tests {
    use houseki_crypto::CryptoSuite;
    use houseki_types::{
        AddressContext, AddressFormatVersion, Amount, EncodedMlKem1024PublicKey, NetworkId,
        OwnershipCommitment, RecipientDescriptor,
    };

    use crate::{NoteBlinding, NoteFormat, NoteOpening, NoteRecipient};

    /// Builds canonical public key bytes with zero polynomial coefficients and a repeated seed.
    fn key(seed: u8) -> [u8; 1568] {
        let mut bytes = [0; 1568];
        bytes[1536..].fill(seed);
        bytes
    }

    /// Constructs a positive opening with an owned recipient and synthetic private fixture bytes.
    fn opening(
        network: [u8; 64],
        ownership: [u8; 64],
        key_bytes: [u8; 1568],
        atoms: u128,
        blinding: &[u8; 32],
    ) -> NoteOpening {
        let network = NetworkId::from_bytes(network);
        let context =
            AddressContext::new(network, AddressFormatVersion::new(1), CryptoSuite::V1.id());
        let descriptor = RecipientDescriptor::new(
            context,
            OwnershipCommitment::from_bytes(ownership),
            EncodedMlKem1024PublicKey::from_bytes(key_bytes),
        );
        let recipient = NoteRecipient::validate(&descriptor, network).unwrap();

        NoteOpening::new(
            NoteFormat::V1,
            &recipient,
            Amount::from_atoms(atoms).unwrap(),
            NoteBlinding::from_bytes(blinding),
        )
        .unwrap()
    }

    /// Checks the notes consumer against independent complete vectors with positive V1 amounts.
    #[test]
    fn commitments_match_independent_positive_v1_vectors() {
        // Independent Python integer arithmetic evaluates both E and C with pinned constants.
        // Canonical synthetic key and blinding fixtures do not establish honest generation.
        for (network, ownership, seed, atoms, blinding, expected) in [
            (
                [0; 64],
                [0; 64],
                0,
                1,
                [0; 32],
                concat!(
                    "67519504e20c7223a5068feae0c831bdfe180fcc11b6b597c5d8a4506d592c41",
                    "decf8a6608538e3c875bcd61322d8a832f554417b2bc5a32f4cde0454adb20f0"
                ),
            ),
            (
                std::array::from_fn(|i| u8::try_from(i).unwrap()),
                std::array::from_fn(|i| u8::try_from(i + 64).unwrap()),
                0xa5,
                (1_u128 << 64) + 0x01020304,
                std::array::from_fn(|i| u8::try_from(i).unwrap()),
                concat!(
                    "e4d71a009781bebee473503ea001250799bbe6993cd0f8abd19af0831ebfd7bc9",
                    "613c3c3e38b39b64f3e2669430253fe98e152ec550823b91554f89adf83ec89"
                ),
            ),
            (
                [0xff; 64],
                [0xff; 64],
                0xff,
                Amount::MAX_ATOMS,
                [0xff; 32],
                concat!(
                    "4de99cdcc2d1080fca897f80fff6e7de81859b438d21ccc9277cb9b964a14853b",
                    "d2081e4214719bfcbbbae16fdc0f529203dfb118d338517c89209e4930ad825"
                ),
            ),
        ] {
            let opening = opening(network, ownership, key(seed), atoms, &blinding);
            let commitment = opening.commitment().unwrap();
            let actual: String = commitment
                .as_bytes()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect();

            assert_eq!(actual, expected);
        }
    }

    /// Checks all network and ownership bytes and canonical polynomial and seed key mutations.
    #[test]
    fn commitment_binds_the_retained_recipient_snapshot() {
        let network = [0x35; 64];
        let ownership = [0x59; 64];
        let blinding = [0xa7; 32];
        let original = opening(network, ownership, key(0), 1, &blinding)
            .commitment()
            .unwrap();

        for index in 0..64 {
            let mut changed = network;
            changed[index] ^= 1;
            assert_ne!(
                opening(changed, ownership, key(0), 1, &blinding)
                    .commitment()
                    .unwrap(),
                original
            );

            let mut changed = ownership;
            changed[index] ^= 1;
            assert_ne!(
                opening(network, changed, key(0), 1, &blinding)
                    .commitment()
                    .unwrap(),
                original
            );
        }

        for index in [0, 1, 383, 384, 767, 768, 1151, 1152, 1535, 1536, 1567] {
            let mut changed = key(0);
            changed[index] ^= 1;

            assert_ne!(
                opening(network, ownership, changed, 1, &blinding)
                    .commitment()
                    .unwrap(),
                original
            );
        }
    }

    /// Checks every representable amount byte position and every retained blinding byte.
    #[test]
    fn commitment_binds_the_original_amount_and_blinding() {
        let network = [0x35; 64];
        let ownership = [0x59; 64];
        let blinding = [0xa7; 32];
        let original = opening(network, ownership, key(0), 2, &blinding)
            .commitment()
            .unwrap();

        for index in 0..13 {
            let changed = 1_u128 << (index * 8);

            assert_ne!(
                opening(network, ownership, key(0), changed, &blinding)
                    .commitment()
                    .unwrap(),
                original
            );
        }

        for index in 0..32 {
            let mut changed = blinding;
            changed[index] ^= 1;

            assert_ne!(
                opening(network, ownership, key(0), 2, &changed)
                    .commitment()
                    .unwrap(),
                original
            );
        }
    }

    /// Checks deterministic borrowing and commitment agreement after a guarded private round trip.
    #[test]
    fn derivation_preserves_the_opening_and_private_codec_agreement() {
        let blinding = [0xa7; 32];
        let opening = opening([0x35; 64], [0x59; 64], key(0xa5), 1_u128 << 64, &blinding);
        let amount = opening.amount();
        let plaintext = opening.encode_plaintext();
        let expected = opening.commitment().unwrap();

        assert_eq!(opening.commitment().unwrap(), expected);
        assert_eq!(amount.atoms(), 1_u128 << 64);
        assert_eq!(opening.blinding.as_bytes(), &blinding);
        assert_eq!(*opening.encode_plaintext(), *plaintext);

        let decoded = NoteOpening::decode_plaintext(&plaintext[..], opening.recipient()).unwrap();

        assert_eq!(decoded.commitment().unwrap(), expected);
        assert_eq!(decoded.amount(), amount);
        assert_eq!(decoded.recipient(), opening.recipient());
    }
}
