//! Guarded canonical opening fields shared by both relation families.

use super::{part, write};
use crate::{
    backend::{BackendError, trace::Trace},
    gadgets::OpeningInput,
};
use houseki_notes::NoteOpening;
use p3_goldilocks::Goldilocks;
use zeroize::Zeroizing;

/// Protected canonical opening inputs shared by payment and withdrawal trace construction.
///
/// These byte limbs describe native values and do not establish AIR constraints or a proof.
pub(crate) struct OpeningFields {
    /// Version, full recipient, amount and blinding in fixed canonical byte order.
    cells: Trace,
}

impl OpeningFields {
    /// Exact cells for four version bytes, 1704 recipient bytes, 16 amount bytes and 32 blinding bytes.
    const CELLS: usize = 1756;

    /// Converts the original owners into one bounded protected field allocation.
    pub(crate) fn new(opening: &NoteOpening) -> Result<Self, BackendError> {
        let mut cells = Trace::new(1, Self::CELLS, Self::CELLS)?;
        write(
            &mut cells.values_mut()[..4],
            &opening.format().version().value().to_le_bytes(),
        );

        let recipient = Zeroizing::new(opening.recipient().to_bytes());
        write(&mut cells.values_mut()[4..1708], recipient.as_slice());

        let amount = Zeroizing::new(opening.amount().atoms().to_le_bytes());
        write(&mut cells.values_mut()[1708..1724], amount.as_slice());

        let mut blinding = Zeroizing::new([0; 32]);
        opening.write_proof_blinding(&mut blinding);
        write(&mut cells.values_mut()[1724..], blinding.as_slice());

        Ok(Self { cells })
    }

    /// Borrows the guarded fields for the shared constrained opening assignment.
    pub(crate) fn input(&self) -> OpeningInput<'_> {
        OpeningInput::new(
            self.version(),
            self.recipient(),
            self.amount(),
            self.blinding(),
        )
    }

    /// Borrows all version bytes without narrowing the declared identifier.
    pub(crate) fn version(&self) -> &[Goldilocks; 4] {
        part(&self.cells, 0)
    }

    /// Borrows the complete recipient context, ownership and encapsulation key encoding.
    pub(crate) fn recipient(&self) -> &[Goldilocks; 1704] {
        part(&self.cells, 4)
    }

    /// Borrows all sixteen amount limbs, including high bytes above a machine word.
    pub(crate) fn amount(&self) -> &[Goldilocks; 16] {
        part(&self.cells, 1708)
    }

    /// Borrows the private blinding while its field owner remains alive.
    pub(crate) fn blinding(&self) -> &[Goldilocks; 32] {
        part(&self.cells, 1724)
    }
}
