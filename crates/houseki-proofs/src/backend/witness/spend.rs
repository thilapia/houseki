//! Guarded ownership and membership fields for one native spend.

use super::{OpeningFields, part, write};
use crate::backend::{BackendError, trace::Trace};
use houseki_notes::SpendWitness;
use p3_goldilocks::Goldilocks;
use zeroize::Zeroizing;

/// Protected opening, ownership keys, original position and full membership path for one spend.
pub(crate) struct SpendFields {
    /// Opening representation reused by both relation families.
    opening: OpeningFields,

    /// Two keys, original position and 64 complete siblings in leaf to root order.
    cells: Trace,
}

impl SpendFields {
    /// Exact cells for two 32 byte keys, eight position bytes and 4096 sibling bytes.
    const CELLS: usize = 4168;

    /// Copies only the specified native capabilities into protected byte limbs.
    pub(crate) fn new(witness: &SpendWitness<'_>) -> Result<Self, BackendError> {
        let opening = OpeningFields::new(witness.opening())?;
        let mut cells = Trace::new(1, Self::CELLS, Self::CELLS)?;

        let mut key = Zeroizing::new([0; 32]);
        witness.spending_key().write_proof_bytes(&mut key);
        write(&mut cells.values_mut()[..32], key.as_slice());

        witness.nullifier_key().write_proof_bytes(&mut key);
        write(&mut cells.values_mut()[32..64], key.as_slice());

        let position = Zeroizing::new(
            witness
                .membership()
                .original_position()
                .value()
                .to_le_bytes(),
        );
        write(&mut cells.values_mut()[64..72], position.as_slice());

        let mut sibling = Zeroizing::new([0; 64]);
        for level in 0..64 {
            crate::memory::checkpoint();
            witness
                .membership()
                .write_proof_sibling(level, &mut sibling)
                .map_err(|_| BackendError::InvalidTrace)?;
            write(
                &mut cells.values_mut()[72 + level * 64..136 + level * 64],
                sibling.as_slice(),
            );
        }

        Ok(Self { opening, cells })
    }

    /// Borrows the shared protected opening without copying its amount or recipient.
    pub(crate) fn opening(&self) -> &OpeningFields {
        &self.opening
    }

    /// Borrows all original spending key bytes.
    pub(crate) fn spending_key(&self) -> &[Goldilocks; 32] {
        part(&self.cells, 0)
    }

    /// Borrows all original nullifier key bytes.
    pub(crate) fn nullifier_key(&self) -> &[Goldilocks; 32] {
        part(&self.cells, 32)
    }

    /// Borrows the original position as eight little endian byte limbs.
    pub(crate) fn position(&self) -> &[Goldilocks; 8] {
        part(&self.cells, 64)
    }

    /// Borrows the complete original path in place for sequential membership assignment.
    pub(crate) fn siblings(&self) -> &[[Goldilocks; 64]; 64] {
        self.cells.values()[72..]
            .as_chunks::<64>()
            .0
            .try_into()
            .unwrap()
    }

    /// Borrows one complete sibling and returns none for every level outside the fixed depth.
    pub(crate) fn sibling(&self, level: usize) -> Option<&[Goldilocks; 64]> {
        if level >= 64 {
            return None;
        }

        Some(part(&self.cells, 72 + level * 64))
    }
}
