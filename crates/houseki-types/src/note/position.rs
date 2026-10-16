//! Original insertion positions in the note commitment tree.

/// The original leaf position of a note commitment in the note tree.
///
/// Execution assigns this position when it appends an accepted note output.
/// The position remains fixed as the tree grows and the wallet updates its
/// spending anchor or membership path. It identifies the created note instance
/// independently of the position of any later transaction that spends it.
///
/// Nullifier derivation uses this original position together with the note's
/// bound nullifier key and commitment. The spending proof must establish that
/// the position used for derivation matches the proven membership path.
/// Constructing this value does not establish membership, finality or unspentness.
///
/// Positions are zero based and every `u64` value is representable. The tree
/// implementation must enforce its capacity separately. Numeric advancement
/// does not allocate a leaf, and returns no successor when the representation
/// is exhausted. Wire encoding and proof field encoding remain separate contracts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NotePosition(u64);

impl NotePosition {
    /// Constructs a note position from its numeric value.
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns the original leaf position.
    pub const fn value(&self) -> u64 {
        self.0
    }

    /// Returns the next numeric position, or `None` at representation exhaustion.
    /// The returned position may still exceed the note tree's capacity.
    pub const fn checked_next(self) -> Option<Self> {
        match self.0.checked_add(1) {
            Some(value) => Some(Self(value)),
            None => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::NotePosition;

    #[test]
    fn advancement_preserves_position_across_integer_boundaries() {
        for (current, expected) in [
            (0, 1),
            (255, 256),
            (4_294_967_295, 4_294_967_296),
            (u64::MAX - 1, u64::MAX),
        ] {
            let position = NotePosition::new(current);
            let next = position.checked_next().unwrap();

            assert_eq!(next.value(), expected);
            assert!(next > position);
        }
    }

    #[test]
    fn advancement_rejects_exhaustion_without_reusing_a_position() {
        const NEXT: Option<NotePosition> = NotePosition::new(u64::MAX).checked_next();

        assert_eq!(NEXT, None);
    }
}
