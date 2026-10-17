//! Sparse append state held in memory for the fixed depth 64 application note tree.

use crate::NoteMembershipWitness;
use houseki_crypto::{
    CryptoFramingError, NoteTreeHashError, note_tree_empty_leaf, note_tree_leaf, note_tree_parent,
    note_tree_root,
};
use houseki_types::{NetworkId, NoteCommitment, NoteCount, NotePosition, NoteRoot, NoteTreeAnchor};
use std::collections::HashMap;
use thiserror::Error;
use zeroize::Zeroizing;

/// A failure to initialize, append or retrieve a concrete application tree path.
#[derive(Debug, Error)]
pub enum NoteTreeError {
    /// All 2^64 leaf positions are occupied.
    #[error("application note tree is full")]
    Full,

    /// The requested witness position has not been appended.
    #[error("note position is not occupied")]
    PositionNotOccupied,

    /// Sparse public node storage could not be reserved before an append.
    #[error("could not reserve application note tree storage")]
    AllocationFailed,

    /// Public parent hashing rejected its fixed tree inputs.
    #[error("could not hash application note tree parent: {0}")]
    Hash(
        /// Original public tree hash failure.
        #[from]
        NoteTreeHashError,
    ),

    /// Fixed leaf or root framing failed before state mutation.
    #[error("could not frame application note tree: {0}")]
    Framing(
        /// Original safe framing failure.
        #[from]
        CryptoFramingError,
    ),
}

/// A concrete append tree retaining occupied public nodes for local witness retrieval.
///
/// The tree allocates stored public paths as needed rather than allocating its full capacity.
///
/// It preflights capacity, node storage and all hashes before changing leaves, count or root.
///
/// Persistence, authenticated ledger history, anchor eligibility and consensus are separate.
///
/// Local witness retrieval reveals access patterns and is not a remote query privacy protocol.
pub struct NoteTree {
    /// Complete immutable network used by every fixed hash.
    network: NetworkId,

    /// Number of occupied leaves, including a possible full tree.
    count: NoteCount,

    /// Current complete count bound root.
    root: NoteRoot,

    /// Empty subtree digest for each height from leaf zero through top 64.
    empty: [[u8; 64]; 65],

    /// Occupied public nodes keyed by subtree height and index at that height.
    nodes: HashMap<(u8, u64), [u8; 64]>,
}

impl NoteTree {
    /// Builds the exact empty depth 64 tree under one network without allocating all leaves.
    ///
    /// # Errors
    ///
    /// Preserves fixed hash and framing failures without returning a partial tree.
    pub fn new(network: NetworkId) -> Result<Self, NoteTreeError> {
        let mut empty = [[0; 64]; 65];
        empty[0] = note_tree_empty_leaf(network)?;

        for level in 0..64 {
            empty[level + 1] = note_tree_parent(
                network,
                u32::try_from(level).expect("fixed level fits u32"),
                &empty[level],
                &empty[level],
            )?;
        }

        let count = NoteCount::new(0).expect("empty count fits capacity");
        let root = note_tree_root(network, count, &empty[64])?;

        Ok(Self {
            network,
            count,
            root,
            empty,
            nodes: HashMap::new(),
        })
    }

    /// Returns declared metadata for the current concrete tree state without authenticating history.
    pub fn anchor(&self) -> NoteTreeAnchor {
        NoteTreeAnchor::new(self.network, self.count, self.root)
    }

    /// Appends one public commitment at the next original position, preserving repeated commitments.
    ///
    /// # Errors
    ///
    /// Checks full capacity and allocation, computes every changed node and root, then commits
    /// the new state, leaving logical state unchanged on a returned error.
    pub fn append(&mut self, commitment: NoteCommitment) -> Result<NotePosition, NoteTreeError> {
        let position = self.count.next_position().ok_or(NoteTreeError::Full)?;
        let count = self
            .count
            .checked_next()
            .expect("append position establishes remaining capacity");

        self.nodes
            .try_reserve(65)
            .map_err(|_| NoteTreeError::AllocationFailed)?;

        let mut changed = [[0; 64]; 65];
        changed[0] = note_tree_leaf(self.network, &commitment)?;
        let mut index = position.value();

        for level in 0..64 {
            let height = u8::try_from(level).expect("fixed height fits u8");
            let sibling = self
                .nodes
                .get(&(height, index ^ 1))
                .unwrap_or(&self.empty[level]);
            let (left, right) = if index & 1 == 0 {
                (&changed[level], sibling)
            } else {
                (sibling, &changed[level])
            };
            changed[level + 1] = note_tree_parent(self.network, u32::from(height), left, right)?;
            index >>= 1;
        }

        let root = note_tree_root(self.network, count, &changed[64])?;

        let mut index = position.value();
        for (height, node) in changed.into_iter().enumerate() {
            self.nodes.insert(
                (u8::try_from(height).expect("fixed height fits u8"), index),
                node,
            );
            index >>= 1;
        }

        self.count = count;
        self.root = root;

        Ok(position)
    }

    /// Retrieves the actual current path into guarded owned witness storage.
    ///
    /// The original borrowed position remains the caller's cleanup responsibility.
    ///
    /// # Errors
    ///
    /// Rejects unoccupied positions without exporting selected sibling bytes.
    pub fn witness(&self, position: &NotePosition) -> Result<NoteMembershipWitness, NoteTreeError> {
        if u128::from(position.value()) >= self.count.value() {
            return Err(NoteTreeError::PositionNotOccupied);
        }

        let mut siblings = Zeroizing::new([[0; 64]; 64]);
        let mut index = Zeroizing::new(position.value());
        for (height, sibling) in siblings.iter_mut().enumerate() {
            let node = self
                .nodes
                .get(&(
                    u8::try_from(height).expect("fixed height fits u8"),
                    *index ^ 1,
                ))
                .unwrap_or(&self.empty[height]);
            sibling.copy_from_slice(node);
            *index >>= 1;
        }

        Ok(NoteMembershipWitness {
            position: Zeroizing::new(*position),
            siblings,
        })
    }
}

/// Concrete append roots, independent vectors and capacity preflight.
#[cfg(test)]
mod tests {
    use crate::{NoteMembershipError, NoteTree, NoteTreeError};
    use houseki_types::{NetworkId, NoteCommitment, NoteCount, NotePosition};

    /// Formats public roots for independent known answer comparison.
    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// Appends real leaves, distinguishes duplicate instances and updates actual membership paths.
    #[test]
    fn append_state_matches_independent_roots_and_retrieves_actual_paths() {
        let network = NetworkId::from_bytes([7; 64]);
        let commitment = NoteCommitment::from_bytes([11; 64]);
        let mut tree = NoteTree::new(network).unwrap();

        assert_eq!(
            hex(tree.anchor().root().as_bytes()),
            "98f94a4db56e412d63ffd9bbcdd2f003b0af316408cc45f2df96e84479748ce39b5c8f20dfbb01e23bafc647f5133067f59aba1c8a6e050cfe9ecf5722b0ec10"
        );
        assert!(matches!(
            tree.witness(&NotePosition::new(0)),
            Err(NoteTreeError::PositionNotOccupied)
        ));

        let first = tree.append(commitment).unwrap();

        assert_eq!(first.value(), 0);
        assert_eq!(tree.anchor().count().value(), 1);
        assert_eq!(
            hex(tree.anchor().root().as_bytes()),
            "a8d550d23bfb1703ec81bd155e5a233c72ccbf1261b45b2999ef38853c4b583af1c8e8a098ef4d26123840a50c1b17818a97ba852af7f987bb8e8b0839dc90f4"
        );

        let old_anchor = tree.anchor();
        let old_witness = tree.witness(&first).unwrap();

        old_witness.verify(&old_anchor, &commitment).unwrap();

        let second = tree.append(commitment).unwrap();

        assert_eq!(second.value(), 1);
        assert_eq!(tree.anchor().count().value(), 2);
        assert_eq!(
            hex(tree.anchor().root().as_bytes()),
            "ccc96d667cc275ffe4ddc49d7df3cf4914ab7bbd1aa5c4c6b28064757e5caedbb8c39a97c5048fdc780d32b6edb64b6a70115e29cb8ab98d63ea695ed449b62b"
        );

        for position in [&first, &second] {
            tree.witness(position)
                .unwrap()
                .verify(&tree.anchor(), &commitment)
                .unwrap();
        }

        assert!(matches!(
            old_witness.verify(&tree.anchor(), &commitment),
            Err(NoteMembershipError::RootMismatch)
        ));
        old_witness.verify(&old_anchor, &commitment).unwrap();

        for byte in 12..20 {
            let commitment = NoteCommitment::from_bytes([byte; 64]);
            let position = tree.append(commitment).unwrap();

            tree.witness(&position)
                .unwrap()
                .verify(&tree.anchor(), &commitment)
                .unwrap();
        }

        tree.witness(&first)
            .unwrap()
            .verify(&tree.anchor(), &commitment)
            .unwrap();
    }

    /// Full capacity returns before any leaf, count or root mutation even at the final represented count.
    #[test]
    fn append_capacity_preflight_preserves_logical_state() {
        let mut tree = NoteTree::new(NetworkId::from_bytes([7; 64])).unwrap();
        tree.count = NoteCount::new(NoteCount::CAPACITY).unwrap();
        let anchor = tree.anchor();
        let nodes = tree.nodes.len();

        assert!(matches!(
            tree.append(NoteCommitment::from_bytes([11; 64])),
            Err(NoteTreeError::Full)
        ));
        assert_eq!(tree.anchor(), anchor);
        assert_eq!(tree.nodes.len(), nodes);
    }
}
