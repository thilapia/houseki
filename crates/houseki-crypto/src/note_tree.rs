//! Fixed application note tree hashes and protected path evaluation.

use crate::{
    CryptoFramingError,
    domain::Domain,
    hash::{poseidon2, poseidon2_secret},
};
use crypto_bigint::ctutils::{Choice, CtSelect};
use houseki_types::{NetworkId, NoteCommitment, NoteCount, NotePosition, NoteRoot};
use thiserror::Error;
use zeroize::Zeroizing;

/// A failure to evaluate one fixed public tree parent.
#[derive(Debug, Error)]
pub enum NoteTreeHashError {
    /// Parent levels must be from zero through 63 inclusive.
    #[error("invalid note tree parent level {level}")]
    InvalidLevel {
        /// Complete supplied level without narrowing.
        level: u32,
    },

    /// Fixed tree framing failed without returning a node.
    #[error("could not frame note tree node: {0}")]
    Framing(
        /// Original safe framing failure.
        #[from]
        CryptoFramingError,
    ),
}

/// Derives the distinct empty leaf under the complete network.
///
/// # Errors
///
/// Preserves the original framing error without returning a node.
pub fn note_tree_empty_leaf(network: NetworkId) -> Result<[u8; 64], CryptoFramingError> {
    poseidon2(Domain::NoteTreeEmpty, &[network.as_bytes()])
}

/// Derives an occupied public leaf from the complete network and note commitment.
///
/// # Errors
///
/// Preserves the original framing error without returning a node.
pub fn note_tree_leaf(
    network: NetworkId,
    commitment: &NoteCommitment,
) -> Result<[u8; 64], CryptoFramingError> {
    poseidon2(
        Domain::NoteTreeLeaf,
        &[network.as_bytes(), commitment.as_bytes()],
    )
}

/// Derives an ordered public parent at level zero through 63, with zero joining leaves.
///
/// # Errors
///
/// Rejects an unsupported complete level before hashing, preserving original framing failures.
pub fn note_tree_parent(
    network: NetworkId,
    level: u32,
    left: &[u8; 64],
    right: &[u8; 64],
) -> Result<[u8; 64], NoteTreeHashError> {
    if level >= 64 {
        return Err(NoteTreeHashError::InvalidLevel { level });
    }

    Ok(poseidon2(
        Domain::NoteTreeNode,
        &[network.as_bytes(), &level.to_le_bytes(), left, right],
    )?)
}

/// Binds a public depth 64 top node to its complete network and bounded occupied count.
///
/// Derivation alone authenticates neither actual leaves nor anchor eligibility.
///
/// # Errors
///
/// Preserves the original framing failure without a root.
pub fn note_tree_root(
    network: NetworkId,
    count: NoteCount,
    top: &[u8; 64],
) -> Result<NoteRoot, CryptoFramingError> {
    let digest = poseidon2(
        Domain::NoteTreeRoot,
        &[
            network.as_bytes(),
            &64_u32.to_le_bytes(),
            &count.value().to_le_bytes(),
            top,
        ],
    )?;

    Ok(NoteRoot::from_bytes(digest))
}

/// Recomputes a depth 64 count bound root from borrowed private membership material.
///
/// Processes every level using constant time orientation selection and guarded digest and
/// selection storage, without branching on individual original position bits.
///
/// Siblings are in leaf to root order and the caller retains ownership and cleanup of inputs.
///
/// This operation derives a root without checking position occupancy, equality to an actual
/// anchor, finality, unspentness or spending authority.
///
/// # Errors
///
/// Returns the original framing failure without a root, with guarded temporary owners dropped.
pub fn note_membership_root(
    network: NetworkId,
    count: NoteCount,
    commitment: &NoteCommitment,
    position: &NotePosition,
    siblings: &[[u8; 64]; 64],
) -> Result<NoteRoot, CryptoFramingError> {
    let position_bytes = Zeroizing::new(position.value().to_le_bytes());
    let mut current = poseidon2_secret(
        Domain::NoteTreeLeaf,
        &[network.as_bytes(), commitment.as_bytes()],
    )?;

    for (level, sibling) in siblings.iter().enumerate() {
        let orientation = Choice::from_u8_lsb((position_bytes[level / 8] >> (level % 8)) & 1);
        let mut left = Zeroizing::new([0; 64]);
        let mut right = Zeroizing::new([0; 64]);
        for index in 0..64 {
            left[index] = current[index].ct_select(&sibling[index], orientation);
            right[index] = sibling[index].ct_select(&current[index], orientation);
        }

        let level = u32::try_from(level).expect("fixed depth tree level fits u32");
        current = poseidon2_secret(
            Domain::NoteTreeNode,
            &[
                network.as_bytes(),
                &level.to_le_bytes(),
                &left[..],
                &right[..],
            ],
        )?;
    }

    let digest = poseidon2_secret(
        Domain::NoteTreeRoot,
        &[
            network.as_bytes(),
            &64_u32.to_le_bytes(),
            &count.value().to_le_bytes(),
            &current[..],
        ],
    )?;

    Ok(NoteRoot::from_bytes(*digest))
}

/// Independent integer vectors and agreement between public append and guarded path evaluation.
#[cfg(test)]
mod tests {
    use super::*;
    use houseki_types::{NetworkId, NoteCommitment, NoteCount, NotePosition};

    /// Formats public digests only for independent oracle comparison.
    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// Computes every empty subtree under the public fixed depth construction.
    fn empties(network: NetworkId) -> [[u8; 64]; 65] {
        let mut values = [[0; 64]; 65];
        values[0] = note_tree_empty_leaf(network).unwrap();
        for level in 0..64 {
            values[level + 1] = note_tree_parent(
                network,
                u32::try_from(level).unwrap(),
                &values[level],
                &values[level],
            )
            .unwrap();
        }
        values
    }

    /// Checks full independent empty, occupied, parent, count bound and duplicate leaf vectors.
    #[test]
    fn application_tree_hashes_match_independent_integer_vectors() {
        let network = NetworkId::from_bytes([7; 64]);
        let empty = empties(network);
        let commitment = NoteCommitment::from_bytes([11; 64]);
        let leaf = note_tree_leaf(network, &commitment).unwrap();
        assert_eq!(
            hex(&empty[0]),
            "faa55e2149cd2456a05bb8936abb21728c53832ec468cccd2e7b69dc8ecb81050f51e41a637ed7fa6ecfce9fe155bc992f6509376afcc26223918695313c0b48"
        );
        assert_eq!(
            hex(&leaf),
            "8612d8c1fcf3a304c752cb1b79156068259b007b56b1b32fb8b2a0b23b7278fa74553cea04c66ec0efd52ecdbdea8ae9812868826a451b3d52efefd33ff7ef24"
        );
        assert_eq!(
            hex(&note_tree_parent(network, 0, &[11; 64], &[12; 64]).unwrap()),
            "f1d18885bf3e2264b6780adf2e296f20b63b69ae0433979db3eb5780447eae612e38d5cbe51777e4abbcc4edf68ad13292fb11cf2ee053b1bf475466ba6939ad"
        );
        assert_eq!(
            hex(&note_tree_parent(network, 63, &[11; 64], &[12; 64]).unwrap()),
            "1909ed435ff68466af353dce47d35d7ed1858b56de213a4a754989bc809e7aff2cbd00d4cdd07920ebfa20c521188fd872abe25260e9c63883c5ecfd2ebc282a"
        );
        assert_eq!(
            hex(
                note_tree_root(network, NoteCount::new(0).unwrap(), &empty[64])
                    .unwrap()
                    .as_bytes()
            ),
            "98f94a4db56e412d63ffd9bbcdd2f003b0af316408cc45f2df96e84479748ce39b5c8f20dfbb01e23bafc647f5133067f59aba1c8a6e050cfe9ecf5722b0ec10"
        );
        let siblings: [[u8; 64]; 64] = empty[..64].try_into().unwrap();
        let one = note_membership_root(
            network,
            NoteCount::new(1).unwrap(),
            &commitment,
            &NotePosition::new(0),
            &siblings,
        )
        .unwrap();
        assert_eq!(
            hex(one.as_bytes()),
            "a8d550d23bfb1703ec81bd155e5a233c72ccbf1261b45b2999ef38853c4b583af1c8e8a098ef4d26123840a50c1b17818a97ba852af7f987bb8e8b0839dc90f4"
        );
        let mut duplicated = siblings;
        duplicated[0] = leaf;
        let two = note_membership_root(
            network,
            NoteCount::new(2).unwrap(),
            &commitment,
            &NotePosition::new(0),
            &duplicated,
        )
        .unwrap();
        assert_eq!(
            hex(two.as_bytes()),
            "ccc96d667cc275ffe4ddc49d7df3cf4914ab7bbd1aa5c4c6b28064757e5caedbb8c39a97c5048fdc780d32b6edb64b6a70115e29cb8ab98d63ea695ed449b62b"
        );
        assert_eq!(
            note_membership_root(
                network,
                NoteCount::new(2).unwrap(),
                &commitment,
                &NotePosition::new(1),
                &duplicated
            )
            .unwrap(),
            two
        );
    }

    /// Binds every position byte and sibling level while leaving caller owned witness material intact.
    #[test]
    fn guarded_paths_preserve_inputs_and_bind_full_position_and_siblings() {
        let network = NetworkId::from_bytes([7; 64]);
        let count = NoteCount::new(1_u128 << 64).unwrap();
        let commitment = NoteCommitment::from_bytes([11; 64]);
        let siblings = [[12; 64]; 64];
        let position = NotePosition::new(0);
        let original =
            note_membership_root(network, count, &commitment, &position, &siblings).unwrap();
        for bit in [0, 8, 16, 24, 32, 40, 48, 56, 63] {
            assert_ne!(
                note_membership_root(
                    network,
                    count,
                    &commitment,
                    &NotePosition::new(1 << bit),
                    &siblings
                )
                .unwrap(),
                original
            );
        }
        for level in 0..64 {
            let mut changed = siblings;
            changed[level][63] ^= 1;
            assert_ne!(
                note_membership_root(network, count, &commitment, &position, &changed).unwrap(),
                original
            );
        }
        assert_ne!(
            note_membership_root(
                network,
                NoteCount::new(1).unwrap(),
                &commitment,
                &position,
                &siblings
            )
            .unwrap(),
            original
        );
        assert_ne!(
            note_membership_root(
                NetworkId::from_bytes([6; 64]),
                count,
                &commitment,
                &position,
                &siblings
            )
            .unwrap(),
            original
        );
        assert_ne!(
            note_membership_root(
                network,
                count,
                &NoteCommitment::from_bytes([10; 64]),
                &position,
                &siblings
            )
            .unwrap(),
            original
        );
        assert_eq!(siblings, [[12; 64]; 64]);
        assert_eq!(position.value(), 0);
        assert_eq!(
            note_membership_root(network, count, &commitment, &position, &siblings).unwrap(),
            original
        );
    }

    /// Rejects unsupported full parent levels and distinguishes order and occupied leaf roles.
    #[test]
    fn tree_parent_levels_and_roles_are_exact() {
        let network = NetworkId::from_bytes([7; 64]);
        for level in [64, 256, u32::MAX] {
            assert!(
                matches!(note_tree_parent(network,level,&[11;64],&[12;64]),Err(NoteTreeHashError::InvalidLevel {level:actual}) if actual==level)
            );
        }
        assert_ne!(
            note_tree_parent(network, 0, &[11; 64], &[12; 64]).unwrap(),
            note_tree_parent(network, 0, &[12; 64], &[11; 64]).unwrap()
        );
        assert_ne!(
            note_tree_empty_leaf(network).unwrap(),
            note_tree_leaf(network, &NoteCommitment::from_bytes([0; 64])).unwrap()
        );
    }
}
