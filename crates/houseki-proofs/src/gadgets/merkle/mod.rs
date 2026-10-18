//! Occupied depth-64 membership with exact original-position and count binding.

#[cfg(all(test, feature = "prover"))]
mod air;
#[cfg(any(test, feature = "prover"))]
mod assignment;
mod endpoints;
#[cfg(any(test, feature = "prover"))]
mod error;
#[cfg(any(test, feature = "prover"))]
mod input;

pub(crate) use endpoints::Endpoints;
#[cfg(any(test, feature = "prover"))]
pub(crate) use error::MembershipError;
#[cfg(any(test, feature = "prover"))]
pub(crate) use input::Input;

use crate::gadgets::{eval_byte, poseidon2::CompactHash};
use p3_air::AirBuilder;
use p3_field::PrimeCharacteristicRing;
use p3_goldilocks::Goldilocks;

/// Occupied leaf, every oriented parent and the count-bound root under one expected network.
///
/// Columns 0 through 191 hold the current node, sibling and next node respectively.
///
/// Columns 192 through 199 hold the selected position byte bits during each parent hash.
///
/// Columns 256 through 479 hold occupancy auxiliaries only on the dedicated initial row.
///
/// Columns 200 through 990 then reuse hash scratch with no duplicated path owner.
pub(crate) struct Membership {
    /// Network and complete occupied note commitment.
    leaf: CompactHash<4>,

    /// Network, trusted level and both selected children.
    parent: CompactHash<6>,

    /// Network, fixed depth, complete occupied count and final top node.
    root: CompactHash<5>,
}

impl Membership {
    /// Private node registers, occupancy auxiliaries and shared hash scratch.
    pub(crate) const WIDTH: usize = 991;

    /// One leaf, sixty-four parents and one final root.
    pub(crate) const ROWS: usize = 1516;

    /// Leaf, repeated parent and root phases followed by sixty-four trusted level selectors.
    pub(crate) const SELECTORS: usize = 131;

    /// Selects exact depth-64 native transcript domains and lengths.
    pub(crate) fn new() -> Self {
        Self {
            leaf: CompactHash::new(b"houseki/v1/note-tree/leaf", &[64, 64]).unwrap(),
            parent: CompactHash::new(b"houseki/v1/note-tree/node", &[64, 4, 64, 64]).unwrap(),
            root: CompactHash::new(b"houseki/v1/note-tree/root", &[64, 4, 16, 64]).unwrap(),
        }
    }

    /// Evaluates exactly one complete invocation under trusted phase and level selectors.
    ///
    /// Selectors 0 through 20 describe the leaf, 21 through 43 the parent, 44 through 65
    /// the root and 66 through 129 the current parent level. Selector 130 marks occupancy.
    ///
    /// The caller supplies stable external endpoints, forbids a final-row-crossing invocation
    /// and constrains all cells outside active membership phases.
    pub(crate) fn eval<AB: AirBuilder<F = Goldilocks>>(
        &self,
        builder: &mut AB,
        row: &[AB::Var; 991],
        next: &[AB::Var; 991],
        phases: &[AB::Expr],
        endpoints: Endpoints<'_, AB::Expr>,
    ) {
        assert_eq!(phases.len(), Self::SELECTORS);
        let leaf: AB::Expr = phases[..21].iter().cloned().sum();
        let parent: AB::Expr = phases[21..44].iter().cloned().sum();
        let root: AB::Expr = phases[44..66].iter().cloned().sum();
        for bit in 0..8 {
            builder.when(phases[21].clone()).assert_bool(row[192 + bit]);
            builder
                .when_transition()
                .when(parent.clone() - phases[43].clone())
                .assert_eq(row[192 + bit], next[192 + bit]);
            builder
                .when(leaf.clone() + root.clone() + phases[130].clone())
                .assert_zero(row[192 + bit]);
        }

        let selected_byte: AB::Expr = (0..64)
            .map(|level| phases[66 + level].clone() * endpoints.position[level / 8].clone())
            .sum();
        let reconstructed: AB::Expr = (0..8)
            .map(|bit| row[192 + bit] * Goldilocks::from_u8(1 << bit))
            .sum();
        builder
            .when(phases[21].clone())
            .assert_eq(reconstructed, selected_byte);

        let within = leaf.clone() - phases[20].clone() + parent.clone() - phases[43].clone();
        for column in 0..192 {
            builder
                .when_transition()
                .when(within.clone())
                .assert_eq(row[column], next[column]);
        }

        for column in 0..64 {
            builder
                .when_transition()
                .when(root.clone() - phases[65].clone())
                .assert_eq(row[column], next[column]);
            builder
                .when_transition()
                .when(phases[20].clone() + phases[43].clone())
                .assert_eq(row[128 + column], next[column]);
        }

        for value in &row[..128] {
            builder.when(leaf.clone()).assert_zero(*value);
        }

        for value in &row[64..192] {
            builder.when(root.clone()).assert_zero(*value);
        }

        for value in row[..192]
            .iter()
            .chain(row[200..256].iter())
            .chain(row[480..].iter())
        {
            builder.when(phases[130].clone()).assert_zero(*value);
        }

        self.eval_occupancy(builder, row, phases[130].clone(), &endpoints);
        let current: [AB::Expr; 64] = std::array::from_fn(|index| row[index].into());
        let digest: [AB::Expr; 64] = std::array::from_fn(|index| row[128 + index].into());
        let orientation: AB::Expr = (0..64)
            .map(|level| phases[66 + level].clone() * row[192 + level % 8])
            .sum();
        let left: [AB::Expr; 64] = std::array::from_fn(|index| {
            current[index].clone() + orientation.clone() * (row[64 + index] - row[index])
        });
        let right: [AB::Expr; 64] = std::array::from_fn(|index| {
            row[64 + index] + orientation.clone() * (row[index] - row[64 + index])
        });
        let level: AB::Expr = (0..64)
            .map(|level| phases[66 + level].clone() * Goldilocks::from_usize(level))
            .sum();
        let level = [level, AB::Expr::ZERO, AB::Expr::ZERO, AB::Expr::ZERO];
        let depth = [
            AB::Expr::from_u8(64),
            AB::Expr::ZERO,
            AB::Expr::ZERO,
            AB::Expr::ZERO,
        ];
        let work = row[200..].try_into().unwrap();
        let next_work = next[200..].try_into().unwrap();
        self.leaf.eval_linked(
            builder,
            work,
            next_work,
            &phases[..21],
            &[endpoints.network, endpoints.commitment],
            &digest,
        );
        self.parent.eval_linked(
            builder,
            work,
            next_work,
            &phases[21..44],
            &[endpoints.network, &level, &left, &right],
            &digest,
        );
        self.root.eval_linked(
            builder,
            work,
            next_work,
            &phases[44..66],
            &[endpoints.network, &depth, endpoints.count, &current],
            endpoints.root,
        );
    }

    /// Proves position plus one plus a nonnegative difference equals the bounded occupied count.
    fn eval_occupancy<AB: AirBuilder<F = Goldilocks>>(
        &self,
        builder: &mut AB,
        row: &[AB::Var; 991],
        selector: AB::Expr,
        endpoints: &Endpoints<'_, AB::Expr>,
    ) {
        let mut builder = builder.when(selector);
        for byte in 0..8 {
            let mut value = AB::Expr::ZERO;
            for bit in 0..8 {
                let cell = row[416 + byte * 8 + bit];
                builder.assert_bool(cell);
                value += cell * Goldilocks::from_u8(1 << bit);
            }

            builder.assert_eq(endpoints.position[byte].clone(), value);
        }

        let mut carry = AB::Expr::ONE;
        for byte in 0..16 {
            eval_byte(
                &mut builder,
                row[256 + byte],
                row[272 + byte * 8..280 + byte * 8].try_into().unwrap(),
            );
            builder.assert_bool(row[400 + byte]);
            let position = if byte < 8 {
                endpoints.position[byte].clone()
            } else {
                AB::Expr::ZERO
            };
            builder.assert_eq(
                position + row[256 + byte] + carry,
                endpoints.count[byte].clone() + row[400 + byte] * Goldilocks::from_u16(256),
            );
            carry = row[400 + byte].into();
        }

        builder.assert_zero(carry);
        builder.assert_bool(endpoints.count[8].clone());
        for byte in &endpoints.count[9..] {
            builder.assert_zero(byte.clone());
        }

        builder.assert_zero(
            endpoints.count[8].clone() * endpoints.count[..8].iter().cloned().sum::<AB::Expr>(),
        );
    }
}

/// Independent native paths and adversarial constraints without spending prechecks.
#[cfg(all(test, feature = "prover"))]
mod tests {
    use super::*;
    use houseki_crypto::note_membership_root;
    use houseki_types::{NetworkId, NoteCommitment, NoteCount, NotePosition};
    use p3_air::check_all_constraints;
    use p3_field::PrimeCharacteristicRing;
    use p3_goldilocks::Goldilocks;
    use p3_matrix::dense::RowMajorMatrix;

    /// Confirms the declared degree against every symbolic constraint and periodic selector.
    #[test]
    fn membership_geometry_matches_symbolic_constraints() {
        use p3_air::{
            BaseAir,
            symbolic::{AirLayout, get_max_constraint_degree},
        };

        let air = air::MembershipAir::new();

        assert_eq!(air.width(), 991);
        assert_eq!(
            get_max_constraint_degree(&air, AirLayout::from_air(&air), 2048),
            4
        );
    }

    /// Creates a synthetic relation path, including full-tree fixtures without allocating leaves.
    fn fixture(count: u128, position: u64) -> (Vec<Goldilocks>, [[Goldilocks; 64]; 64]) {
        let network = NetworkId::from_bytes([7; 64]);
        let commitment = NoteCommitment::from_bytes([13; 64]);
        let siblings =
            std::array::from_fn(|level| std::array::from_fn(|byte| (level + byte) as u8));
        let root = note_membership_root(
            network,
            NoteCount::new(count).unwrap(),
            &commitment,
            &NotePosition::new(position),
            &siblings,
        )
        .unwrap();
        let mut bytes = network.as_bytes().to_vec();
        bytes.extend_from_slice(&count.to_le_bytes());
        bytes.extend_from_slice(commitment.as_bytes());
        bytes.extend_from_slice(&position.to_le_bytes());
        bytes.extend_from_slice(root.as_bytes());

        (
            bytes.into_iter().map(Goldilocks::from_u8).collect(),
            siblings.map(|sibling| sibling.map(Goldilocks::from_u8)),
        )
    }

    /// Borrows exact fields used by the component and the independent public-endpoint AIR.
    fn input<'a>(public: &'a [Goldilocks], siblings: &'a [[Goldilocks; 64]; 64]) -> Input<'a> {
        Input {
            network: public[..64].try_into().unwrap(),
            count: public[64..80].try_into().unwrap(),
            commitment: public[80..144].try_into().unwrap(),
            position: public[144..152].try_into().unwrap(),
            siblings,
        }
    }

    /// Native roots agree for both orientations, first occupancy and the complete tree boundary.
    #[test]
    fn membership_matches_native_all_levels_and_full_count() {
        let air = air::MembershipAir::new();
        for (count, position) in [
            (1, 0),
            (2, 1),
            (1_u128 << 64, u64::MAX),
            (1_u128 << 64, 0xaaaaaaaaaaaaaaaa),
        ] {
            let (public, siblings) = fixture(count, position);
            let mut rows = vec![Goldilocks::ZERO; 2048 * Membership::WIDTH];
            let (result, allocations, _) = crate::test_allocator::measure(|| {
                air.membership
                    .assign(input(&public, &siblings), &mut rows, Membership::WIDTH)
            });
            result.unwrap();

            assert_eq!(allocations, 0);
            assert!(
                check_all_constraints(
                    &air,
                    &RowMajorMatrix::new(rows, Membership::WIDTH),
                    &public,
                    Some(4)
                )
                .is_ok()
            );
        }
    }

    /// No path level, selected direction or complete endpoint can be changed independently.
    #[test]
    fn membership_rejects_each_path_level_and_endpoint() {
        let air = air::MembershipAir::new();
        let (public, siblings) = fixture(1_u128 << 64, 0xaaaaaaaaaaaaaaaa);
        let mut rows = vec![Goldilocks::ZERO; 2048 * Membership::WIDTH];
        air.membership
            .assign(input(&public, &siblings), &mut rows, Membership::WIDTH)
            .unwrap();
        for level in 0..64 {
            let phase = 22 + 23 * level;
            for column in [64, 192 + level % 8] {
                let index = phase * Membership::WIDTH + column;
                rows[index] += Goldilocks::ONE;

                assert!(
                    !air.valid_row(&rows, &public, phase),
                    "level {level}, column {column}"
                );
                rows[index] -= Goldilocks::ONE;
            }
        }

        for index in [0, 63, 64, 72, 79, 80, 143, 144, 151, 152, 215] {
            let mut changed = public.clone();
            changed[index] += Goldilocks::ONE;

            assert!(
                !check_all_constraints(
                    &air,
                    &RowMajorMatrix::new(rows.clone(), Membership::WIDTH),
                    &changed,
                    Some(1)
                )
                .is_ok(),
                "endpoint {index}"
            );
        }
    }

    /// Rehashed directions remain bound to the original expected root.
    #[test]
    fn membership_rehashed_directions_cannot_replace_the_anchor() {
        let air = air::MembershipAir::new();
        let (original, _) = fixture(1_u128 << 64, 0);
        for position in [1, 1_u64 << 63] {
            let (mut public, siblings) = fixture(1_u128 << 64, position);
            let mut rows = vec![Goldilocks::ZERO; 2048 * Membership::WIDTH];
            air.membership
                .assign(input(&public, &siblings), &mut rows, Membership::WIDTH)
                .unwrap();
            public[152..].copy_from_slice(&original[152..]);

            assert!((1500..1516).any(|phase| !air.valid_row(&rows, &public, phase)));
        }
    }

    /// A coherent count-bound root cannot make an unoccupied position satisfy integer comparison.
    #[test]
    fn membership_occupancy_rejects_coherently_rehashed_invalid_count() {
        let air = air::MembershipAir::new();
        let (valid, siblings) = fixture(2, 1);
        let (invalid, _) = fixture(1, 1);
        let mut rows = vec![Goldilocks::ZERO; 2048 * Membership::WIDTH];
        air.membership
            .assign(input(&valid, &siblings), &mut rows, Membership::WIDTH)
            .unwrap();
        let top: [Goldilocks; 64] = rows[1494 * Membership::WIDTH..1494 * Membership::WIDTH + 64]
            .try_into()
            .unwrap();
        let depth = [
            Goldilocks::from_u8(64),
            Goldilocks::ZERO,
            Goldilocks::ZERO,
            Goldilocks::ZERO,
        ];
        air.membership
            .root
            .assign(
                &[&invalid[..64], &depth, &invalid[64..80], &top],
                &mut rows[1494 * Membership::WIDTH + 200..],
                Membership::WIDTH,
            )
            .unwrap();

        assert!((1494..1516).all(|phase| air.valid_row(&rows, &invalid, phase)));
        assert!(!air.valid_row(&rows, &invalid, 0));
    }

    /// Uses an actual occupied native tree and its original witness through the same constraints.
    #[test]
    fn membership_matches_actual_note_tree_witness() {
        let network = NetworkId::from_bytes([7; 64]);
        let commitment = NoteCommitment::from_bytes([13; 64]);
        let mut tree = houseki_state::NoteTree::new(network).unwrap();
        let position = tree.append(commitment).unwrap();
        tree.append(NoteCommitment::from_bytes([19; 64])).unwrap();
        let witness = tree.witness(&position).unwrap();
        let (mut public, mut siblings) = fixture(2, position.value());
        public[152..].copy_from_slice(&tree.anchor().root().as_bytes().map(Goldilocks::from_u8));
        let mut bytes = zeroize::Zeroizing::new([0; 64]);
        for (level, sibling) in siblings.iter_mut().enumerate() {
            witness.write_proof_sibling(level, &mut bytes).unwrap();
            for (cell, byte) in sibling.iter_mut().zip(bytes.iter()) {
                *cell = Goldilocks::from_u8(*byte);
            }
        }

        let air = air::MembershipAir::new();
        let mut rows = vec![Goldilocks::ZERO; 2048 * Membership::WIDTH];
        air.membership
            .assign(input(&public, &siblings), &mut rows, Membership::WIDTH)
            .unwrap();

        assert!(
            check_all_constraints(
                &air,
                &RowMajorMatrix::new(rows, Membership::WIDTH),
                &public,
                Some(4)
            )
            .is_ok()
        );
    }

    /// Invalid final path bytes and excessive counts preserve the entire destination.
    #[test]
    fn membership_assignment_preflights_every_source_and_layout() {
        let membership = Membership::new();
        let (mut public, mut siblings) = fixture(1, 0);
        siblings[63][63] = Goldilocks::from_u16(256);
        let mut rows = vec![Goldilocks::NEG_ONE; Membership::ROWS * Membership::WIDTH];

        assert_eq!(
            membership.assign(input(&public, &siblings), &mut rows, Membership::WIDTH),
            Err(MembershipError::InvalidByte)
        );
        assert!(rows.iter().all(|value| *value == Goldilocks::NEG_ONE));
        for stride in [0, Membership::WIDTH - 1, usize::MAX] {
            assert_eq!(
                membership.assign(input(&public, &siblings), &mut rows, stride),
                Err(MembershipError::ShapeMismatch)
            );
        }

        siblings[63][63] = Goldilocks::ZERO;
        public[64..80]
            .copy_from_slice(&((1_u128 << 64) + 1).to_le_bytes().map(Goldilocks::from_u8));

        assert_eq!(
            membership.assign(input(&public, &siblings), &mut rows, Membership::WIDTH),
            Err(MembershipError::InvalidCount)
        );
        assert!(rows.iter().all(|value| *value == Goldilocks::NEG_ONE));
    }

    /// Empty anchors and positions at or beyond occupancy fail before any destination changes.
    #[test]
    fn membership_assignment_rejects_unoccupied_positions_atomically() {
        let membership = Membership::new();
        for (count, position) in [(0, 0), (1, 1), (19, 19), (19, 20)] {
            let (public, siblings) = fixture(count, position);
            let mut rows = vec![Goldilocks::NEG_ONE; Membership::ROWS * Membership::WIDTH];

            assert_eq!(
                membership.assign(input(&public, &siblings), &mut rows, Membership::WIDTH),
                Err(MembershipError::UnoccupiedPosition)
            );
            assert!(rows.iter().all(|value| *value == Goldilocks::NEG_ONE));
        }
    }
}
