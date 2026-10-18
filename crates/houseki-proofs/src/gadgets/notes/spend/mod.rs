//! Linked authority and position-bound nullifier constraints for one spent note.

#[cfg(test)]
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
pub(crate) use error::SpendError;
#[cfg(any(test, feature = "prover"))]
pub(crate) use input::Input;

use crate::gadgets::poseidon2::ScheduledHash;
use p3_air::AirBuilder;
use p3_field::PrimeCharacteristicRing;
use p3_goldilocks::Goldilocks;

/// Four complete hashes linking both secrets to ownership and the original note instance.
///
/// Columns 0 through 63 hold the keys and 64 through 191 hold their two complete digests.
///
/// Columns 192 through 1100 reuse hash work cells across 21, 21, 23 and 23 consecutive rows.
///
/// The caller binds network, opening ownership, note commitment, original position and marker
/// through the same endpoints throughout the invocation and owns inactive-row constraints.
pub(crate) struct Spend {
    /// Network and spending secret commitment.
    spending: ScheduledHash<4>,

    /// Network and nullifier secret commitment.
    nullifier_key: ScheduledHash<4>,

    /// Network and both complete inner commitments.
    ownership: ScheduledHash<6>,

    /// Network, V1 note version, nullifier secret, note commitment and original position.
    nullifier: ScheduledHash<6>,
}

impl Spend {
    /// Private key and digest registers followed by shared hash scratch.
    pub(crate) const WIDTH: usize = 1101;

    /// Exact number of consecutive active phases without power-of-two padding.
    pub(crate) const ROWS: usize = 88;

    /// Resolves exact native domains and part lengths without witness-dependent metadata.
    pub(crate) fn new() -> Self {
        Self {
            spending: ScheduledHash::new(b"houseki/v1/ownership/spend-key", &[64, 32]).unwrap(),
            nullifier_key: ScheduledHash::new(b"houseki/v1/ownership/nullifier-key", &[64, 32])
                .unwrap(),
            ownership: ScheduledHash::new(b"houseki/v1/ownership/commitment", &[64, 64, 64])
                .unwrap(),
            nullifier: ScheduledHash::new(b"houseki/v1/note/nullifier", &[64, 4, 32, 64, 8])
                .unwrap(),
        }
    }

    /// Constrains all sources and endpoints under trusted consecutive one-hot phase selectors.
    ///
    /// The caller must not schedule an invocation across the final trace row.
    pub(crate) fn eval<AB: AirBuilder<F = Goldilocks>>(
        &self,
        builder: &mut AB,
        row: &[AB::Var; 1101],
        next: &[AB::Var; 1101],
        phases: &[AB::Expr],
        endpoints: Endpoints<'_, AB::Expr>,
    ) {
        assert_eq!(phases.len(), Self::ROWS);
        let continuing: AB::Expr = phases[..Self::ROWS - 1].iter().cloned().sum();
        for column in 0..192 {
            builder
                .when_transition()
                .when(continuing.clone())
                .assert_eq(row[column], next[column]);
        }

        let spending: [AB::Expr; 32] = std::array::from_fn(|index| row[index].into());
        let nullifier: [AB::Expr; 32] = std::array::from_fn(|index| row[32 + index].into());
        let first: [AB::Expr; 64] = std::array::from_fn(|index| row[64 + index].into());
        let second: [AB::Expr; 64] = std::array::from_fn(|index| row[128 + index].into());
        let version = std::array::from_fn::<_, 4, _>(|index| AB::Expr::from_bool(index == 0));
        let work = row[192..].try_into().unwrap();
        let next_work = next[192..].try_into().unwrap();
        self.spending.eval_linked(
            builder,
            work,
            next_work,
            &phases[..21],
            &[endpoints.network, &spending],
            &first,
        );
        self.nullifier_key.eval_linked(
            builder,
            work,
            next_work,
            &phases[21..42],
            &[endpoints.network, &nullifier],
            &second,
        );
        self.ownership.eval_linked(
            builder,
            work,
            next_work,
            &phases[42..65],
            &[endpoints.network, &first, &second],
            endpoints.ownership,
        );
        self.nullifier.eval_linked(
            builder,
            work,
            next_work,
            &phases[65..],
            &[
                endpoints.network,
                &version,
                &nullifier,
                endpoints.commitment,
                endpoints.position,
            ],
            endpoints.nullifier,
        );
    }
}

/// Complete source linkage tested independently of native spending validation.
#[cfg(all(test, feature = "prover"))]
mod tests {
    use super::*;
    use houseki_crypto::{NullifierKey, SpendingKey};
    use houseki_types::{NetworkId, NoteCommitment, NotePosition, NoteVersion};
    use p3_air::check_all_constraints;
    use p3_field::{PrimeCharacteristicRing, PrimeField64};
    use p3_goldilocks::Goldilocks;
    use p3_matrix::dense::RowMajorMatrix;

    /// Confirms the declared degree against every symbolic constraint and periodic selector.
    #[test]
    fn spend_geometry_matches_symbolic_constraints() {
        use p3_air::{
            BaseAir,
            symbolic::{AirLayout, get_max_constraint_degree},
        };

        let air = air::SpendAir::new();

        assert_eq!(air.width(), 1101);
        assert_eq!(
            get_max_constraint_degree(&air, AirLayout::from_air(&air), 128),
            4
        );
    }

    /// Builds synthetic public endpoints using the native authority and nullifier transcripts.
    fn public(spending: &[u8; 32], nullifier: &[u8; 32], position: u64) -> Vec<Goldilocks> {
        let network = NetworkId::from_bytes([7; 64]);
        let commitment = NoteCommitment::from_bytes([13; 64]);
        let spending = SpendingKey::from_bytes(spending);
        let nullifier = NullifierKey::from_bytes(nullifier);
        let mut bytes = network.as_bytes().to_vec();
        bytes.extend_from_slice(
            spending
                .ownership_commitment(network, &nullifier)
                .unwrap()
                .as_bytes(),
        );
        bytes.extend_from_slice(commitment.as_bytes());
        bytes.extend_from_slice(&position.to_le_bytes());
        bytes.extend_from_slice(
            nullifier
                .nullifier(
                    network,
                    NoteVersion::new(1),
                    commitment,
                    &NotePosition::new(position),
                )
                .unwrap()
                .as_bytes(),
        );

        bytes.into_iter().map(Goldilocks::from_u8).collect()
    }

    /// Assigns all four hashes from guarded field views into one caller-owned operation.
    fn rows(
        air: &air::SpendAir,
        public: &[Goldilocks],
        spending: &[u8; 32],
        nullifier: &[u8; 32],
    ) -> Vec<Goldilocks> {
        let spending = spending.map(Goldilocks::from_u8);
        let nullifier = nullifier.map(Goldilocks::from_u8);
        let input = Input {
            spending_key: &spending,
            nullifier_key: &nullifier,
            network: public[..64].try_into().unwrap(),
            commitment: public[128..192].try_into().unwrap(),
            position: public[192..200].try_into().unwrap(),
        };
        let mut rows = vec![Goldilocks::ZERO; 128 * Spend::WIDTH];
        let (result, allocations, _) =
            crate::test_allocator::measure(|| air.spend.assign(input, &mut rows, Spend::WIDTH));
        result.unwrap();
        assert_eq!(allocations, 0);

        rows
    }

    /// Matches native ownership and nullifiers for zero, mixed and maximum position bytes.
    #[test]
    fn spend_matches_native_authority_and_position_bound_nullifiers() {
        let air = air::SpendAir::new();
        for (spending, nullifier, position) in [
            ([0; 32], [255; 32], 0),
            ([17; 32], [29; 32], 0x0102030405060708),
            ([255; 32], [0; 32], u64::MAX),
        ] {
            let public = public(&spending, &nullifier, position);
            let rows = rows(&air, &public, &spending, &nullifier);

            assert!(
                check_all_constraints(
                    &air,
                    &RowMajorMatrix::new(rows, Spend::WIDTH),
                    &public,
                    Some(4)
                )
                .is_ok()
            );
        }
    }

    /// Rejects direct changes to secrets, both key digests and every external relation link.
    #[test]
    fn spend_rejects_mutated_secrets_intermediates_and_endpoints() {
        let air = air::SpendAir::new();
        let public = public(&[17; 32], &[29; 32], 9);
        let rows = rows(&air, &public, &[17; 32], &[29; 32]);
        for (phase, column) in [
            (0, 0),
            (21, 32),
            (42, 64),
            (42, 128),
            (64, 191),
            (5, 1049),
            (26, 1049),
            (49, 1049),
            (72, 1049),
            (127, 0),
        ] {
            let mut changed = rows.clone();
            changed[phase * Spend::WIDTH + column] += Goldilocks::ONE;

            assert!(
                !check_all_constraints(
                    &air,
                    &RowMajorMatrix::new(changed, Spend::WIDTH),
                    &public,
                    Some(1)
                )
                .is_ok(),
                "cell {phase}:{column}"
            );
        }

        for index in [0, 63, 64, 127, 128, 191, 192, 199, 200, 263] {
            let mut changed = public.clone();
            changed[index] += Goldilocks::ONE;

            assert!(
                !check_all_constraints(
                    &air,
                    &RowMajorMatrix::new(rows.clone(), Spend::WIDTH),
                    &changed,
                    Some(1)
                )
                .is_ok(),
                "endpoint {index}"
            );
        }
    }

    /// A coherent replacement nullifier secret and marker cannot keep the original opening ownership.
    #[test]
    fn spend_rehashed_nullifier_secret_still_requires_original_ownership() {
        let air = air::SpendAir::new();
        let original = public(&[17; 32], &[29; 32], 9);
        let mut changed = public(&[17; 32], &[30; 32], 9);
        let rows = rows(&air, &changed, &[17; 32], &[30; 32]);
        changed[64..128].copy_from_slice(&original[64..128]);

        assert!(
            !check_all_constraints(
                &air,
                &RowMajorMatrix::new(rows, Spend::WIDTH),
                &changed,
                Some(1)
            )
            .is_ok()
        );
    }

    /// Original position changes the marker while repeated derivation has no anchor input.
    #[test]
    fn spend_marker_identity_depends_on_original_position() {
        let first = public(&[17; 32], &[29; 32], 9);
        let repeated = public(&[17; 32], &[29; 32], 9);
        let other = public(&[17; 32], &[29; 32], 10);

        assert_eq!(&first[200..], &repeated[200..]);
        assert_ne!(&first[200..], &other[200..]);
        assert_eq!(&first[..192], &other[..192]);
    }

    /// Invalid final sources leave every destination cell unchanged, and valid writes preserve gaps.
    #[test]
    fn spend_assignment_preflights_sources_and_strided_storage() {
        let spend = Spend::new();
        let key = [Goldilocks::ZERO; 32];
        let network = [Goldilocks::ZERO; 64];
        let mut position = [Goldilocks::ZERO; 8];
        position[7] = Goldilocks::from_u16(256);
        let mut rows = vec![Goldilocks::NEG_ONE; 88 * 1110];
        let input = |position| Input {
            spending_key: &key,
            nullifier_key: &key,
            network: &network,
            commitment: &network,
            position,
        };

        assert_eq!(
            spend.assign(input(&position), &mut rows, 1110),
            Err(SpendError::InvalidByte)
        );
        assert!(rows.iter().all(|value| *value == Goldilocks::NEG_ONE));
        for stride in [0, 1100, usize::MAX] {
            assert_eq!(
                spend.assign(input(&position), &mut rows, stride),
                Err(SpendError::ShapeMismatch)
            );
            assert!(rows.iter().all(|value| *value == Goldilocks::NEG_ONE));
        }

        let valid_position = [Goldilocks::ZERO; 8];
        spend
            .assign(input(&valid_position), &mut rows, 1110)
            .unwrap();

        assert!(rows.as_chunks::<1110>().0.iter().all(|row| {
            row[1101..]
                .iter()
                .all(|value| *value == Goldilocks::NEG_ONE)
        }));
    }

    /// The two independent inner-key digests retain the established native integer vectors.
    #[test]
    fn spend_inner_commitments_match_native_vectors() {
        let air = air::SpendAir::new();
        let mut public = public(&[0; 32], &[0; 32], 0);
        public[..64].fill(Goldilocks::ZERO);
        let rows = rows(&air, &public, &[0; 32], &[0; 32]);
        let actual: String = rows[64..128]
            .iter()
            .map(|value| format!("{:02x}", value.as_canonical_u64()))
            .collect();

        let nullifier: String = rows[128..192]
            .iter()
            .map(|value| format!("{:02x}", value.as_canonical_u64()))
            .collect();

        assert_eq!(
            nullifier,
            "163a7706a8455fd5dbd410d3011524184fbeab1995ca0676b6438aab351255eff5a3dc146a6b9e3d48488bf4086c726114a8932906a03928047cbb510270a946"
        );
        assert_eq!(
            actual,
            "2ca91de1c497fcf205aac4fbc2fcd25200f68355b9339b628f2ac8fe55995e30ee1c165304dd02e61fab7bcb1cb5a314805a584b1e54287e36201fd949804ba9"
        );
    }
}
