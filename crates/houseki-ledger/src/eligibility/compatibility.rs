//! Immutable interpretation shared by independently executed checkpoint slices.

use crate::{CommitteeEntry, ParentSnapshot, UnitPreparationError, encode_policy};
use houseki_types::{CommitteeContext, EncodedMlDsa87PublicKey, NetworkId, RewardAccountId};

/// Exact private recognition implementation revision.
const VERIFIER_REGISTRY_REVISION: u32 = 1;

/// Structural immutable compatibility across independently executed slices.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct Compatibility {
    /// Local registry interpretation revision.
    registry_revision: u32,

    /// Account and anchor interpretation network.
    network: NetworkId,

    /// Exact complete canonical policy bytes.
    policy: Vec<u8>,

    /// Sorted complete source identities and immutable public authorities.
    authorities: Vec<(RewardAccountId, EncodedMlDsa87PublicKey)>,

    /// Fixed epoch and committee identity.
    committee_context: CommitteeContext,

    /// Complete sorted immutable validator registrations.
    committee: Vec<CommitteeEntry>,
}

impl Compatibility {
    /// Captures immutable interpretation while excluding balances, nonces, spent and
    /// history.
    pub(super) fn capture(parent: &ParentSnapshot) -> Result<Self, UnitPreparationError> {
        let mut authorities = Vec::new();
        authorities
            .try_reserve_exact(parent.state().accounts.len())
            .map_err(|_| UnitPreparationError::Allocation)?;
        authorities.extend(parent.state().accounts().map(|(id, a)| {
            (
                RewardAccountId::from_bytes(*id),
                a.withdrawal_authority().clone(),
            )
        }));

        authorities.sort_unstable_by_key(|a| a.0.into_bytes());

        let mut committee = Vec::new();
        committee
            .try_reserve_exact(parent.state().committee.len())
            .map_err(|_| UnitPreparationError::Allocation)?;
        committee.extend(parent.state().committee().cloned());
        committee.sort_unstable_by_key(|c| c.validator().into_bytes());

        Ok(Self {
            registry_revision: VERIFIER_REGISTRY_REVISION,
            network: parent.state().network(),
            policy: encode_policy(parent.state().policy())?,
            authorities,
            committee_context: parent.state().committee_context(),
            committee,
        })
    }
}
