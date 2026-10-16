//! Declared protocol context shared by transaction bodies.

use crate::{FeeScheduleId, NetworkId, ProofProfileId, ProtocolVersion, ValidityCheckpointRange};

/// The network, rule identifiers and validity window declared by a transaction.
///
/// Payments and reward withdrawals carry these values as part of their bodies,
/// binding them into the transaction's authorization and expected proof
/// statement. The operation kind and its specific fields belong to the body.
///
/// Construction preserves the supplied values without checking that their
/// combination is supported or active. Execution must match the intended
/// network, resolve allowed protocol rules, proof profiles and fee schedules,
/// and check the validity window against the current checkpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TransactionContext {
    network_id: NetworkId,
    protocol_version: ProtocolVersion,
    proof_profile_id: ProofProfileId,
    fee_schedule_id: FeeScheduleId,
    validity_checkpoint_range: ValidityCheckpointRange,
}

impl TransactionContext {
    /// Groups the declared context without checking support or activation.
    pub const fn new(
        network_id: NetworkId,
        protocol_version: ProtocolVersion,
        proof_profile_id: ProofProfileId,
        fee_schedule_id: FeeScheduleId,
        validity_checkpoint_range: ValidityCheckpointRange,
    ) -> Self {
        Self {
            network_id,
            protocol_version,
            proof_profile_id,
            fee_schedule_id,
            validity_checkpoint_range,
        }
    }

    /// Returns the intended network's genesis commitment.
    pub const fn network_id(&self) -> NetworkId {
        self.network_id
    }

    /// Returns the declared protocol rule version.
    pub const fn protocol_version(&self) -> ProtocolVersion {
        self.protocol_version
    }

    /// Returns the declared proof configuration identifier.
    pub const fn proof_profile_id(&self) -> ProofProfileId {
        self.proof_profile_id
    }

    /// Returns the declared fee schedule identifier.
    pub const fn fee_schedule_id(&self) -> FeeScheduleId {
        self.fee_schedule_id
    }

    /// Returns the inclusive checkpoint validity window.
    pub const fn validity_checkpoint_range(&self) -> ValidityCheckpointRange {
        self.validity_checkpoint_range
    }
}
