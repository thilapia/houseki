//! Resource bounds encoded at complete canonical integer widths.

/// Inclusive development resource bounds and anchor history policy.
///
/// Counts remain `u64` until a bounded consumer checks conversion to its host index width.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionLimits {
    /// Maximum canonical transaction body bytes.
    pub(crate) body_bytes: u64,

    /// Maximum encoded transaction proof bytes.
    pub(crate) proof_bytes: u64,

    /// Maximum encrypted output payload bytes.
    pub(crate) output_payload_bytes: u64,

    /// Maximum occurrences in one checkpoint.
    pub(crate) batch_occurrences: u64,

    /// Maximum complete occurrence component bytes per checkpoint.
    pub(crate) batch_bytes: u64,

    /// Maximum units in a finite fixture stream.
    pub(crate) fixture_units: u64,

    /// Maximum occurrences in one source unit.
    pub(crate) unit_occurrences: u64,

    /// Maximum complete occurrence component bytes per unit.
    pub(crate) unit_bytes: u64,

    /// Maximum retained note leaves.
    pub(crate) note_leaves: u64,

    /// Maximum distinct spent markers.
    pub(crate) spent_markers: u64,

    /// Maximum registered reward accounts.
    pub(crate) accounts: u64,

    /// Maximum fixed committee validators.
    pub(crate) validators: u64,

    /// Maximum bytes in one consensus key descriptor.
    pub(crate) key_descriptor_bytes: u64,

    /// Maximum checkpoint positions in the eligible anchor window.
    pub(crate) anchor_window: u64,

    /// Maximum canonical historical anchor records.
    pub(crate) anchor_retention: u64,
}

impl ExecutionLimits {
    /// Returns the fixed bounded reference preset.
    pub(crate) const fn reference() -> Self {
        Self {
            body_bytes: 16384,
            proof_bytes: 2097152,
            output_payload_bytes: 4096,
            batch_occurrences: 64,
            batch_bytes: 16777216,
            fixture_units: 64,
            unit_occurrences: 128,
            unit_bytes: 33554432,
            note_leaves: 4096,
            spent_markers: 4096,
            accounts: 64,
            validators: 64,
            key_descriptor_bytes: 16384,
            anchor_window: 32,
            anchor_retention: 64,
        }
    }

    /// Returns the maximum canonical transaction body bytes.
    pub const fn body_bytes(&self) -> u64 {
        self.body_bytes
    }

    /// Returns the maximum encoded transaction proof bytes.
    pub const fn proof_bytes(&self) -> u64 {
        self.proof_bytes
    }

    /// Returns the maximum encrypted output payload bytes.
    pub const fn output_payload_bytes(&self) -> u64 {
        self.output_payload_bytes
    }

    /// Returns the maximum occurrences in one checkpoint.
    pub const fn batch_occurrences(&self) -> u64 {
        self.batch_occurrences
    }

    /// Returns the maximum complete occurrence component bytes per checkpoint.
    pub const fn batch_bytes(&self) -> u64 {
        self.batch_bytes
    }

    /// Returns the maximum units in a finite fixture stream.
    pub const fn fixture_units(&self) -> u64 {
        self.fixture_units
    }

    /// Returns the maximum occurrences in one source unit.
    pub const fn unit_occurrences(&self) -> u64 {
        self.unit_occurrences
    }

    /// Returns the maximum complete occurrence component bytes per unit.
    pub const fn unit_bytes(&self) -> u64 {
        self.unit_bytes
    }

    /// Returns the maximum retained note leaves.
    pub const fn note_leaves(&self) -> u64 {
        self.note_leaves
    }

    /// Returns the maximum distinct spent markers.
    pub const fn spent_markers(&self) -> u64 {
        self.spent_markers
    }

    /// Returns the maximum registered reward accounts.
    pub const fn accounts(&self) -> u64 {
        self.accounts
    }

    /// Returns the maximum fixed committee validators.
    pub const fn validators(&self) -> u64 {
        self.validators
    }

    /// Returns the maximum bytes in one consensus key descriptor.
    pub const fn key_descriptor_bytes(&self) -> u64 {
        self.key_descriptor_bytes
    }

    /// Returns the maximum checkpoint positions in the eligible anchor window.
    pub const fn anchor_window(&self) -> u64 {
        self.anchor_window
    }

    /// Returns the maximum canonical historical anchor records.
    pub const fn anchor_retention(&self) -> u64 {
        self.anchor_retention
    }
}
