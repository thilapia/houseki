//! Fixed dispatch for the eight payment shapes and one withdrawal workload.

use crate::Error;
use houseki_proofs::{EXPERIMENTAL_PAYMENT_PROFILE, EXPERIMENTAL_REWARD_WITHDRAWAL_PROFILE};
use houseki_types::{
    CheckpointSequence, FeeScheduleId, NetworkId, ProtocolVersion, TransactionContext,
    ValidityCheckpointRange,
};
use std::str::FromStr;

/// One immutable supported workload selected independently of proof bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Workload {
    /// Zero through seven are payment shapes and eight is withdrawal.
    index: u8,
}

impl Workload {
    /// Complete ordered launch workload inventory.
    pub const ALL: [Self; 9] = [
        Self { index: 0 },
        Self { index: 1 },
        Self { index: 2 },
        Self { index: 3 },
        Self { index: 4 },
        Self { index: 5 },
        Self { index: 6 },
        Self { index: 7 },
        Self { index: 8 },
    ];

    /// Returns the stable identifier used by command lines and public artifact directories.
    pub fn label(self) -> String {
        if self.index == 8 {
            "withdrawal".to_owned()
        } else {
            format!("payment-{}-{}", self.index / 2 + 1, self.index % 2 + 1)
        }
    }

    /// Returns payment counts, with withdrawal represented by no payment shape.
    pub fn counts(self) -> Option<(usize, usize)> {
        (self.index < 8).then_some((self.index as usize / 2 + 1, self.index as usize % 2 + 1))
    }

    /// Fixes expected rules independently of all loaded body and proof metadata.
    pub fn context(self) -> TransactionContext {
        TransactionContext::new(
            NetworkId::from_bytes([7; 64]),
            ProtocolVersion::new(1),
            if self.counts().is_some() {
                EXPERIMENTAL_PAYMENT_PROFILE
            } else {
                EXPERIMENTAL_REWARD_WITHDRAWAL_PROFILE
            },
            FeeScheduleId::new(4),
            ValidityCheckpointRange::new(CheckpointSequence::new(5), CheckpointSequence::new(8))
                .expect("fixed ordered checkpoints"),
        )
    }
}

impl FromStr for Workload {
    /// Rejects selectors outside the complete supported workload inventory.
    type Err = Error;

    /// Accepts only exact canonical labels, including their count spelling.
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|workload| workload.label() == value)
            .ok_or(Error::Input("unknown workload"))
    }
}

/// Fixed shape inventory and hostile selector rejection.
#[cfg(test)]
mod tests {
    use super::*;

    /// Every supported label round trips while unsupported counts and alternate spelling fail.
    #[test]
    fn fixed_inventory_round_trips_and_rejects_other_shapes() {
        for workload in Workload::ALL {
            assert_eq!(workload.label().parse::<Workload>().unwrap(), workload);
        }

        for label in [
            "",
            "payment-0-1",
            "payment-5-2",
            "payment-4-3",
            "payment-01-1",
            "withdrawal ",
        ] {
            assert!(label.parse::<Workload>().is_err());
        }
    }
}
