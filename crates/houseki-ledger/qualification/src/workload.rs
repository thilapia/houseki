//! Exact named local qualification workloads and supported payment shapes.

use crate::QualificationError;

/// One complete local proof/execution workload with explicit fixture trust.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Workload {
    /// One actual payment under a supported input/output pair.
    Payment {
        /// Real input count from one through four.
        inputs: usize,

        /// Ordinary output count from one through two.
        outputs: usize,
    },

    /// One actual signed reward withdrawal.
    Withdrawal,

    /// Exact payment, reward withdrawal, native recovery and subsequent note spend.
    ValueLoop,

    /// Equal ordinary output commitments retained at separate positions.
    RepeatedCommitments,

    /// Genuine conflicting occurrences credit the first successful author only.
    Conflicts,

    /// An early failed withdrawal succeeds after a fee credit and later fails nonce.
    FailedEarlyCopy,

    /// Multiple distinct authors share one registered fee beneficiary.
    SharedBeneficiary,

    /// A real old proof still verifies after pruning but its expired anchor is state rejected.
    AnchorPruning,
}

impl Workload {
    /// Requires actual named outcomes and accounting independently of archive replay consistency.
    pub(crate) fn validate_checkpoints(
        self,
        checkpoints: &[houseki_ledger::CommittedCheckpoint],
    ) -> Result<(), QualificationError> {
        use houseki_types::{ExecutionOutcome as O, ExecutionRejectionReason as R};
        let expected = match self {
            Self::Payment { inputs, outputs } => {
                if !(1..=4).contains(&inputs) || !(1..=2).contains(&outputs) {
                    return Err(QualificationError::Input("unsupported payment shape"));
                }
                vec![(
                    vec![O::Accepted],
                    outputs,
                    (inputs * 100 - inputs - outputs) as u128,
                )]
            }
            Self::RepeatedCommitments => vec![(vec![O::Accepted], 2, 196)],
            Self::Withdrawal => vec![(vec![O::Accepted], 1, 3)],
            Self::Conflicts => vec![(vec![O::Accepted, O::Rejected(R::SpentNullifier)], 1, 98)],
            Self::AnchorPruning => {
                let mut expected = vec![
                    (vec![O::Accepted], 1, 98),
                    (vec![O::Rejected(R::SpentNullifier)], 0, 98),
                ];
                expected.extend((0..62).map(|_| (vec![], 0, 98)));
                expected.push((vec![O::Rejected(R::DisallowedAnchor)], 0, 98));
                expected
            }
            Self::ValueLoop | Self::SharedBeneficiary => vec![
                (vec![O::Accepted, O::Accepted], 3, 99),
                (vec![O::Accepted], 1, 97),
            ],
            Self::FailedEarlyCopy => vec![
                (
                    vec![
                        O::Rejected(R::InsufficientBalance),
                        O::Accepted,
                        O::Accepted,
                        O::Rejected(R::WrongNonce),
                    ],
                    3,
                    99,
                ),
                (vec![O::Accepted], 1, 97),
            ],
        };
        if checkpoints.len() != expected.len() {
            return Err(QualificationError::Input(
                "unexpected workload checkpoint count",
            ));
        }
        for (checkpoint, (outcomes, outputs, pool)) in checkpoints.iter().zip(expected) {
            if !checkpoint
                .receipts()
                .iter()
                .map(|r| r.outcome())
                .eq(outcomes)
                || checkpoint.accepted_outputs().count() != outputs
                || checkpoint.state().pool().atoms() != pool
            {
                return Err(QualificationError::Input(
                    "workload outcomes or accounting differ",
                ));
            }
        }
        if let Self::Payment { inputs, outputs } = self {
            let checkpoint = &checkpoints[0];
            let occurrence = &checkpoint.artifact().occurrences()[0];
            let houseki_types::TransactionEnvelope::Payment(envelope) = occurrence.envelope()
            else {
                return Err(QualificationError::Input("workload payment family differs"));
            };
            let fee = (inputs + outputs) as u128;
            let effect = checkpoint.effects()[0]
                .accepted
                .as_ref()
                .ok_or(QualificationError::Input("workload payment has no effects"))?;
            if envelope.body().inputs().input_count() != inputs
                || envelope.body().outputs().output_count() != outputs
                || envelope.body().public_fee().atoms() != fee
                || effect.before_pool.atoms() != (inputs * 100) as u128
                || effect.accounts.len() != 1
                || effect.accounts[0].before_balance.atoms() != 0
                || effect.accounts[0].after_balance.atoms() != fee
                || effect.nullifiers.len() != inputs
                || effect.appends.len() != outputs
            {
                return Err(QualificationError::Input(
                    "workload payment shape or fee differs",
                ));
            }
        }
        Ok(())
    }

    /// Resolves only the documented named scenarios and eight exact shape strings.
    pub fn parse(value: &str) -> Result<Self, QualificationError> {
        match value {
            "withdrawal" => Ok(Self::Withdrawal),
            "value-loop" => Ok(Self::ValueLoop),
            "repeated-commitments" => Ok(Self::RepeatedCommitments),
            "conflicts" => Ok(Self::Conflicts),
            "failed-early-copy" => Ok(Self::FailedEarlyCopy),
            "shared-beneficiary" => Ok(Self::SharedBeneficiary),
            "anchor-pruning" => Ok(Self::AnchorPruning),
            _ => {
                let (i, o) = value
                    .split_once('-')
                    .ok_or(QualificationError::Input("unknown workload"))?;
                let inputs = i
                    .parse()
                    .map_err(|_| QualificationError::Input("invalid input count"))?;
                let outputs = o
                    .parse()
                    .map_err(|_| QualificationError::Input("invalid output count"))?;
                if !(1..=4).contains(&inputs) || !(1..=2).contains(&outputs) {
                    return Err(QualificationError::Input("unsupported payment shape"));
                }
                Ok(Self::Payment { inputs, outputs })
            }
        }
    }

    /// Returns the stable public workload directory and report name.
    pub fn name(self) -> String {
        match self {
            Self::Payment { inputs, outputs } => format!("{inputs}-{outputs}"),
            Self::Withdrawal => "withdrawal".into(),
            Self::ValueLoop => "value-loop".into(),
            Self::RepeatedCommitments => "repeated-commitments".into(),
            Self::Conflicts => "conflicts".into(),
            Self::FailedEarlyCopy => "failed-early-copy".into(),
            Self::SharedBeneficiary => "shared-beneficiary".into(),
            Self::AnchorPruning => "anchor-pruning".into(),
        }
    }

    /// Returns all nine family workloads, four named scenarios and two boundary workloads.
    pub fn all() -> Vec<Self> {
        let mut all = vec![];
        for inputs in 1..=4 {
            for outputs in 1..=2 {
                all.push(Self::Payment { inputs, outputs });
            }
        }
        all.extend([
            Self::Withdrawal,
            Self::ValueLoop,
            Self::RepeatedCommitments,
            Self::Conflicts,
            Self::FailedEarlyCopy,
            Self::SharedBeneficiary,
            Self::AnchorPruning,
        ]);
        all
    }
}
