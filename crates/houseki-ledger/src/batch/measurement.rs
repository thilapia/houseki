//! Operational phase timings excluded from canonical state and execution decisions.

use std::time::Duration;

/// Local preparation observations that never choose source cuts or canonical outcomes.
#[derive(Debug, Clone)]
pub struct PreparationMetrics {
    /// Independent tree/map reconstruction duration.
    pub(super) reconstruction: Duration,

    /// Ordered effects, conservation, anchor update and alignment duration.
    pub(super) execution: Duration,

    /// Complete canonical encoding and registered commitment duration.
    pub(super) commitments: Duration,

    /// Complete preparation duration before immutable candidate sealing.
    pub(super) total: Duration,
}

impl PreparationMetrics {
    /// Returns independent reconstruction time without a capacity claim.
    pub const fn reconstruction(&self) -> Duration {
        self.reconstruction
    }

    /// Returns ordered state execution and alignment time.
    pub const fn execution(&self) -> Duration {
        self.execution
    }

    /// Returns complete commitment construction time.
    pub const fn commitments(&self) -> Duration {
        self.commitments
    }

    /// Returns total local preparation time.
    pub const fn total(&self) -> Duration {
        self.total
    }
}
