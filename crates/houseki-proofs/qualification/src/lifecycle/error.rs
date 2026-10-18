//! Lifecycle admission failures before any worker retains a private owner.

use std::{error::Error, fmt};

/// A request cannot begin under the current foreground or worker state.
#[derive(Debug, Eq, PartialEq)]
pub enum LifecycleError {
    /// The application has not entered the foreground.
    Background,

    /// The previous worker has not completed cleanup.
    Busy,

    /// A panicking callback poisoned the shared state, requiring a process restart.
    Poisoned,

    /// The monotonic attempt identifier cannot advance.
    Exhausted,
}

impl fmt::Display for LifecycleError {
    /// Formats only the public admission state.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Background => "application is in the background",
            Self::Busy => "previous worker still owns admission",
            Self::Poisoned => "lifecycle state requires a process restart",
            Self::Exhausted => "attempt identifier exhausted",
        })
    }
}

impl Error for LifecycleError {}
