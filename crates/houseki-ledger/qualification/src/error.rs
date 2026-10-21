//! Qualification boundary errors carry only public fixture diagnostics.

use std::{error::Error, fmt};

/// A public fixture workload could not be generated or independently verified.
#[derive(Debug)]
pub enum QualificationError {
    /// A command, workload declaration or observed public result violates qualification requirements.
    Input(
        /// Fixed public input diagnostic.
        &'static str,
    ),

    /// An underlying bounded native proof, crypto, ledger or filesystem operation failed.
    Native(
        /// Original public diagnostic without wallet witnesses or private traces.
        Box<dyn Error>,
    ),
}

impl fmt::Display for QualificationError {
    /// Formats public operational diagnostics without private fixture owners.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Input(message) => f.write_str(message),
            Self::Native(source) => fmt::Display::fmt(source, f),
        }
    }
}

impl Error for QualificationError {
    /// Retains the original public failure when an underlying native operation failed.
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Input(_) => None,
            Self::Native(source) => Some(source.as_ref()),
        }
    }
}
