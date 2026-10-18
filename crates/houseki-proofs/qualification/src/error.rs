//! Public qualification failures without retaining protected inputs.

use std::{error, fmt, io};

/// An invalid request, failed public operation or unavailable artifact.
#[derive(Debug)]
pub enum Error {
    /// A request does not match the fixed qualification contract.
    Input(&'static str),

    /// A public artifact could not be read or written.
    Io(io::Error),

    /// A public library operation failed with a nonsecret diagnostic.
    Operation(String),
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Input(message) => formatter.write_str(message),
            Self::Io(error) => error.fmt(formatter),
            Self::Operation(message) => formatter.write_str(message),
        }
    }
}

impl error::Error for Error {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}
