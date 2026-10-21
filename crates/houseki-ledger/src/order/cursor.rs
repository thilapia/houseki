//! Persisted source position independent of transport callbacks.

use crate::{FixtureStreamId, FixtureUnitId};

/// A declared fixture stream position without evidence of source validity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SourceCursor {
    /// A source unit with a next unconsumed occurrence or one explicit empty range.
    Unit {
        /// Complete declared stream identifier.
        stream_id: FixtureStreamId,

        /// Zero based source unit ordinal.
        ordinal: u64,

        /// Complete declared unit identifier.
        unit_id: FixtureUnitId,

        /// Next unconsumed occurrence index.
        offset: u64,
    },

    /// The finite source has no successor.
    Exhausted {
        /// Complete declared stream identifier.
        stream_id: FixtureStreamId,
    },
}

impl SourceCursor {
    /// Returns the complete stream identity in either progress state.
    pub const fn stream_id(&self) -> FixtureStreamId {
        match self {
            Self::Unit { stream_id, .. } | Self::Exhausted { stream_id } => *stream_id,
        }
    }

    /// Encodes the exact 148 byte auxiliary cursor record without a trust claim.
    pub fn to_bytes(&self) -> [u8; 148] {
        let mut bytes = [0; 148];
        match self {
            Self::Unit {
                stream_id,
                ordinal,
                unit_id,
                offset,
            } => {
                bytes[..64].copy_from_slice(stream_id.as_bytes());
                bytes[68..76].copy_from_slice(&ordinal.to_le_bytes());
                bytes[76..140].copy_from_slice(unit_id.as_bytes());
                bytes[140..].copy_from_slice(&offset.to_le_bytes());
            }
            Self::Exhausted { stream_id } => {
                bytes[..64].copy_from_slice(stream_id.as_bytes());
                bytes[64..68].copy_from_slice(&1_u32.to_le_bytes());
            }
        }

        bytes
    }

    /// Decodes representation only and rejects noncanonical exhausted metadata.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, crate::OrderError> {
        let bytes: &[u8; 148] = bytes.try_into().map_err(|_| crate::OrderError::Binding)?;
        let stream_id =
            FixtureStreamId::from_bytes(bytes[..64].try_into().expect("fixed cursor width"));
        let tag = u32::from_le_bytes(bytes[64..68].try_into().expect("fixed tag width"));
        match tag {
            0 => Ok(Self::Unit {
                stream_id,
                ordinal: u64::from_le_bytes(bytes[68..76].try_into().expect("fixed ordinal width")),
                unit_id: FixtureUnitId::from_bytes(
                    bytes[76..140].try_into().expect("fixed identity width"),
                ),
                offset: u64::from_le_bytes(bytes[140..].try_into().expect("fixed offset width")),
            }),
            1 if bytes[68..].iter().all(|b| *b == 0) => Ok(Self::Exhausted { stream_id }),
            _ => Err(crate::OrderError::Binding),
        }
    }
}

/// Exact auxiliary cursor representation and malformed state tests.
#[cfg(test)]
mod tests {
    use super::*;

    /// Preserves full integer widths and rejects nonzero exhausted fields.
    #[test]
    fn cursor_encoding_is_exact() {
        let cursor = SourceCursor::Unit {
            stream_id: FixtureStreamId::from_bytes([1; 64]),
            ordinal: u64::MAX,
            unit_id: FixtureUnitId::from_bytes([2; 64]),
            offset: u64::MAX,
        };

        let bytes = cursor.to_bytes();

        assert_eq!(bytes.len(), 148);
        assert_eq!(&bytes[68..76], &u64::MAX.to_le_bytes());
        assert_eq!(SourceCursor::from_bytes(&bytes).unwrap(), cursor);

        let exhausted = SourceCursor::Exhausted {
            stream_id: FixtureStreamId::from_bytes([1; 64]),
        };

        let bytes = exhausted.to_bytes();

        assert_eq!(&bytes[64..68], &1_u32.to_le_bytes());
        assert!(bytes[68..].iter().all(|b| *b == 0));

        for length in [0, 147] {
            assert!(SourceCursor::from_bytes(&bytes[..length]).is_err());
        }

        let mut bad = bytes;
        bad[76] = 1;

        assert!(SourceCursor::from_bytes(&bad).is_err());
    }
}
