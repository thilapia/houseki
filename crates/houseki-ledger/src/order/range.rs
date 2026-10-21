//! Greedy checkpoint cuts determined only by complete unit bytes and trusted progress.

use crate::{ExecutionPolicy, OrderBinding, OrderError, SourceCursor, VerifiedOrderUnit};
use std::ops::Range;

/// Exact greedily derived source range and its authenticated continuation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ExecutionRange {
    /// Complete committed source range metadata.
    pub(crate) binding: OrderBinding,

    /// Checked host-index bounds used only after canonical arithmetic succeeds.
    pub(crate) host: Range<usize>,

    /// Complete input list bytes, including count and every record prefix.
    pub(crate) component_bytes: u64,

    /// Exact successor position to publish with the checkpoint.
    pub(crate) next_cursor: SourceCursor,
}

/// Derives one deterministic range without accepting caller-supplied cuts.
pub(crate) fn next_range(
    cursor: &SourceCursor,
    unit: &VerifiedOrderUnit,
    policy: &ExecutionPolicy,
) -> Result<ExecutionRange, OrderError> {
    let (stream, ordinal, identity, start) = match cursor {
        SourceCursor::Unit {
            stream_id,
            ordinal,
            unit_id,
            offset,
        } => (*stream_id, *ordinal, *unit_id, *offset),
        SourceCursor::Exhausted { .. } => return Err(OrderError::SourceExhausted),
    };
    if stream != unit.stream_id || ordinal != unit.ordinal || identity != unit.unit_id {
        return Err(OrderError::Binding);
    }
    let count = u64::try_from(unit.record_lengths.len()).map_err(|_| OrderError::Bound)?;
    let limits = policy.limits();
    if count > limits.unit_occurrences()
        || limits.batch_occurrences() == 0
        || limits.batch_bytes() < 8
    {
        return Err(OrderError::Bound);
    }
    let mut total = 8_u64;
    for length in &unit.record_lengths {
        let cost = 8_u64.checked_add(*length).ok_or(OrderError::Bound)?;
        if 8_u64.checked_add(cost).ok_or(OrderError::Bound)? > limits.batch_bytes() {
            return Err(OrderError::UnitInadmissible);
        }
        total = total.checked_add(cost).ok_or(OrderError::Bound)?;
    }
    if total > limits.unit_bytes() || start > count || (start == count && count != 0) {
        return Err(OrderError::Binding);
    }
    let host_start = usize::try_from(start).map_err(|_| OrderError::Bound)?;
    let mut end = start;
    let mut bytes = 8_u64;
    for length in &unit.record_lengths[host_start..] {
        let next = bytes
            .checked_add(8)
            .and_then(|b| b.checked_add(*length))
            .ok_or(OrderError::Bound)?;
        if end - start == limits.batch_occurrences() || next > limits.batch_bytes() {
            break;
        }
        bytes = next;
        end = end.checked_add(1).ok_or(OrderError::Bound)?;
    }
    let next_cursor = if end == count {
        match unit.successor {
            Some(unit_id) => SourceCursor::Unit {
                stream_id: stream,
                ordinal: ordinal.checked_add(1).ok_or(OrderError::Bound)?,
                unit_id,
                offset: 0,
            },
            None => SourceCursor::Exhausted { stream_id: stream },
        }
    } else {
        SourceCursor::Unit {
            stream_id: stream,
            ordinal,
            unit_id: identity,
            offset: end,
        }
    };
    Ok(ExecutionRange {
        binding: OrderBinding {
            stream_id: stream,
            unit_id: identity,
            start_offset: start,
            end_offset: end,
            unit_occurrence_count: count,
        },
        host: host_start..usize::try_from(end).map_err(|_| OrderError::Bound)?,
        component_bytes: bytes,
        next_cursor,
    })
}

/// Exact count, byte and continuation boundary tests.
#[cfg(all(test, feature = "experimental-profiles"))]
mod tests {
    use super::*;
    use crate::{ExecutionPolicy, FixtureStreamId, FixtureUnitId};

    /// Builds private slicing evidence with synthetic complete record lengths.
    fn sized_unit(lengths: Vec<u64>) -> VerifiedOrderUnit {
        VerifiedOrderUnit {
            stream_id: FixtureStreamId::from_bytes([1; 64]),
            unit_id: FixtureUnitId::from_bytes([2; 64]),
            previous: FixtureUnitId::from_bytes([0; 64]),
            ordinal: 0,
            successor: None,
            occurrences: vec![].into(),
            record_lengths: lengths,
            canonical: vec![].into(),
        }
    }

    /// Supplies exact declared progress for a private slicing fixture.
    fn cursor(offset: u64) -> SourceCursor {
        SourceCursor::Unit {
            stream_id: FixtureStreamId::from_bytes([1; 64]),
            unit_id: FixtureUnitId::from_bytes([2; 64]),
            ordinal: 0,
            offset,
        }
    }

    /// Applies both count limits and complete list/record prefixes at exact byte boundaries.
    #[test]
    fn range_uses_count_and_complete_byte_caps() {
        let policy = ExecutionPolicy::development().unwrap();
        let unit = sized_unit(vec![10; 65]);
        let first = next_range(&cursor(0), &unit, &policy).unwrap();
        assert_eq!(first.host, 0..64);
        assert_eq!(first.component_bytes, 1160);
        let last = next_range(&first.next_cursor, &unit, &policy).unwrap();
        assert_eq!(last.host, 64..65);
        assert!(matches!(last.next_cursor, SourceCursor::Exhausted { .. }));
        let mut policy = policy;
        policy.limits.batch_bytes = 44;
        let two = sized_unit(vec![10; 3]);
        let cut = next_range(&cursor(0), &two, &policy).unwrap();
        assert_eq!(cut.host, 0..2);
        assert_eq!(cut.component_bytes, 44);
        policy.limits.batch_bytes = 43;
        assert_eq!(next_range(&cursor(0), &two, &policy).unwrap().host, 0..1);
        let oversized = sized_unit(vec![100]);
        assert!(matches!(
            next_range(&cursor(0), &oversized, &policy),
            Err(OrderError::UnitInadmissible)
        ));
    }

    /// Rejects exhausted, complete, foreign and unrepresentable progress rather than fabricating work.
    #[test]
    fn cursor_rejects_overlap_skip_foreign_unit() {
        let policy = ExecutionPolicy::development().unwrap();
        let unit = sized_unit(vec![10; 65]);
        assert!(next_range(&cursor(65), &unit, &policy).is_err());
        assert!(next_range(&cursor(u64::MAX), &unit, &policy).is_err());
        let wrong = SourceCursor::Unit {
            stream_id: unit.stream_id,
            unit_id: unit.unit_id,
            ordinal: 1,
            offset: 0,
        };
        assert!(next_range(&wrong, &unit, &policy).is_err());
        let wrong = SourceCursor::Unit {
            stream_id: FixtureStreamId::from_bytes([9; 64]),
            unit_id: unit.unit_id,
            ordinal: 0,
            offset: 0,
        };
        assert!(next_range(&wrong, &unit, &policy).is_err());
        assert!(matches!(
            next_range(
                &SourceCursor::Exhausted {
                    stream_id: unit.stream_id
                },
                &unit,
                &policy
            ),
            Err(OrderError::SourceExhausted)
        ));
        assert_eq!(
            next_range(&cursor(32), &unit, &policy).unwrap().host,
            32..65
        );
    }

    /// An explicit empty unit advances exactly once through its authenticated successor.
    #[test]
    fn empty_unit_advances_once() {
        let policy = ExecutionPolicy::development().unwrap();
        let mut unit = sized_unit(vec![]);
        unit.successor = Some(FixtureUnitId::from_bytes([3; 64]));
        let range = next_range(&cursor(0), &unit, &policy).unwrap();
        assert_eq!(range.host, 0..0);
        assert_eq!(range.component_bytes, 8);
        assert_eq!(
            range.next_cursor,
            SourceCursor::Unit {
                stream_id: unit.stream_id,
                unit_id: unit.successor.unwrap(),
                ordinal: 1,
                offset: 0
            }
        );
        assert!(next_range(&range.next_cursor, &unit, &policy).is_err());
    }

    /// Repeated computation and different scratch allocation orders derive identical cuts.
    #[test]
    fn range_has_no_clock_dependency() {
        let policy = ExecutionPolicy::development().unwrap();
        let unit = sized_unit(vec![10; 128]);
        let first = next_range(&cursor(0), &unit, &policy).unwrap();
        for _ in 0..10 {
            assert_eq!(next_range(&cursor(0), &unit, &policy).unwrap(), first);
        }
    }
}
