//! Fixed registered commitment roles for native ledger reference records.

use crate::{CryptoFramingError, domain::Domain, hash::poseidon2};

/// Commits the complete canonical reference state bytes under reference schema 1.
///
/// The caller supplies canonical bytes and separately validates their representation.
///
/// # Errors
///
/// Preserves transcript framing failures without returning a partial digest.
pub fn ledger_reference_state(canonical: &[u8]) -> Result<[u8; 64], CryptoFramingError> {
    poseidon2(
        Domain::LedgerReferenceState,
        &[&1_u32.to_le_bytes(), canonical],
    )
}

/// Commits the complete canonical execution policy bytes under reference schema 1.
///
/// The caller supplies canonical bytes and separately validates their representation.
///
/// # Errors
///
/// Preserves transcript framing failures without returning a partial digest.
pub fn ledger_execution_policy(canonical: &[u8]) -> Result<[u8; 64], CryptoFramingError> {
    poseidon2(
        Domain::LedgerExecutionPolicy,
        &[&1_u32.to_le_bytes(), canonical],
    )
}

/// Commits the complete canonical ordered occurrences bytes under reference schema 1.
///
/// The caller supplies canonical bytes and separately validates their representation.
///
/// # Errors
///
/// Preserves transcript framing failures without returning a partial digest.
pub fn ledger_ordered_occurrences(canonical: &[u8]) -> Result<[u8; 64], CryptoFramingError> {
    poseidon2(
        Domain::LedgerOrderedOccurrences,
        &[&1_u32.to_le_bytes(), canonical],
    )
}

/// Commits the complete canonical receipts bytes under reference schema 1.
///
/// The caller supplies canonical bytes and separately validates their representation.
///
/// # Errors
///
/// Preserves transcript framing failures without returning a partial digest.
pub fn ledger_receipts(canonical: &[u8]) -> Result<[u8; 64], CryptoFramingError> {
    poseidon2(Domain::LedgerReceipts, &[&1_u32.to_le_bytes(), canonical])
}

/// Commits the complete canonical public effects bytes under reference schema 1.
///
/// The caller supplies canonical bytes and separately validates their representation.
///
/// # Errors
///
/// Preserves transcript framing failures without returning a partial digest.
pub fn ledger_public_effects(canonical: &[u8]) -> Result<[u8; 64], CryptoFramingError> {
    poseidon2(
        Domain::LedgerPublicEffects,
        &[&1_u32.to_le_bytes(), canonical],
    )
}

/// Commits the complete canonical system events bytes under reference schema 1.
///
/// The caller supplies canonical bytes and separately validates their representation.
///
/// # Errors
///
/// Preserves transcript framing failures without returning a partial digest.
pub fn ledger_system_events(canonical: &[u8]) -> Result<[u8; 64], CryptoFramingError> {
    poseidon2(
        Domain::LedgerSystemEvents,
        &[&1_u32.to_le_bytes(), canonical],
    )
}

/// Commits the complete canonical execution artifact bytes under reference schema 1.
///
/// The caller supplies canonical bytes and separately validates their representation.
///
/// # Errors
///
/// Preserves transcript framing failures without returning a partial digest.
pub fn ledger_execution_artifact(canonical: &[u8]) -> Result<[u8; 64], CryptoFramingError> {
    poseidon2(
        Domain::LedgerExecutionArtifact,
        &[&1_u32.to_le_bytes(), canonical],
    )
}

/// Commits the complete canonical fixture order unit bytes under reference schema 1.
///
/// The caller supplies canonical bytes and separately validates their representation.
///
/// # Errors
///
/// Preserves transcript framing failures without returning a partial digest.
pub fn ledger_fixture_order_unit(canonical: &[u8]) -> Result<[u8; 64], CryptoFramingError> {
    poseidon2(
        Domain::LedgerFixtureOrderUnit,
        &[&1_u32.to_le_bytes(), canonical],
    )
}

/// Commits the complete canonical fixture order stream bytes under reference schema 1.
///
/// The caller supplies canonical bytes and separately validates their representation.
///
/// # Errors
///
/// Preserves transcript framing failures without returning a partial digest.
pub fn ledger_fixture_order_stream(canonical: &[u8]) -> Result<[u8; 64], CryptoFramingError> {
    poseidon2(
        Domain::LedgerFixtureOrderStream,
        &[&1_u32.to_le_bytes(), canonical],
    )
}

/// Independent ledger hash fixtures and registered domain separation.
#[cfg(test)]
mod tests {
    use super::*;

    /// Verifies all nine fixed domains against an independent integer implementation.
    #[test]
    fn ledger_domains_match_independent_vectors() {
        let actual = ledger_reference_state(include_bytes!(
            "../../../houseki-ledger/fixtures/reference-v1/snapshot.bin"
        ))
        .unwrap();
        let hex = actual
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        assert_eq!(
            hex,
            include_str!("../../../houseki-ledger/fixtures/reference-v1/snapshot.hex").trim()
        );
        let actual = ledger_execution_policy(include_bytes!(
            "../../../houseki-ledger/fixtures/reference-v1/policy.bin"
        ))
        .unwrap();
        let hex = actual
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        assert_eq!(
            hex,
            include_str!("../../../houseki-ledger/fixtures/reference-v1/policy.hex").trim()
        );
        let actual = ledger_ordered_occurrences(include_bytes!(
            "../../../houseki-ledger/fixtures/reference-v1/occurrences.bin"
        ))
        .unwrap();
        let hex = actual
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        assert_eq!(
            hex,
            include_str!("../../../houseki-ledger/fixtures/reference-v1/occurrences.hex").trim()
        );
        let actual = ledger_receipts(include_bytes!(
            "../../../houseki-ledger/fixtures/reference-v1/receipts.bin"
        ))
        .unwrap();
        let hex = actual
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        assert_eq!(
            hex,
            include_str!("../../../houseki-ledger/fixtures/reference-v1/receipts.hex").trim()
        );
        let actual = ledger_public_effects(include_bytes!(
            "../../../houseki-ledger/fixtures/reference-v1/effects.bin"
        ))
        .unwrap();
        let hex = actual
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        assert_eq!(
            hex,
            include_str!("../../../houseki-ledger/fixtures/reference-v1/effects.hex").trim()
        );
        let actual = ledger_system_events(include_bytes!(
            "../../../houseki-ledger/fixtures/reference-v1/system_events.bin"
        ))
        .unwrap();
        let hex = actual
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        assert_eq!(
            hex,
            include_str!("../../../houseki-ledger/fixtures/reference-v1/system_events.hex").trim()
        );
        let actual = ledger_execution_artifact(include_bytes!(
            "../../../houseki-ledger/fixtures/reference-v1/artifact_header.bin"
        ))
        .unwrap();
        let hex = actual
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        assert_eq!(
            hex,
            include_str!("../../../houseki-ledger/fixtures/reference-v1/artifact_header.hex")
                .trim()
        );
        let actual = ledger_fixture_order_unit(include_bytes!(
            "../../../houseki-ledger/fixtures/reference-v1/fixture_unit.bin"
        ))
        .unwrap();
        let hex = actual
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        assert_eq!(
            hex,
            include_str!("../../../houseki-ledger/fixtures/reference-v1/fixture_unit.hex").trim()
        );
        let actual = ledger_fixture_order_stream(include_bytes!(
            "../../../houseki-ledger/fixtures/reference-v1/fixture_stream.bin"
        ))
        .unwrap();
        let hex = actual
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        assert_eq!(
            hex,
            include_str!("../../../houseki-ledger/fixtures/reference-v1/fixture_stream.hex").trim()
        );
    }
}
