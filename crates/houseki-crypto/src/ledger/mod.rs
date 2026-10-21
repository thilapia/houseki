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
