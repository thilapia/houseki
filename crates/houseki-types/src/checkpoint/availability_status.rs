//! Reported availability of identified checkpoint data.

/// A reporter's observation of availability for a specified set of data.
///
/// The containing record must identify the data being reported.
///
/// Transaction payloads and execution proof packages need separate observations because either
/// can be available without the other.
///
/// A commitment or a partial download does not establish availability of the complete data.
///
/// Availability describes the reporter's observation at a particular time.
///
/// It does not guarantee continued retention, access for other observers or network liveness.
///
/// Obtaining data also does not establish consensus finality, proof validity or successful note
/// recovery.
///
/// This public reporting value carries neither data nor evidence.
///
/// Retrieval, completeness and identity checks belong to the consumer.
///
/// Observation records, retention policies and wire tags remain separate contracts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AvailabilityStatus {
    /// The reporter has not determined whether the complete identified data is available.
    ///
    /// This does not report a failed retrieval attempt.
    Unknown,

    /// The reporter could not obtain the complete identified data at the time of the
    /// observation.
    ///
    /// Another observer or a later attempt may obtain it.
    Unavailable,

    /// The reporter has the complete identified data at the time of the observation.
    ///
    /// This does not report cryptographic verification of its contents or promise future access.
    Available,
}
