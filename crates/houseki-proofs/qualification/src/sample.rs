//! Nonsecret observations with explicit public API measurement boundaries.

use crate::Workload;

/// Timings and encoded sizes for one successful public verification or proving attempt.
pub struct Sample {
    /// Workload selected before any input bytes were inspected.
    pub(crate) workload: Workload,

    /// Fresh synthetic fixture preparation, absent from verifier-only observations.
    pub(crate) fixture_us: Option<u128>,

    /// Context, witness preparation and the complete encoded proving API result.
    pub(crate) prove_api_us: Option<u128>,

    /// Public body serialization performed after successful proving.
    pub(crate) body_encode_us: Option<u128>,

    /// Canonical body and expected context decoding, excluding file transport.
    pub(crate) decode_us: u128,

    /// Complete public verifier call, including internal proof decoding.
    pub(crate) verify_api_us: u128,

    /// Complete canonical public body length.
    pub(crate) body_bytes: usize,

    /// Complete encoded proof length.
    pub(crate) proof_bytes: usize,
}

impl Sample {
    /// Serializes only fixed labels, public sizes and integer durations as one JSON line.
    pub fn json(&self) -> String {
        format!(
            "{{\"schema\":1,\"workload\":\"{}\",\"fixture_us\":{},\"prove_api_us\":{},\"body_encode_us\":{},\"decode_us\":{},\"verify_api_us\":{},\"body_bytes\":{},\"proof_bytes\":{}}}",
            self.workload.label(),
            optional(self.fixture_us),
            optional(self.prove_api_us),
            optional(self.body_encode_us),
            self.decode_us,
            self.verify_api_us,
            self.body_bytes,
            self.proof_bytes
        )
    }
}

/// Distinguishes an unmeasured phase from a measured zero duration.
fn optional(value: Option<u128>) -> String {
    value.map_or_else(|| "null".to_owned(), |value| value.to_string())
}
