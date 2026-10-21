//! Canonical public reference records and distinct commitment identities.

mod accepted_effect;
mod account_effect;
mod append;
mod codec;
mod effect;
mod error;
mod execution_artifact;
mod fixture_stream;
mod fixture_unit;
mod header;
mod identifier;
mod order_binding;
mod snapshot_record;

pub use accepted_effect::AcceptedEffect;
pub use account_effect::AccountEffect;
pub use append::NoteAppend;
pub use codec::{
    DecodeLimits, decode_artifact_header, decode_effects, decode_fixture_stream,
    decode_fixture_unit, decode_occurrences, decode_policy, decode_receipts, decode_snapshot,
    encode_artifact_header, encode_effects, encode_fixture_stream, encode_fixture_unit,
    encode_occurrences, encode_policy, encode_receipts, encode_snapshot,
};
pub use effect::EffectRecord;
pub use error::ArtifactError;
pub use execution_artifact::ExecutionArtifact;
pub use fixture_stream::FixtureStreamRecord;
pub use fixture_unit::FixtureUnitRecord;
pub use header::ArtifactHeader;
pub use identifier::{
    ExecutionArtifactId, ExecutionPolicyId, FixtureStreamId, FixtureUnitId, StateCommitment,
};
pub use order_binding::OrderBinding;
pub use snapshot_record::SnapshotRecord;

pub(crate) use codec::{decode_archive, encode_archive};
