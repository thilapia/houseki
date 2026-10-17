//! Complete public field emission after checked length preflight.

use super::{BodyCodecError, BodyCodecLimits};
use crate::{NoteOutput, TransactionContext};

/// Emits the complete version, operation tag and common context in canonical field order.
pub(super) fn header(bytes: &mut Vec<u8>, kind: u32, context: TransactionContext) {
    bytes.extend_from_slice(&1_u32.to_le_bytes());
    bytes.extend_from_slice(&kind.to_le_bytes());
    bytes.extend_from_slice(context.network_id().as_bytes());
    bytes.extend_from_slice(&context.protocol_version().value().to_le_bytes());
    bytes.extend_from_slice(&context.proof_profile_id().value().to_le_bytes());
    bytes.extend_from_slice(&context.fee_schedule_id().value().to_le_bytes());
    bytes.extend_from_slice(
        &context
            .validity_checkpoint_range()
            .start()
            .value()
            .to_le_bytes(),
    );
    bytes.extend_from_slice(
        &context
            .validity_checkpoint_range()
            .end()
            .value()
            .to_le_bytes(),
    );
}

/// Returns a complete output length after checking payload and wire length bounds.
pub(super) fn output_len(
    output: &NoteOutput,
    limits: BodyCodecLimits,
) -> Result<usize, BodyCodecError> {
    let length = output.envelope().payload_len();
    super::bound_payload(length, limits)?;
    u64::try_from(length).map_err(|_| BodyCodecError::LengthOverflow)?;
    1640_usize
        .checked_add(length)
        .ok_or(BodyCodecError::LengthOverflow)
}

/// Emits the complete selected commitment, encapsulation and length prefixed opaque payload.
pub(super) fn output(bytes: &mut Vec<u8>, output: &NoteOutput) -> Result<(), BodyCodecError> {
    let envelope = output.envelope();
    let length =
        u64::try_from(envelope.payload_len()).map_err(|_| BodyCodecError::LengthOverflow)?;
    bytes.extend_from_slice(output.commitment().as_bytes());
    bytes.extend_from_slice(envelope.encapsulation().as_bytes());
    bytes.extend_from_slice(&length.to_le_bytes());
    bytes.extend_from_slice(envelope.payload());
    Ok(())
}
