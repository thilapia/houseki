//! Complete V1 record composition over existing transaction body codecs.

use super::{DecodeLimits, reader::Reader, writer::Writer};
use crate::{
    AcceptedEffect, AccountEffect, AnchorRecord, ArtifactError, ArtifactHeader, CommitteeEntry,
    EffectRecord, ExecutionArtifactId, ExecutionLimits, ExecutionPolicy, ExecutionPolicyId,
    FixtureStreamId, FixtureStreamRecord, FixtureUnitId, FixtureUnitRecord, NoteAppend,
    OrderBinding, SnapshotRecord, StateCommitment,
};
use houseki_types::{
    Amount, BodyCodecLimits, CheckpointSequence, CommitteeContext, CommitteeId,
    EncodedMlDsa87PublicKey, EncodedMlDsa87Signature, EncodedTransactionProof, Epoch,
    ExecutionOutcome, ExecutionRejectionReason, FeeScheduleId, NetworkId, NoteCommitment,
    NoteCount, NotePosition, NoteRoot, NoteTreeAnchor, Nullifier, Occurrence, PaymentBody,
    PaymentCountLimits, PaymentEnvelope, ProofProfileId, ProtocolVersion, Receipt, RewardAccount,
    RewardAccountId, RewardWithdrawalBody, RewardWithdrawalEnvelope, TransactionEnvelope,
    ValidatorId, VertexId, WithdrawalNonce,
};

/// Selects the existing exact wallet body codec bounds.
fn body_limits() -> BodyCodecLimits {
    BodyCodecLimits::new(
        PaymentCountLimits::new(4, 2).expect("positive counts"),
        4096,
        16384,
    )
}

/// Decodes a bounded amount without modular reduction.
fn amount(reader: &mut Reader<'_>) -> Result<Amount, ArtifactError> {
    Amount::from_atoms(reader.u128()?).map_err(|_| ArtifactError::Invalid)
}

/// Copies bounded bytes only after reserving their complete size.
fn copied(bytes: &[u8]) -> Result<Vec<u8>, ArtifactError> {
    let mut value = Vec::new();
    value
        .try_reserve_exact(bytes.len())
        .map_err(|_| ArtifactError::Allocation)?;
    value.extend_from_slice(bytes);
    Ok(value)
}

/// Emits complete envelope bytes including proof and required signature.
fn encode_envelope(value: &TransactionEnvelope) -> Result<Vec<u8>, ArtifactError> {
    let mut w = Writer::new();
    match value {
        TransactionEnvelope::Payment(e) => {
            w.u32(1)?;
            w.blob(&e.body().to_bytes(body_limits())?)?;
            if e.proof().byte_len() > 2097152 {
                return Err(ArtifactError::Bound);
            }
            w.blob(e.proof().as_bytes())?;
            w.blob(&[])?;
        }
        TransactionEnvelope::RewardWithdrawal(e) => {
            w.u32(2)?;
            w.blob(&e.body().to_bytes(body_limits())?)?;
            if e.proof().byte_len() > 2097152 {
                return Err(ArtifactError::Bound);
            }
            w.blob(e.proof().as_bytes())?;
            w.blob(e.signature().as_bytes())?;
        }
    }
    Ok(w.finish())
}

/// Decodes a complete unverified envelope under native body limits.
fn decode_envelope(
    bytes: &[u8],
    limits: DecodeLimits,
) -> Result<TransactionEnvelope, ArtifactError> {
    let mut r = Reader::new(bytes, limits)?;
    let kind = r.u32()?;
    let body = r.blob()?;
    let proof = r.blob()?;
    let signature = r.blob()?;
    r.finish()?;
    if proof.len() > 2097152 {
        return Err(ArtifactError::Bound);
    }
    let proof = EncodedTransactionProof::new(copied(proof)?, 2097152)
        .map_err(|_| ArtifactError::Invalid)?;
    match kind {
        1 if signature.is_empty() => {
            Ok(PaymentEnvelope::new(PaymentBody::from_bytes(body, body_limits())?, proof).into())
        }
        2 => Ok(RewardWithdrawalEnvelope::new(
            RewardWithdrawalBody::from_bytes(body, body_limits())?,
            proof,
            EncodedMlDsa87Signature::try_from(signature).map_err(|_| ArtifactError::Invalid)?,
        )
        .into()),
        _ => Err(ArtifactError::Invalid),
    }
}

/// Emits the fixed 208 bytes of origin metadata before its complete envelope blob.
fn encode_occurrence(value: &Occurrence) -> Result<Vec<u8>, ArtifactError> {
    let mut w = Writer::new();
    w.raw(value.vertex_id().as_bytes())?;
    w.raw(value.vertex_author().as_bytes())?;
    w.u64(value.committee_context().epoch().value())?;
    w.raw(value.committee_context().committee_id().as_bytes())?;
    w.u64(value.transaction_index())?;
    w.blob(&encode_envelope(value.envelope())?)?;
    Ok(w.finish())
}

/// Decodes origin metadata without authenticating its binding.
fn decode_occurrence(bytes: &[u8], limits: DecodeLimits) -> Result<Occurrence, ArtifactError> {
    let mut r = Reader::new(bytes, limits)?;
    let vertex = VertexId::from_bytes(r.fixed()?);
    let author = ValidatorId::from_bytes(r.fixed()?);
    let epoch = Epoch::new(r.u64()?);
    let committee = CommitteeId::from_bytes(r.fixed()?);
    let index = r.u64()?;
    let envelope = decode_envelope(r.blob()?, limits)?;
    r.finish()?;
    Ok(Occurrence::new(
        vertex,
        author,
        CommitteeContext::new(epoch, committee),
        index,
        envelope,
    ))
}

/// Encodes the complete length-prefixed occurrence list used for component accounting.
pub fn encode_occurrences(values: &[Occurrence]) -> Result<Vec<u8>, ArtifactError> {
    if values.len() > 128 {
        return Err(ArtifactError::Bound);
    }
    let mut w = Writer::new();
    w.list(values, encode_occurrence)?;
    Ok(w.finish())
}

/// Decodes a complete bounded occurrence list without establishing source validity.
pub fn decode_occurrences(
    bytes: &[u8],
    limits: DecodeLimits,
) -> Result<Vec<Occurrence>, ArtifactError> {
    let mut r = Reader::new(bytes, limits)?;
    let values = r.list(128, |b| decode_occurrence(b, limits))?;
    r.finish()?;
    Ok(values)
}

/// Assigns schema codes independently of enum declaration or rejection precedence.
fn reason_code(reason: ExecutionRejectionReason) -> u32 {
    match reason {
        ExecutionRejectionReason::UnsupportedContext => 1,
        ExecutionRejectionReason::OutsideValidityRange => 2,
        ExecutionRejectionReason::DisallowedAnchor => 3,
        ExecutionRejectionReason::WrongFeeSchedule => 4,
        ExecutionRejectionReason::WrongFee => 5,
        ExecutionRejectionReason::SpentNullifier => 6,
        ExecutionRejectionReason::InsufficientBalance => 7,
        ExecutionRejectionReason::WrongNonce => 8,
        ExecutionRejectionReason::NonceExhausted => 9,
        ExecutionRejectionReason::StateBoundsExceeded => 10,
    }
}

/// Resolves one explicit schema rejection code.
fn reason(code: u32) -> Result<ExecutionRejectionReason, ArtifactError> {
    match code {
        1 => Ok(ExecutionRejectionReason::UnsupportedContext),
        2 => Ok(ExecutionRejectionReason::OutsideValidityRange),
        3 => Ok(ExecutionRejectionReason::DisallowedAnchor),
        4 => Ok(ExecutionRejectionReason::WrongFeeSchedule),
        5 => Ok(ExecutionRejectionReason::WrongFee),
        6 => Ok(ExecutionRejectionReason::SpentNullifier),
        7 => Ok(ExecutionRejectionReason::InsufficientBalance),
        8 => Ok(ExecutionRejectionReason::WrongNonce),
        9 => Ok(ExecutionRejectionReason::NonceExhausted),
        10 => Ok(ExecutionRejectionReason::StateBoundsExceeded),
        _ => Err(ArtifactError::Invalid),
    }
}

/// Encodes one reported receipt with an explicit outcome and reason pair.
fn encode_receipt(value: &Receipt) -> Result<Vec<u8>, ArtifactError> {
    let mut w = Writer::new();
    w.raw(value.vertex_id().as_bytes())?;
    w.u64(value.transaction_index())?;
    match value.outcome() {
        ExecutionOutcome::Accepted => {
            w.u32(1)?;
            w.u32(0)?
        }
        ExecutionOutcome::Rejected(r) => {
            w.u32(2)?;
            w.u32(reason_code(r))?
        }
    }
    Ok(w.finish())
}

/// Decodes a receipt, rejecting impossible accepted reason pairs.
pub(super) fn decode_receipt(bytes: &[u8], limits: DecodeLimits) -> Result<Receipt, ArtifactError> {
    let mut r = Reader::new(bytes, limits)?;
    let vertex = VertexId::from_bytes(r.fixed()?);
    let index = r.u64()?;
    let outcome = match (r.u32()?, r.u32()?) {
        (1, 0) => ExecutionOutcome::Accepted,
        (2, code) => ExecutionOutcome::Rejected(reason(code)?),
        _ => return Err(ArtifactError::Invalid),
    };
    r.finish()?;
    Ok(Receipt::new(vertex, index, outcome))
}

/// Encodes every occurrence receipt in execution order.
pub fn encode_receipts(values: &[Receipt]) -> Result<Vec<u8>, ArtifactError> {
    if values.len() > 64 {
        return Err(ArtifactError::Bound);
    }
    let mut w = Writer::new();
    w.list(values, encode_receipt)?;
    Ok(w.finish())
}

/// Decodes bounded receipt representations without an acceptance claim.
pub fn decode_receipts(bytes: &[u8], limits: DecodeLimits) -> Result<Vec<Receipt>, ArtifactError> {
    let mut r = Reader::new(bytes, limits)?;
    let values = r.list(64, |b| decode_receipt(b, limits))?;
    r.finish()?;
    Ok(values)
}

/// Sorts complete keys while rejecting duplicate map entries before encoding.
fn sorted<T>(values: &[T], key: impl Fn(&T) -> [u8; 64]) -> Result<Vec<&T>, ArtifactError> {
    let mut refs = Vec::new();
    refs.try_reserve_exact(values.len())
        .map_err(|_| ArtifactError::Allocation)?;
    refs.extend(values);
    refs.sort_unstable_by_key(|v| key(v));
    if refs.windows(2).any(|v| key(v[0]) == key(v[1])) {
        return Err(ArtifactError::Invalid);
    }
    Ok(refs)
}

/// Encodes a complete registered account record.
fn encode_account(value: &(RewardAccountId, RewardAccount)) -> Result<Vec<u8>, ArtifactError> {
    let mut w = Writer::new();
    w.raw(value.0.as_bytes())?;
    w.raw(value.1.withdrawal_authority().as_bytes())?;
    w.u128(value.1.balance().atoms())?;
    w.u64(value.1.next_nonce().value())?;
    Ok(w.finish())
}

/// Decodes account representation without registering its authority.
fn decode_account(
    bytes: &[u8],
    limits: DecodeLimits,
) -> Result<(RewardAccountId, RewardAccount), ArtifactError> {
    let mut r = Reader::new(bytes, limits)?;
    let id = RewardAccountId::from_bytes(r.fixed()?);
    let key = EncodedMlDsa87PublicKey::from_bytes(r.fixed()?);
    let balance = amount(&mut r)?;
    let nonce = WithdrawalNonce::new(r.u64()?);
    r.finish()?;
    Ok((id, RewardAccount::new(key, balance, nonce)))
}

/// Encodes an ordered canonical anchor descriptor.
pub(super) fn encode_anchor(value: &AnchorRecord) -> Result<Vec<u8>, ArtifactError> {
    let mut w = Writer::new();
    let a = value.anchor();
    w.u64(value.sequence().value())?;
    w.raw(a.network_id().as_bytes())?;
    w.u128(a.count().value())?;
    w.raw(a.root().as_bytes())?;
    Ok(w.finish())
}

/// Decodes complete anchor metadata without authenticating it.
pub(super) fn decode_anchor(
    bytes: &[u8],
    limits: DecodeLimits,
) -> Result<AnchorRecord, ArtifactError> {
    let mut r = Reader::new(bytes, limits)?;
    let seq = CheckpointSequence::new(r.u64()?);
    let network = NetworkId::from_bytes(r.fixed()?);
    let count = NoteCount::new(r.u128()?).map_err(|_| ArtifactError::Invalid)?;
    let root = NoteRoot::from_bytes(r.fixed()?);
    r.finish()?;
    Ok(AnchorRecord::new(
        seq,
        NoteTreeAnchor::new(network, count, root),
    ))
}

/// Encodes a complete fixture committee registration.
fn encode_committee(value: &CommitteeEntry) -> Result<Vec<u8>, ArtifactError> {
    if value.weight() == 0 || value.key_descriptor().len() > 16384 {
        return Err(ArtifactError::Invalid);
    }
    let mut w = Writer::new();
    w.raw(value.validator().as_bytes())?;
    w.u128(value.weight())?;
    w.raw(value.reward_account().as_bytes())?;
    w.blob(value.key_descriptor())?;
    Ok(w.finish())
}

/// Decodes bounded opaque registration data without verifying consensus keys.
fn decode_committee(bytes: &[u8], limits: DecodeLimits) -> Result<CommitteeEntry, ArtifactError> {
    let mut r = Reader::new(bytes, limits)?;
    let validator = ValidatorId::from_bytes(r.fixed()?);
    let weight = r.u128()?;
    let account = RewardAccountId::from_bytes(r.fixed()?);
    let key = r.blob()?;
    if key.len() > 16384 || weight == 0 {
        return Err(ArtifactError::Invalid);
    }
    let value = CommitteeEntry::new(validator, weight, account, copied(key)?);
    r.finish()?;
    Ok(value)
}

/// Encodes every policy field in the governing schema order.
pub fn encode_policy(value: &ExecutionPolicy) -> Result<Vec<u8>, ArtifactError> {
    value.validate()?;
    let mut w = Writer::new();
    w.u32(value.protocol().value())?;
    w.list(value.payment_profiles(), |p| {
        Ok(p.value().to_le_bytes().to_vec())
    })?;
    w.list(value.withdrawal_profiles(), |p| {
        Ok(p.value().to_le_bytes().to_vec())
    })?;
    w.u32(value.fee_schedule().value())?;
    w.u128(value.payment_base_fee().atoms())?;
    w.u128(value.per_input_fee().atoms())?;
    w.u128(value.per_output_fee().atoms())?;
    w.u128(value.withdrawal_fee().atoms())?;
    w.u64(value.limits().body_bytes())?;
    w.u64(value.limits().proof_bytes())?;
    w.u64(value.limits().output_payload_bytes())?;
    w.u64(value.limits().batch_occurrences())?;
    w.u64(value.limits().batch_bytes())?;
    w.u64(value.limits().fixture_units())?;
    w.u64(value.limits().unit_occurrences())?;
    w.u64(value.limits().unit_bytes())?;
    w.u64(value.limits().note_leaves())?;
    w.u64(value.limits().spent_markers())?;
    w.u64(value.limits().accounts())?;
    w.u64(value.limits().validators())?;
    w.u64(value.limits().key_descriptor_bytes())?;
    w.u64(value.limits().anchor_window())?;
    w.u64(value.limits().anchor_retention())?;
    w.u32(value.body_codec_version())?;
    w.u32(value.state_scheme())?;
    w.u32(value.artifact_schema())?;
    Ok(w.finish())
}

/// Decodes a V1 policy without changing proof-registry recognition or admission.
pub fn decode_policy(bytes: &[u8], limits: DecodeLimits) -> Result<ExecutionPolicy, ArtifactError> {
    let mut r = Reader::new(bytes, limits)?;
    let protocol = ProtocolVersion::new(r.u32()?);
    let profile = |b: &[u8]| {
        let mut p = Reader::new(b, limits)?;
        let v = ProofProfileId::new(p.u32()?);
        p.finish()?;
        Ok(v)
    };
    let payment_profiles = r.list(1, profile)?;
    let withdrawal_profiles = r.list(1, profile)?;
    if protocol.value() != 1
        || payment_profiles.iter().any(|p| p.value() != 0xffff0008)
        || withdrawal_profiles.iter().any(|p| p.value() != 0xffff0007)
    {
        return Err(ArtifactError::Invalid);
    }
    if !cfg!(feature = "experimental-profiles")
        && (!payment_profiles.is_empty() || !withdrawal_profiles.is_empty())
    {
        return Err(ArtifactError::Invalid);
    }
    let fee_schedule = FeeScheduleId::new(r.u32()?);
    let payment_base_fee = amount(&mut r)?;
    let per_input_fee = amount(&mut r)?;
    let per_output_fee = amount(&mut r)?;
    let withdrawal_fee = amount(&mut r)?;
    let resource = ExecutionLimits {
        body_bytes: r.u64()?,
        proof_bytes: r.u64()?,
        output_payload_bytes: r.u64()?,
        batch_occurrences: r.u64()?,
        batch_bytes: r.u64()?,
        fixture_units: r.u64()?,
        unit_occurrences: r.u64()?,
        unit_bytes: r.u64()?,
        note_leaves: r.u64()?,
        spent_markers: r.u64()?,
        accounts: r.u64()?,
        validators: r.u64()?,
        key_descriptor_bytes: r.u64()?,
        anchor_window: r.u64()?,
        anchor_retention: r.u64()?,
    };
    if (r.u32()?, r.u32()?, r.u32()?) != (1, 1, 1) {
        return Err(ArtifactError::Invalid);
    }
    r.finish()?;
    let value = ExecutionPolicy {
        protocol,
        payment_profiles,
        withdrawal_profiles,
        fee_schedule,
        payment_base_fee,
        per_input_fee,
        per_output_fee,
        withdrawal_fee,
        limits: resource,
    };
    value.validate()?;
    if encode_policy(&value)? != bytes {
        return Err(ArtifactError::Invalid);
    }
    Ok(value)
}

/// Encodes the complete flat logical state record with canonical full-key sorting.
pub fn encode_snapshot(value: &SnapshotRecord) -> Result<Vec<u8>, ArtifactError> {
    if value.spent.len() > 4096
        || value.accounts.len() > 64
        || value.anchors.len() > 64
        || value.committee.len() > 64
        || value.note_anchor.network_id() != value.network
    {
        return Err(ArtifactError::Bound);
    }
    let mut w = Writer::new();
    w.raw(value.network.as_bytes())?;
    w.raw(value.note_anchor.root().as_bytes())?;
    w.u128(value.note_anchor.count().value())?;
    w.list(&sorted(&value.spent, |v| v.into_bytes())?, |v| {
        Ok(v.as_bytes().to_vec())
    })?;
    w.list(&sorted(&value.accounts, |v| v.0.into_bytes())?, |v| {
        encode_account(v)
    })?;
    w.list(&value.anchors, encode_anchor)?;
    w.blob(&encode_policy(&value.policy)?)?;
    w.u64(value.committee_context.epoch().value())?;
    w.raw(value.committee_context.committee_id().as_bytes())?;
    w.list(
        &sorted(&value.committee, |v| v.validator().into_bytes())?,
        |v| encode_committee(v),
    )?;
    w.u128(value.pool.atoms())?;
    w.u128(value.issued.atoms())?;
    Ok(w.finish())
}

/// Decodes canonical snapshot fields without reconstructing a trusted logical state.
pub fn decode_snapshot(
    bytes: &[u8],
    limits: DecodeLimits,
) -> Result<SnapshotRecord, ArtifactError> {
    let mut r = Reader::new(bytes, limits)?;
    let network = NetworkId::from_bytes(r.fixed()?);
    let root = NoteRoot::from_bytes(r.fixed()?);
    let count = NoteCount::new(r.u128()?).map_err(|_| ArtifactError::Invalid)?;
    let spent = r.list(4096, |b| {
        let mut r = Reader::new(b, limits)?;
        let v = Nullifier::from_bytes(r.fixed()?);
        r.finish()?;
        Ok(v)
    })?;
    let accounts = r.list(64, |b| decode_account(b, limits))?;
    let anchors = r.list(64, |b| decode_anchor(b, limits))?;
    let policy = decode_policy(r.blob()?, limits)?;
    let epoch = Epoch::new(r.u64()?);
    let committee_id = CommitteeId::from_bytes(r.fixed()?);
    let committee = r.list(64, |b| decode_committee(b, limits))?;
    let pool = amount(&mut r)?;
    let issued = amount(&mut r)?;
    r.finish()?;
    let value = SnapshotRecord {
        network,
        note_anchor: NoteTreeAnchor::new(network, count, root),
        spent,
        accounts,
        anchors,
        policy,
        committee_context: CommitteeContext::new(epoch, committee_id),
        committee,
        pool,
        issued,
    };
    if encode_snapshot(&value)? != bytes {
        return Err(ArtifactError::Invalid);
    }
    Ok(value)
}

/// Encodes a complete coalesced account before/after record.
fn encode_account_effect(v: &AccountEffect) -> Result<Vec<u8>, ArtifactError> {
    let mut w = Writer::new();
    w.raw(v.account_id.as_bytes())?;
    w.u128(v.before_balance.atoms())?;
    w.u64(v.before_nonce.value())?;
    w.u128(v.after_balance.atoms())?;
    w.u64(v.after_nonce.value())?;
    Ok(w.finish())
}

/// Decodes full-width account effects without authorizing their application.
fn decode_account_effect(b: &[u8], l: DecodeLimits) -> Result<AccountEffect, ArtifactError> {
    let mut r = Reader::new(b, l)?;
    let v = AccountEffect {
        account_id: RewardAccountId::from_bytes(r.fixed()?),
        before_balance: amount(&mut r)?,
        before_nonce: WithdrawalNonce::new(r.u64()?),
        after_balance: amount(&mut r)?,
        after_nonce: WithdrawalNonce::new(r.u64()?),
    };
    r.finish()?;
    Ok(v)
}

/// Encodes one rejection or complete accepted effect payload.
fn encode_effect(v: &EffectRecord) -> Result<Vec<u8>, ArtifactError> {
    let mut w = Writer::new();
    w.raw(v.vertex_id.as_bytes())?;
    w.u64(v.transaction_index)?;
    if let Some(a) = &v.accepted {
        if a.nullifiers.len() > 4 || a.appends.len() > 2 || a.accounts.len() > 2 {
            return Err(ArtifactError::Bound);
        }
        let mut p = Writer::new();
        p.list(&a.nullifiers, |n| Ok(n.as_bytes().to_vec()))?;
        p.list(&a.appends, |a| {
            let mut w = Writer::new();
            w.u64(a.position.value())?;
            w.raw(a.commitment.as_bytes())?;
            Ok(w.finish())
        })?;
        p.list(&sorted(&a.accounts, |a| a.account_id.into_bytes())?, |v| {
            encode_account_effect(v)
        })?;
        p.u128(a.before_pool.atoms())?;
        p.u128(a.after_pool.atoms())?;
        w.u32(1)?;
        w.blob(&p.finish())?;
    } else {
        w.u32(0)?;
        w.blob(&[])?
    }
    Ok(w.finish())
}

/// Decodes complete effect records while checking canonical sorted account entries.
pub(super) fn decode_effect(b: &[u8], l: DecodeLimits) -> Result<EffectRecord, ArtifactError> {
    let mut r = Reader::new(b, l)?;
    let vertex_id = VertexId::from_bytes(r.fixed()?);
    let transaction_index = r.u64()?;
    let tag = r.u32()?;
    let payload = r.blob()?;
    r.finish()?;
    let accepted = match tag {
        0 if payload.is_empty() => None,
        1 => {
            let mut p = Reader::new(payload, l)?;
            let nullifiers = p.list(4, |b| {
                let mut r = Reader::new(b, l)?;
                let v = Nullifier::from_bytes(r.fixed()?);
                r.finish()?;
                Ok(v)
            })?;
            let appends = p.list(2, |b| {
                let mut r = Reader::new(b, l)?;
                let a = NoteAppend {
                    position: NotePosition::new(r.u64()?),
                    commitment: NoteCommitment::from_bytes(r.fixed()?),
                };
                r.finish()?;
                Ok(a)
            })?;
            let accounts = p.list(2, |b| decode_account_effect(b, l))?;
            let before_pool = amount(&mut p)?;
            let after_pool = amount(&mut p)?;
            p.finish()?;
            Some(AcceptedEffect {
                nullifiers,
                appends,
                accounts,
                before_pool,
                after_pool,
            })
        }
        _ => return Err(ArtifactError::Invalid),
    };
    let v = EffectRecord {
        vertex_id,
        transaction_index,
        accepted,
    };
    if encode_effect(&v)? != b {
        return Err(ArtifactError::Invalid);
    }
    Ok(v)
}

/// Encodes aligned public effect records in occurrence order.
pub fn encode_effects(values: &[EffectRecord]) -> Result<Vec<u8>, ArtifactError> {
    if values.len() > 64 {
        return Err(ArtifactError::Bound);
    }
    let mut w = Writer::new();
    w.list(values, encode_effect)?;
    Ok(w.finish())
}

/// Decodes bounded effect representations without establishing their execution.
pub fn decode_effects(b: &[u8], l: DecodeLimits) -> Result<Vec<EffectRecord>, ArtifactError> {
    let mut r = Reader::new(b, l)?;
    let v = r.list(64, |b| decode_effect(b, l))?;
    r.finish()?;
    Ok(v)
}

/// Checks exact order-range arithmetic without authenticating the source.
fn check_order(v: &OrderBinding) -> Result<(), ArtifactError> {
    if v.start_offset > v.end_offset
        || v.end_offset > v.unit_occurrence_count
        || v.unit_occurrence_count > 128
        || v.end_offset - v.start_offset > 64
    {
        return Err(ArtifactError::Invalid);
    }
    Ok(())
}

/// Encodes the complete source range binding.
fn encode_order(v: &OrderBinding) -> Result<Vec<u8>, ArtifactError> {
    check_order(v)?;
    let mut w = Writer::new();
    w.raw(v.stream_id.as_bytes())?;
    w.raw(v.unit_id.as_bytes())?;
    w.u64(v.start_offset)?;
    w.u64(v.end_offset)?;
    w.u64(v.unit_occurrence_count)?;
    Ok(w.finish())
}

/// Decodes range representation before source verification.
fn decode_order(b: &[u8], l: DecodeLimits) -> Result<OrderBinding, ArtifactError> {
    let mut r = Reader::new(b, l)?;
    let v = OrderBinding {
        stream_id: FixtureStreamId::from_bytes(r.fixed()?),
        unit_id: FixtureUnitId::from_bytes(r.fixed()?),
        start_offset: r.u64()?,
        end_offset: r.u64()?,
        unit_occurrence_count: r.u64()?,
    };
    r.finish()?;
    check_order(&v)?;
    Ok(v)
}

/// Encodes every artifact header field in the governing acyclic order.
pub fn encode_artifact_header(v: &ArtifactHeader) -> Result<Vec<u8>, ArtifactError> {
    check_order(&v.order)?;
    if v.schema != 1 || v.occurrence_count != v.order.end_offset - v.order.start_offset {
        return Err(ArtifactError::Invalid);
    }
    let mut w = Writer::new();
    w.u32(v.schema)?;
    w.raw(v.policy_id.as_bytes())?;
    w.raw(v.network.as_bytes())?;
    w.u64(v.sequence.value())?;
    w.u64(v.committee_context.epoch().value())?;
    w.raw(v.committee_context.committee_id().as_bytes())?;
    w.raw(v.parent_artifact_id.as_bytes())?;
    w.raw(v.pre_state.as_bytes())?;
    w.raw(v.post_state.as_bytes())?;
    w.blob(&encode_order(&v.order)?)?;
    w.raw(&v.occurrences_root)?;
    w.u64(v.occurrence_count)?;
    w.raw(&v.receipts_root)?;
    w.raw(&v.effects_root)?;
    w.raw(&v.system_events_root)?;
    Ok(w.finish())
}

/// Decodes a complete header without certifying its referenced roots.
pub fn decode_artifact_header(b: &[u8], l: DecodeLimits) -> Result<ArtifactHeader, ArtifactError> {
    let mut r = Reader::new(b, l)?;
    let v = ArtifactHeader {
        schema: r.u32()?,
        policy_id: ExecutionPolicyId::from_bytes(r.fixed()?),
        network: NetworkId::from_bytes(r.fixed()?),
        sequence: CheckpointSequence::new(r.u64()?),
        committee_context: CommitteeContext::new(
            Epoch::new(r.u64()?),
            CommitteeId::from_bytes(r.fixed()?),
        ),
        parent_artifact_id: ExecutionArtifactId::from_bytes(r.fixed()?),
        pre_state: StateCommitment::from_bytes(r.fixed()?),
        post_state: StateCommitment::from_bytes(r.fixed()?),
        order: decode_order(r.blob()?, l)?,
        occurrences_root: r.fixed()?,
        occurrence_count: r.u64()?,
        receipts_root: r.fixed()?,
        effects_root: r.fixed()?,
        system_events_root: r.fixed()?,
    };
    r.finish()?;
    if encode_artifact_header(&v)? != b {
        return Err(ArtifactError::Invalid);
    }
    Ok(v)
}

/// Encodes a complete source unit including its predecessor and every envelope byte.
pub fn encode_fixture_unit(v: &FixtureUnitRecord) -> Result<Vec<u8>, ArtifactError> {
    let mut w = Writer::new();
    w.u64(v.ordinal)?;
    w.raw(v.previous_unit_id.as_bytes())?;
    w.raw(&encode_occurrences(&v.occurrences)?)?;
    Ok(w.finish())
}

/// Decodes a complete source unit without authenticating its manifest membership.
pub fn decode_fixture_unit(b: &[u8], l: DecodeLimits) -> Result<FixtureUnitRecord, ArtifactError> {
    let mut r = Reader::new(b, l)?;
    let ordinal = r.u64()?;
    let previous_unit_id = FixtureUnitId::from_bytes(r.fixed()?);
    let occurrences = r.list(128, |b| decode_occurrence(b, l))?;
    r.finish()?;
    Ok(FixtureUnitRecord {
        ordinal,
        previous_unit_id,
        occurrences,
    })
}

/// Encodes a finite fixture stream bound to network and trusted starting identity.
pub fn encode_fixture_stream(v: &FixtureStreamRecord) -> Result<Vec<u8>, ArtifactError> {
    if v.unit_ids.len() > 64 {
        return Err(ArtifactError::Bound);
    }
    let mut w = Writer::new();
    w.raw(v.network.as_bytes())?;
    w.raw(v.starting_artifact_id.as_bytes())?;
    w.list(&v.unit_ids, |v| Ok(v.as_bytes().to_vec()))?;
    Ok(w.finish())
}

/// Decodes a finite stream representation without installing fixture trust.
pub fn decode_fixture_stream(
    b: &[u8],
    l: DecodeLimits,
) -> Result<FixtureStreamRecord, ArtifactError> {
    let mut r = Reader::new(b, l)?;
    let network = NetworkId::from_bytes(r.fixed()?);
    let starting_artifact_id = ExecutionArtifactId::from_bytes(r.fixed()?);
    let unit_ids = r.list(64, |b| {
        let mut r = Reader::new(b, l)?;
        let v = FixtureUnitId::from_bytes(r.fixed()?);
        r.finish()?;
        Ok(v)
    })?;
    r.finish()?;
    Ok(FixtureStreamRecord {
        network,
        starting_artifact_id,
        unit_ids,
    })
}
