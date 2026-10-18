//! Protected payment trace construction from original borrowed native owners.

use super::{PaymentAir, PaymentLayout, schedule::Schedule};
use crate::{
    CancellationToken, PaymentWitness,
    backend::{BackendError, OpeningFields, SpendFields, Trace},
    gadgets::{CompactOpening, MembershipInput, Scratch, SpendInput, assign_addition},
    statement::{PaymentValues, Statement},
};
use p3_field::PrimeCharacteristicRing;
use p3_goldilocks::Goldilocks;

/// Builds complete note operations with one protected conversion at a time and exact public sources.
pub(super) fn build(
    air: &PaymentAir<'_>,
    witness: &PaymentWitness<'_>,
    statement: &Statement,
    cancellation: &CancellationToken,
) -> Result<Trace, BackendError> {
    if cancellation.is_cancelled() {
        return Err(BackendError::Cancelled);
    }

    let shape = air.layout.shape();
    if witness.inputs().len() != shape.inputs() || witness.outputs().len() != shape.outputs() {
        return Err(BackendError::InvalidTrace);
    }

    let public = PaymentValues::new(&statement.public_values, shape.inputs(), shape.outputs())
        .ok_or(BackendError::InvalidTrace)?;
    let width = air.layout.width();
    let mut trace = Trace::new(air.layout.rows(), width, air.layout.rows() * width)?;
    let mut totals = Scratch::<32>::default();
    for (index, witness) in witness.inputs().iter().enumerate() {
        checkpoint(cancellation)?;
        let fields = SpendFields::new(witness)?;
        let start = index * Schedule::INPUT_ROWS;
        let commitment = opening(air, fields.opening(), &mut trace, start)?;
        note_registers(
            &mut trace,
            start..start + Schedule::INPUT_ROWS,
            &totals,
            fields.opening(),
            &commitment,
            fields.position(),
        );
        air.spend
            .assign(
                SpendInput {
                    spending_key: fields.spending_key(),
                    nullifier_key: fields.nullifier_key(),
                    network: public.network(),
                    commitment: &commitment,
                    position: fields.position(),
                },
                &mut trace.values_mut()[(start + 128) * width + PaymentLayout::WORK..],
                width,
            )
            .map_err(|_| BackendError::InvalidTrace)?;
        checkpoint(cancellation)?;
        air.membership
            .assign(
                MembershipInput {
                    network: public.network(),
                    count: public.count(),
                    commitment: &commitment,
                    position: fields.position(),
                    siblings: fields.siblings(),
                },
                &mut trace.values_mut()[(start + 216) * width + PaymentLayout::WORK..],
                width,
            )
            .map_err(|_| BackendError::InvalidTrace)?;
        add(
            &mut trace,
            start + Schedule::INPUT_ROWS - 1,
            (&mut totals[..16]).try_into().unwrap(),
            fields.opening().amount(),
        )?;
    }

    for (index, opening_owner) in witness.outputs().iter().enumerate() {
        checkpoint(cancellation)?;
        let fields = OpeningFields::new(opening_owner)?;
        let start = shape.inputs() * Schedule::INPUT_ROWS + index * Schedule::OUTPUT_ROWS;
        let commitment = opening(air, &fields, &mut trace, start)?;
        note_registers(
            &mut trace,
            start..start + Schedule::OUTPUT_ROWS,
            &totals,
            &fields,
            &commitment,
            &[Goldilocks::ZERO; 8],
        );
        add(
            &mut trace,
            start + 128,
            (&mut totals[16..]).try_into().unwrap(),
            fields.amount(),
        )?;
    }

    checkpoint(cancellation)?;
    let fee_row = air.layout.schedule.active_rows() - 1;
    trace.values_mut()[fee_row * width..fee_row * width + 32].copy_from_slice(&totals[..]);
    add(
        &mut trace,
        fee_row,
        (&mut totals[16..]).try_into().unwrap(),
        public.fee(),
    )?;
    for row in fee_row + 1..air.layout.rows() {
        trace.values_mut()[row * width..row * width + 32].copy_from_slice(&totals[..]);
    }

    Ok(trace)
}

/// Imports one complete opening into reusable guarded scratch and copies its exact digest.
fn opening(
    air: &PaymentAir<'_>,
    fields: &OpeningFields,
    trace: &mut Trace,
    start: usize,
) -> Result<Scratch<64>, BackendError> {
    let mut rows = Trace::new(128, CompactOpening::WIDTH, 128 * CompactOpening::WIDTH)?;
    air.opening
        .assign(fields.input(), rows.values_mut())
        .map_err(|_| BackendError::InvalidTrace)?;
    let mut commitment = Scratch::<64>::default();
    for word in 0..16 {
        let offset = (60 + word) * CompactOpening::WIDTH + 373;
        commitment[word * 4..word * 4 + 4].copy_from_slice(&rows.values()[offset..offset + 4]);
    }

    let width = trace.width();
    for row in 0..128 {
        let destination = (start + row) * width + PaymentLayout::WORK;
        trace.values_mut()[destination..destination + CompactOpening::WIDTH].copy_from_slice(
            &rows.values()[row * CompactOpening::WIDTH..(row + 1) * CompactOpening::WIDTH],
        );
    }

    Ok(commitment)
}

/// Keeps exact totals and linked note fields live until its one scheduled accumulation completes.
fn note_registers(
    trace: &mut Trace,
    rows: std::ops::Range<usize>,
    totals: &[Goldilocks; 32],
    fields: &OpeningFields,
    commitment: &[Goldilocks; 64],
    position: &[Goldilocks; 8],
) {
    let width = trace.width();
    for row in rows {
        let destination = &mut trace.values_mut()[row * width..row * width + PaymentLayout::WORK];
        destination[..32].copy_from_slice(totals);
        destination[32..48].copy_from_slice(fields.amount());
        destination[48..112].copy_from_slice(&fields.recipient()[72..136]);
        destination[112..176].copy_from_slice(commitment);
        destination[176..184].copy_from_slice(position);
    }
}

/// Assigns exact limb addition and updates only the selected protected running total.
fn add(
    trace: &mut Trace,
    row: usize,
    total: &mut [Goldilocks; 16],
    amount: &[Goldilocks; 16],
) -> Result<(), BackendError> {
    let start = row * trace.width() + PaymentLayout::WORK;
    let work = &mut trace.values_mut()[start..start + 448];
    work[..16].copy_from_slice(total);
    work[16..32].copy_from_slice(amount);
    let (operands, rest) = work.split_at_mut(32);
    let (sum, rest) = rest.split_at_mut(16);
    let (left_bits, rest) = rest.split_at_mut(128);
    let (right_bits, rest) = rest.split_at_mut(128);
    let (sum_bits, carries) = rest.split_at_mut(128);
    assign_addition(
        [
            operands[..16].try_into().unwrap(),
            operands[16..].try_into().unwrap(),
        ],
        [
            left_bits.as_chunks_mut::<8>().0.try_into().unwrap(),
            right_bits.as_chunks_mut::<8>().0.try_into().unwrap(),
        ],
        sum.try_into().unwrap(),
        sum_bits.as_chunks_mut::<8>().0.try_into().unwrap(),
        carries.try_into().unwrap(),
    )
    .map_err(|_| BackendError::InvalidTrace)?;
    total.copy_from_slice(sum);

    Ok(())
}

/// Observes explicit caller cancellation and protected backend cancellation between components.
fn checkpoint(cancellation: &CancellationToken) -> Result<(), BackendError> {
    if cancellation.is_cancelled() {
        return Err(BackendError::Cancelled);
    }

    crate::memory::checkpoint();

    Ok(())
}
