//! Canonical fingerprints of public polynomial and schedule metadata.

use crate::circuits::payment::PaymentAir;
use p3_air::{
    BaseAir,
    symbolic::{
        AirLayout, BaseEntry, BaseLeaf, SymbolicExpr, SymbolicExpression, get_symbolic_constraints,
    },
};
use p3_field::PrimeField64;
use p3_goldilocks::Goldilocks;
use sha3::{Digest, Sha3_512};
use std::collections::HashMap;

/// Hashes the ordered complete polynomial list with canonical field and variable encodings.
pub(super) fn polynomials(air: &PaymentAir<'_>) -> [u8; 64] {
    let expressions = get_symbolic_constraints(air, AirLayout::from_air(air));
    let mut cached = HashMap::new();
    let mut hash = Sha3_512::new();
    hash.update(b"houseki/payment/air-polynomials/v1");
    hash.update((expressions.len() as u64).to_le_bytes());
    for expression in &expressions {
        hash.update(expression_hash(expression, &mut cached));
    }

    hash.finalize().into()
}

/// Hashes exact row-major selector bytes including the entire zeroed padding suffix.
pub(super) fn schedule(air: &PaymentAir<'_>) -> [u8; 64] {
    let mut hash = Sha3_512::new();
    hash.update(b"houseki/payment/schedule/v1");
    hash.update((air.layout.shape().inputs() as u32).to_le_bytes());
    hash.update((air.layout.shape().outputs() as u32).to_le_bytes());
    hash.update((air.layout.rows() as u64).to_le_bytes());
    hash.update((air.num_periodic_columns() as u32).to_le_bytes());
    for row in 0..air.layout.rows() {
        let values: Vec<u8> = air
            .periodic_values(row)
            .iter()
            .map(|value| {
                let value = value.as_canonical_u64();
                assert!(value <= 1);

                value as u8
            })
            .collect();
        hash.update(values);
    }

    hash.finalize().into()
}

/// Encodes shared expression nodes independently from pointer identity or allocation order.
fn expression_hash(
    expression: &SymbolicExpression<Goldilocks>,
    cached: &mut HashMap<*const SymbolicExpression<Goldilocks>, [u8; 64]>,
) -> [u8; 64] {
    let pointer = std::ptr::from_ref(expression);
    if let Some(digest) = cached.get(&pointer) {
        return *digest;
    }

    let mut hash = Sha3_512::new();
    match expression {
        SymbolicExpr::Leaf(BaseLeaf::Variable(variable)) => {
            hash.update([0]);
            let (kind, offset) = match variable.entry {
                BaseEntry::Preprocessed { offset } => (0, offset),
                BaseEntry::Main { offset } => (1, offset),
                BaseEntry::Periodic => (2, 0),
                BaseEntry::Public => (3, 0),
            };
            hash.update([kind]);
            hash.update((offset as u64).to_le_bytes());
            hash.update((variable.index as u64).to_le_bytes());
        }

        SymbolicExpr::Leaf(BaseLeaf::IsFirstRow) => hash.update([1]),
        SymbolicExpr::Leaf(BaseLeaf::IsLastRow) => hash.update([2]),
        SymbolicExpr::Leaf(BaseLeaf::IsTransition) => hash.update([3]),
        SymbolicExpr::Leaf(BaseLeaf::Constant(value)) => {
            hash.update([4]);
            hash.update(value.as_canonical_u64().to_le_bytes());
        }

        SymbolicExpr::Add { x, y, .. }
        | SymbolicExpr::Sub { x, y, .. }
        | SymbolicExpr::Mul { x, y, .. } => {
            let tag = match expression {
                SymbolicExpr::Add { .. } => 5,
                SymbolicExpr::Sub { .. } => 6,
                _ => 7,
            };
            hash.update([tag]);
            hash.update(expression_hash(x, cached));
            hash.update(expression_hash(y, cached));
        }

        SymbolicExpr::Neg { x, .. } => {
            hash.update([8]);
            hash.update(expression_hash(x, cached));
        }
    }

    let digest = hash.finalize().into();
    cached.insert(pointer, digest);

    digest
}

/// Formats public metadata hashes consistently in golden vectors.
pub(super) fn hex(bytes: [u8; 64]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
