//! Synthetic public fixtures shared only by inline ledger tests.

mod execution;
mod failure;
mod fixtures;
mod order;
mod seed;

pub(crate) use execution::payment;
pub(crate) use failure::{FailurePoint, hit, inject};
pub(crate) use fixtures::{manifest, payment_body, trusted_manifest};
pub(crate) use order::fixture_source_for;
pub(crate) use seed::seed_fixture;
