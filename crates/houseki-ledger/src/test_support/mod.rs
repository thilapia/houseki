//! Synthetic public fixtures shared only by inline ledger tests.

mod fixtures;
mod order;
pub(crate) use fixtures::{manifest, payment_body, trusted_manifest};
pub(crate) use order::{fixture_occurrence, fixture_source, fixture_source_for};
pub(crate) mod execution;
mod seed;
pub(crate) use seed::seed_fixture;
