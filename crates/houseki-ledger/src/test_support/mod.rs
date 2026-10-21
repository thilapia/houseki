//! Synthetic public fixtures shared only by inline ledger tests.

pub(crate) mod execution;
pub(crate) mod failure;
mod fixtures;
pub(crate) mod model;
mod order;
mod seed;

pub(crate) use fixtures::{manifest, payment_body, trusted_manifest};

pub(crate) use order::{fixture_occurrence, fixture_source, fixture_source_for};

pub(crate) use seed::seed_fixture;
