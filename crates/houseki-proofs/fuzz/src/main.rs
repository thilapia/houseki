//! Reproducible public verifier attacks on the pinned stable Rust toolchain.

#![warn(missing_docs, clippy::missing_docs_in_private_items)]

mod allocation;
mod body;
mod campaign;
mod mutation;
mod seed;

use allocation::ObservedAllocator;
use seed::Seed;
use std::{error::Error, path::PathBuf, time::Duration};

/// Observes verifier allocations without adding witness or proving capabilities.
#[global_allocator]
static ALLOCATOR: ObservedAllocator = ObservedAllocator;

/// Runs fixed conformance attacks or a reproducible time bounded mutation campaign.
fn main() -> Result<(), Box<dyn Error>> {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let directory = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../fixtures/adversarial");
    let seeds = Seed::load_all(&directory)?;
    match arguments.as_slice() {
        [mode] if mode == "conformance" => campaign::conformance(&seeds),
        [mode, iteration, random] if mode == "replay" => {
            campaign::replay(&seeds, iteration.parse()?, random.parse()?)
        }
        [mode, seconds, random] if mode == "fuzz" => {
            let seconds: u64 = seconds.parse()?;
            if !(1..=3600).contains(&seconds) {
                return Err("campaign duration must be between 1 and 3600 seconds".into());
            }

            campaign::fuzz(&seeds, Duration::from_secs(seconds), random.parse()?)
        }
        _ => Err("expected conformance, fuzz <seconds> <nonzero-seed> or replay <iteration> <nonzero-seed>".into()),
    }
}
