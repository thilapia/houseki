//! Explicitly opted in fresh public signed-unit fixture producer.

use std::{alloc::System, error::Error, path::PathBuf};

/// Enables protected allocation cleanup for the independent proving process.
#[global_allocator]
static ALLOCATOR: houseki_proofs::ProofAllocator<System> =
    houseki_proofs::ProofAllocator::new(System);

/// Generates only public fixture artifacts in a new requested output directory.
fn main() -> Result<(), Box<dyn Error>> {
    let directory = PathBuf::from(
        std::env::args_os()
            .nth(1)
            .ok_or("expected a new seed output directory")?,
    );
    houseki_ledger_qualification::seed(&directory)
}
