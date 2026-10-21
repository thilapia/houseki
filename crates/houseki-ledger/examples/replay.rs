//! Fresh verifier only public fixture replay with explicit experimental admission.

#[path = "../qualification/src/checkpoint_measurement.rs"]
mod checkpoint_measurement;
#[path = "../qualification/src/consumer.rs"]
mod consumer;
#[path = "../qualification/src/error.rs"]
mod error;
#[path = "../qualification/src/workload.rs"]
mod workload;

pub use error::QualificationError;
pub use workload::Workload;

use std::{error::Error, path::PathBuf};

/// Replays one digest bound public fixture without a prover allocator or wallet inputs.
fn main() -> Result<(), Box<dyn Error>> {
    let mut args = std::env::args_os().skip(1);
    let directory = PathBuf::from(args.next().ok_or("expected a public fixture directory")?);
    if args.next().is_some() {
        return Err("unexpected replay argument".into());
    }

    let result = consumer::verify(&directory)?;
    print!("{}", result.report());
    Ok(())
}
