//! Serial native qualification commands with successful observations written as JSON lines.

#[cfg(feature = "prover")]
use houseki_proofs::CancellationToken;
use houseki_proofs::ProofRuntime;
use houseki_proofs_qualification::{Error, PublicArtifact, Workload};
#[cfg(feature = "prover")]
use std::fs;
use std::{
    io::{self, Write},
    path::PathBuf,
};

/// Rejects malformed commands before fixture preparation or verification.
fn main() -> Result<(), Error> {
    let mut args = std::env::args().skip(1);
    let operation = args
        .next()
        .ok_or(Error::Input("expected produce or verify"))?;
    let workload: Workload = args
        .next()
        .ok_or(Error::Input("expected workload"))?
        .parse()?;
    let directory = PathBuf::from(
        args.next()
            .ok_or(Error::Input("expected artifact directory"))?,
    );
    let iterations: usize = args
        .next()
        .ok_or(Error::Input("expected iteration count"))?
        .parse()
        .map_err(|_| Error::Input("invalid iteration count"))?;
    if args.next().is_some() || !(1..=1000).contains(&iterations) {
        return Err(Error::Input(
            "expected 1 through 1000 iterations and no trailing arguments",
        ));
    }

    let runtime = ProofRuntime::new();
    match operation.as_str() {
        "verify" => {
            for _ in 0..iterations {
                let sample = PublicArtifact::load(&directory, workload)?.verify(&runtime)?;
                println!("{}", sample.json());
                io::stdout().flush()?;
            }
        }
        #[cfg(feature = "prover")]
        "produce" => {
            fs::create_dir(&directory)?;
            for index in 0..iterations {
                let (artifact, sample) = houseki_proofs_qualification::produce(
                    workload,
                    &runtime,
                    &CancellationToken::new(),
                )?;
                artifact.write(&directory.join(format!("sample-{index:04}")))?;
                println!("{}", sample.json());
                io::stdout().flush()?;
            }
        }
        _ => {
            return Err(Error::Input(
                "unsupported operation or producer feature is disabled",
            ));
        }
    }

    Ok(())
}
