//! Public fixture generation supervisor and separately buildable verifier only consumer.

#[cfg(feature = "prover")]
use houseki_ledger_qualification::Workload;
use houseki_ledger_qualification::verify;
use std::{error::Error, path::PathBuf};
#[cfg(feature = "prover")]
use std::{
    fs::{self, OpenOptions},
    io::Write,
    process::Command,
};

/// Installs private allocation cleanup only for explicitly proving executable builds.
#[cfg(feature = "prover")]
#[global_allocator]
static ALLOCATOR: houseki_proofs::ProofAllocator<std::alloc::System> =
    houseki_proofs::ProofAllocator::new(std::alloc::System);

/// Executes one documented command and returns nonzero for missing inputs or failed
/// workloads.
fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    match args.first().and_then(|a| a.to_str()) {
        Some("verify") if args.len() == 2 => {
            let summary = verify(&PathBuf::from(&args[1]))?;
            print!("{}", summary.report());
            Ok(())
        }
        #[cfg(feature = "prover")]
        Some("generate") if args.len() == 4 && args[2] == "--workload" => {
            let workload = Workload::parse(args[3].to_str().ok_or("non-UTF8 workload")?)?;
            let fixture = houseki_ledger_qualification::generate(
                workload,
                &PathBuf::from(&args[1]),
            )?;
            println!("generated {}\n{}", workload.name(), fixture.measurement().report());
            Ok(())
        }
        #[cfg(feature = "prover")]
        Some("generate-all") if args.len() == 2 => generate_all(PathBuf::from(&args[1])),
        _ => Err("usage: verify <public-directory>, or with prover: generate <new-directory> --workload <name> | generate-all <new-directory>".into()),
    }
}

/// Runs every required workload in its own measured child process without overwriting a
/// corpus.
#[cfg(feature = "prover")]
fn generate_all(directory: PathBuf) -> Result<(), Box<dyn Error>> {
    fs::create_dir(&directory)?;
    let executable = std::env::current_exe()?;
    for workload in Workload::all() {
        let destination = directory.join(workload.name());
        let timer = std::path::Path::new("/usr/bin/time");
        let mut command = if timer.exists() {
            let mut c = Command::new(timer);
            c.arg(if cfg!(target_os = "macos") {
                "-l"
            } else {
                "-v"
            });

            c.arg(&executable);
            c
        } else {
            Command::new(&executable)
        };

        let output = command
            .arg("generate")
            .arg(&destination)
            .arg("--workload")
            .arg(workload.name())
            .output()?;
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        let log = format!("{stdout}\n{stderr}");
        if !output.status.success() {
            fs::write(
                directory.join(format!("{}-failed.log", workload.name())),
                log,
            )?;
            return Err(format!(
                "required workload {} failed: {}",
                workload.name(),
                output.status
            )
            .into());
        }

        fs::write(destination.join("runner.log"), log)?;
        let peak = observed_peak(&stderr);
        let mut report = OpenOptions::new()
            .append(true)
            .open(destination.join("measurement.txt"))?;
        writeln!(
            report,
            "supervised_peak_memory_bytes={}\nsupervised_peak_scope=fresh-workload-process",
            peak.map_or_else(|| "unavailable".into(), |n| n.to_string())
        )?;
        println!(
            "{}: verified, public artifacts exported, peak_memory_bytes={}",
            workload.name(),
            peak.map_or_else(|| "unavailable".into(), |n| n.to_string())
        );
    }

    println!("all {} required workloads completed", Workload::all().len());
    Ok(())
}

/// Parses observed platform high water memory while retaining unavailable data explicitly.
#[cfg(feature = "prover")]
fn observed_peak(stderr: &str) -> Option<u64> {
    for line in stderr.lines() {
        if line.contains("maximum resident set size") {
            return line.split_whitespace().next()?.parse().ok();
        }

        if let Some(value) = line
            .trim()
            .strip_prefix("Maximum resident set size (kbytes):")
        {
            return value.trim().parse::<u64>().ok()?.checked_mul(1024);
        }
    }

    None
}
