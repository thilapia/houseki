//! Public only fixture retention and digest bound reproducible files.

use crate::{Measurement, Workload};
use houseki_ledger::{
    BootstrapManifest, CommittedCheckpoint, ReplayArchive, SnapshotRecord, encode_snapshot,
};
use sha3::{Digest, Sha3_512};
use std::{
    error::Error,
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};

/// A generated actual execution corpus containing no private wallet or signing owners.
pub struct PublicFixture {
    /// Requested new public output directory.
    pub(crate) directory: PathBuf,

    /// Independently generated public fixture bootstrap declarations.
    pub(crate) manifest: BootstrapManifest,

    /// Complete replay archive of actual verified execution.
    pub(crate) archive: ReplayArchive,

    /// Actual immutable committed records used for local result inspection.
    pub(crate) checkpoints: Vec<CommittedCheckpoint>,

    /// Separate local phase/retention observations.
    pub(crate) measurement: Measurement,
}

impl PublicFixture {
    /// Borrows actual committed checkpoint handles for public result inspection.
    pub fn checkpoints(&self) -> &[CommittedCheckpoint] {
        &self.checkpoints
    }

    /// Borrows explicit local resource observations.
    pub const fn measurement(&self) -> &Measurement {
        &self.measurement
    }

    /// Returns the public output directory selected by the caller.
    pub fn directory(&self) -> &Path {
        &self.directory
    }

    /// Exports complete public inputs only after execution and native replay succeeded.
    pub(crate) fn write(&self, workload: Workload) -> Result<(), Box<dyn Error>> {
        fs::create_dir(&self.directory)?;
        let candidate = self.manifest.clone().candidate()?;
        let state = encode_snapshot(&SnapshotRecord::from_state(candidate.state())?)?;
        let mut leaves = (self.manifest.leaves.len() as u64).to_le_bytes().to_vec();
        for leaf in &self.manifest.leaves {
            leaves.extend_from_slice(&64_u64.to_le_bytes());
            leaves.extend_from_slice(leaf.as_bytes());
        }

        let root = hex(self.manifest.expected_state_commitment.as_bytes()).into_bytes();
        let stream = hex(self.manifest.source_cursor.stream_id().as_bytes()).into_bytes();
        let archive = self.archive.to_bytes()?;
        let mut metadata = format!(
            "houseki-ledger-public-fixture-v1\nfixture_order=true\nworkload={}\n",
            workload.name()
        );
        for (name, bytes) in [
            ("bootstrap-state.bin", state),
            ("bootstrap-leaves.bin", leaves),
            ("bootstrap-state.hex", root),
            ("stream.hex", stream),
            ("archive.bin", archive),
        ] {
            metadata.push_str(&format!("{name}={}\n", hex(&Sha3_512::digest(&bytes))));
            write_new(&self.directory.join(name), &bytes)?;
        }

        write_new(&self.directory.join("manifest.txt"), metadata.as_bytes())?;
        write_new(
            &self.directory.join("measurement.txt"),
            self.measurement.report().as_bytes(),
        )?;
        Ok(())
    }
}

/// Creates one new complete public artifact without overwriting an existing file.
fn write_new(path: &Path, bytes: &[u8]) -> Result<(), Box<dyn Error>> {
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(bytes)?;
    Ok(())
}

/// Formats only public digests for corpus integrity checks.
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
