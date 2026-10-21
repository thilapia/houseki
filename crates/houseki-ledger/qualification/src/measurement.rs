//! Public byte/work counters and phase observations without production capacity thresholds.

use houseki_ledger::{CommittedCheckpoint, OutputBody, PreparationMetrics, ReplayArchive};
use houseki_types::{ExecutionOutcome, TransactionEnvelope};
use std::{error::Error, time::Duration};

/// Complete local workload observations with overlapping byte categories explicitly
/// retained.
#[derive(Debug, Default, Clone)]
pub struct Measurement {
    /// Per checkpoint public rows in actual execution order, including empty
    /// checkpoints.
    pub(crate) checkpoints: Vec<crate::checkpoint_measurement::CheckpointMeasurement>,

    /// Fresh proving duration across all actual proof calls.
    pub(crate) proving: Duration,

    /// Exact fixture order verification time.
    pub(crate) order: Duration,

    /// Complete cryptographic unit authorization time.
    pub(crate) authorization: Duration,

    /// Independently reconstructed working state time.
    pub(crate) reconstruction: Duration,

    /// Ordered state effects and alignment time.
    pub(crate) execution: Duration,

    /// Exact canonical encoding and commitment time.
    pub(crate) commitments: Duration,

    /// Complete ownership publication time.
    pub(crate) publication: Duration,

    /// Independent native replay time in this producer graph.
    pub(crate) replay: Duration,

    /// Complete length prefixed component input bytes across unique source units.
    pub(crate) component_bytes: u64,

    /// Complete original body bytes, including outputs and recovery context.
    pub(crate) body_bytes: u64,

    /// Proof bytes across every genuine occurrence, including state rejections.
    pub(crate) proof_bytes: u64,

    /// Complete encoded source unit storage retained once per unit.
    pub(crate) retained_unit_bytes: u64,

    /// Exact serialized public replay bytes.
    pub(crate) archive_bytes: u64,

    /// Number of accepted canonical occurrence results.
    pub(crate) accepted: u64,

    /// Number of rejected canonical occurrence results.
    pub(crate) rejected: u64,

    /// Accepted original output instances including repeated commitments.
    pub(crate) accepted_outputs: u64,

    /// Accepted position bound public marker bytes.
    pub(crate) accepted_nullifier_bytes: u64,

    /// Accepted encapsulation bytes, overlapping the complete body/context category.
    pub(crate) accepted_encapsulation_bytes: u64,

    /// Accepted opaque encrypted payload bytes, overlapping complete body/context
    /// bytes.
    pub(crate) accepted_payload_bytes: u64,

    /// Full accepted body bytes counted once per origin even for multiple outputs.
    pub(crate) accepted_body_context_bytes: u64,

    /// Process high water memory when directly available on this platform.
    pub(crate) peak_memory_bytes: Option<u64>,
}

impl Measurement {
    /// Adds diagnostics that cannot influence canonical preparation decisions.
    pub(crate) fn preparation(&mut self, metrics: &PreparationMetrics) {
        self.reconstruction += metrics.reconstruction();
        self.execution += metrics.execution();
        self.commitments += metrics.commitments();
    }

    /// Counts committed accepted contexts once per origin and output payloads once per
    /// actual append.
    pub(crate) fn checkpoint(
        &mut self,
        checkpoint: &CommittedCheckpoint,
    ) -> Result<(), Box<dyn Error>> {
        for (occurrence, receipt) in checkpoint
            .artifact()
            .occurrences()
            .iter()
            .zip(checkpoint.receipts())
        {
            match receipt.outcome() {
                ExecutionOutcome::Accepted => {
                    self.accepted += 1;
                    self.accepted_body_context_bytes += match occurrence.envelope() {
                        TransactionEnvelope::Payment(e) => {
                            e.body()
                                .to_bytes(
                                    houseki_proofs::ProofContext::new(e.body().context())?
                                        .body_limits(),
                                )?
                                .len() as u64
                        }
                        TransactionEnvelope::RewardWithdrawal(e) => {
                            e.body()
                                .to_bytes(
                                    houseki_proofs::ProofContext::new(e.body().context())?
                                        .body_limits(),
                                )?
                                .len() as u64
                        }
                    };
                }
                ExecutionOutcome::Rejected(_) => self.rejected += 1,
            }
        }

        for effect in checkpoint.effects() {
            if let Some(effect) = &effect.accepted {
                self.accepted_nullifier_bytes += effect.nullifiers.len() as u64 * 64;
            }
        }

        for output in checkpoint.accepted_outputs() {
            self.accepted_outputs += 1;
            self.accepted_encapsulation_bytes +=
                output.output().envelope().encapsulation().as_bytes().len() as u64;
            self.accepted_payload_bytes += output.output().envelope().payload().len() as u64;
            match output.body() {
                OutputBody::Payment(_) | OutputBody::RewardWithdrawal(_) => {}
            }
        }

        self.checkpoints
            .push(crate::checkpoint_measurement::CheckpointMeasurement::capture(checkpoint));
        Ok(())
    }

    /// Records actual serialized retention instead of multiplying shared owners by
    /// slice count.
    pub(crate) fn archive(&mut self, archive: &ReplayArchive) -> Result<(), Box<dyn Error>> {
        self.retained_unit_bytes = archive.source_units().map(|b| b.len() as u64).sum();
        self.archive_bytes = archive.to_bytes()?.len() as u64;
        self.peak_memory_bytes = peak_memory();
        Ok(())
    }

    /// Produces explicit local observations with no throughput or production assurance
    /// claim.
    pub fn report(&self) -> String {
        let mut report = format!(
            "fixture_order=true\nconsensus_finality=unconfirmed\nexecution_proof=unverified\nbyte_categories_overlap=true\nproving_ns={}\norder_ns={}\nauthorization_ns={}\nreconstruction_ns={}\nexecution_ns={}\ncommitments_ns={}\npublication_ns={}\nproducer_graph_replay_ns={}\ncomponent_input_bytes={}\nbody_bytes={}\nproof_bytes={}\nretained_unit_bytes={}\narchive_bytes={}\naccepted={}\nrejected={}\naccepted_outputs={}\naccepted_nullifier_bytes={}\naccepted_encapsulation_bytes={}\naccepted_payload_bytes={}\naccepted_body_context_bytes={}\npeak_memory_bytes={}\n",
            self.proving.as_nanos(),
            self.order.as_nanos(),
            self.authorization.as_nanos(),
            self.reconstruction.as_nanos(),
            self.execution.as_nanos(),
            self.commitments.as_nanos(),
            self.publication.as_nanos(),
            self.replay.as_nanos(),
            self.component_bytes,
            self.body_bytes,
            self.proof_bytes,
            self.retained_unit_bytes,
            self.archive_bytes,
            self.accepted,
            self.rejected,
            self.accepted_outputs,
            self.accepted_nullifier_bytes,
            self.accepted_encapsulation_bytes,
            self.accepted_payload_bytes,
            self.accepted_body_context_bytes,
            self.peak_memory_bytes
                .map_or_else(|| "unavailable".into(), |v| v.to_string())
        );
        report.push_str(&format!("checkpoint_rows={}\n", self.checkpoints.len()));
        for checkpoint in &self.checkpoints {
            report.push_str(&checkpoint.report());
        }

        report
    }
}

/// Reads Linux's observed process high water mark without interpreting absent data as zero.
fn peak_memory() -> Option<u64> {
    #[cfg(target_os = "linux")]
    {
        let status = std::fs::read_to_string("/proc/self/status").ok()?;
        let line = status.lines().find(|l| l.starts_with("VmHWM:"))?;
        return line
            .split_whitespace()
            .nth(1)?
            .parse::<u64>()
            .ok()?
            .checked_mul(1024);
    }

    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

/// Resource accounting checks over required complete generated public workloads.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::consumer::load;
    use houseki_ledger::{DecodeLimits, decode_fixture_unit, replay};
    use houseki_proofs::{ProofContext, ProofRuntime};
    use houseki_types::{ExecutionProofStatus, FinalityStatus};
    use std::path::PathBuf;

    /// Requires the complete generated public corpus rather than silently skipping
    /// measurements.
    fn directory(name: &str) -> PathBuf {
        PathBuf::from(
            std::env::var_os("HOUSEKI_LEDGER_PUBLIC_CORPUS")
                .expect("generate-all and set HOUSEKI_LEDGER_PUBLIC_CORPUS"),
        )
        .join(name)
    }

    /// Input accounting includes the original count and every complete record prefix.
    #[test]
    fn measurement_counts_complete_unit_and_archive_bytes() {
        let (_, _, archive) = load(&directory("1-2")).unwrap();
        let mut measurement = Measurement::default();
        measurement.archive(&archive).unwrap();
        let unit = archive.source_units().next().unwrap();

        assert_eq!(measurement.retained_unit_bytes, unit.len() as u64);
        assert_eq!(
            measurement.archive_bytes,
            std::fs::metadata(directory("1-2").join("archive.bin"))
                .unwrap()
                .len()
        );

        let decoded = decode_fixture_unit(unit, DecodeLimits::reference()).unwrap();

        assert_eq!(
            houseki_ledger::encode_occurrences(&decoded.occurrences)
                .unwrap()
                .len()
                + 72,
            unit.len()
        );
    }

    /// Sixty five real checkpoints retain sixty four unique unit payloads under the
    /// fixed caps.
    #[test]
    fn fixture_limits_bound_retention() {
        let (_, manifest, archive) = load(&directory("anchor-pruning")).unwrap();

        assert_eq!(archive.source_unit_count(), 64);
        assert_eq!(archive.checkpoint_count(), 65);
        assert_eq!(manifest.policy.limits().unit_occurrences(), 128);
        assert_eq!(manifest.policy.limits().fixture_units(), 64);

        for unit in archive.source_units() {
            assert!(unit.len() <= 33554432 + 72);
            assert!(
                decode_fixture_unit(unit, DecodeLimits::reference())
                    .unwrap()
                    .occurrences
                    .len()
                    <= 128
            );
        }
    }

    /// Every retained checkpoint has public identity and counts whose sums equal the
    /// totals.
    #[test]
    fn per_checkpoint_counts_match_aggregate() {
        let (_, manifest, archive) = load(&directory("anchor-pruning")).unwrap();

        let store = replay(manifest, &archive, &ProofRuntime::new()).unwrap();
        let mut identity = store.snapshot().head().artifact_id();
        let mut checkpoints = vec![];
        loop {
            let checkpoint = store.checkpoint(identity).unwrap();
            identity = checkpoint.artifact().header().parent_artifact_id;
            checkpoints.push(checkpoint);
            if identity == houseki_ledger::ExecutionArtifactId::from_bytes([0; 64]) {
                break;
            }
        }

        let mut measurement = Measurement::default();
        for checkpoint in checkpoints.iter().rev() {
            measurement.checkpoint(checkpoint).unwrap();
        }

        let report = measurement.report();
        let fields: std::collections::BTreeMap<_, _> = report
            .lines()
            .filter_map(|line| line.split_once('='))
            .collect();

        assert_eq!(fields.get("checkpoint_rows"), Some(&"65"));

        for (suffix, aggregate) in [
            ("accepted", measurement.accepted),
            ("rejected", measurement.rejected),
            ("appended_outputs", measurement.accepted_outputs),
        ] {
            let total: u64 = (1..=65)
                .map(|sequence| {
                    fields[format!("checkpoint.{sequence}.{suffix}").as_str()]
                        .parse::<u64>()
                        .unwrap()
                })
                .sum();

            assert_eq!(total, aggregate);
        }

        for checkpoint in checkpoints {
            let identity: String = checkpoint
                .artifact()
                .identity()
                .as_bytes()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect();
            let sequence = checkpoint.artifact().header().sequence.value();

            assert_eq!(
                fields[format!("checkpoint.{sequence}.artifact_id").as_str()],
                identity
            );
        }
    }

    /// Output contexts are counted once per accepted body, including two output and
    /// rejected copy cases.
    #[test]
    fn accepted_output_measurements_preserve_context_cost() {
        for name in ["1-2", "conflicts"] {
            let (_, manifest, archive) = load(&directory(name)).unwrap();

            let store = replay(manifest, &archive, &ProofRuntime::new()).unwrap();
            let checkpoint = store
                .checkpoint(store.snapshot().head().artifact_id())
                .unwrap();
            let mut measurement = Measurement::default();
            measurement.checkpoint(&checkpoint).unwrap();

            let unit = decode_fixture_unit(
                archive.source_units().next().unwrap(),
                DecodeLimits::reference(),
            )
            .unwrap();
            let TransactionEnvelope::Payment(e) = unit.occurrences[0].envelope() else {
                unreachable!()
            };
            let length = e
                .body()
                .to_bytes(ProofContext::new(e.body().context()).unwrap().body_limits())
                .unwrap()
                .len() as u64;

            assert_eq!(measurement.accepted_body_context_bytes, length);
            assert_eq!(
                measurement.accepted_encapsulation_bytes,
                measurement.accepted_outputs * 1568
            );
            assert_eq!(measurement.accepted, 1);

            if name == "1-2" {
                assert_eq!(measurement.accepted_outputs, 2)
            } else {
                assert_eq!(measurement.rejected, 1)
            }
        }
    }

    /// Local publication and public replay preserve explicit consensus and execution
    /// proof status.
    #[test]
    fn consumer_status_never_implies_finality() {
        let (_, manifest, archive) = load(&directory("withdrawal")).unwrap();

        let store = replay(manifest, &archive, &ProofRuntime::new()).unwrap();
        let checkpoint = store
            .checkpoint(store.snapshot().head().artifact_id())
            .unwrap();

        assert_eq!(checkpoint.finality_status(), FinalityStatus::Unconfirmed);
        assert_eq!(
            checkpoint.execution_proof_status(),
            ExecutionProofStatus::Unverified
        );
    }
}
