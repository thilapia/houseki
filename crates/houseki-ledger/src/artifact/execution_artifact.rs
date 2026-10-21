//! Complete native summary without consensus or execution-proof certification.

use crate::{
    ArtifactError, ArtifactHeader, EffectRecord, ExecutionArtifactId, encode_artifact_header,
};
use houseki_types::{Occurrence, Receipt};
use std::{ops::Range, sync::Arc};

/// Public native reference artifact whose publication is owned by a later prepared capability.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionArtifact {
    /// Canonical complete header binding context and component commitments.
    pub(crate) header: ArtifactHeader,

    /// Complete local identity derived from the acyclic header.
    pub(crate) identity: ExecutionArtifactId,

    /// Original ordered occurrences retained for recovery and replay queries.
    pub(crate) occurrences: Arc<[Occurrence]>,

    /// Exact chosen range within the shared complete source owner.
    pub(crate) range: Range<usize>,

    /// Canonical ordered outcomes.
    pub(crate) receipts: Vec<Receipt>,

    /// Canonical public effects aligned with occurrences and receipts.
    pub(crate) effects: Vec<EffectRecord>,
}

impl ExecutionArtifact {
    /// Returns the exact artifact identity without implying consensus finality.
    pub const fn identity(&self) -> ExecutionArtifactId {
        self.identity
    }

    /// Borrows the complete immutable header.
    pub const fn header(&self) -> &ArtifactHeader {
        &self.header
    }

    /// Borrows the original ordered occurrences.
    pub fn occurrences(&self) -> &[Occurrence] {
        &self.occurrences[self.range.clone()]
    }

    /// Borrows one canonical outcome per occurrence.
    pub fn receipts(&self) -> &[Receipt] {
        &self.receipts
    }

    /// Borrows the aligned public effects.
    pub fn effects(&self) -> &[EffectRecord] {
        &self.effects
    }

    /// Returns complete canonical header bytes for independent identity reproduction.
    pub fn canonical_header(&self) -> Result<Vec<u8>, ArtifactError> {
        encode_artifact_header(&self.header)
    }
}

/// Identity construction has no self reference in its canonical header.
#[cfg(all(test, feature = "experimental-profiles"))]
mod tests {
    use crate::{DecodeLimits, decode_artifact_header, encode_artifact_header};

    /// Header identity excludes itself while binding both state commitments.
    #[test]
    fn artifact_identity_has_no_cycle() {
        let bytes = include_bytes!("../../fixtures/reference-v1/artifact_header.bin");
        let mut header = decode_artifact_header(bytes, DecodeLimits::reference()).unwrap();
        assert_eq!(encode_artifact_header(&header).unwrap(), bytes);
        let original = houseki_crypto::ledger_execution_artifact(bytes).unwrap();
        header.post_state = crate::StateCommitment::from_bytes([8; 64]);
        assert_ne!(
            houseki_crypto::ledger_execution_artifact(&encode_artifact_header(&header).unwrap())
                .unwrap(),
            original
        );
    }
}
