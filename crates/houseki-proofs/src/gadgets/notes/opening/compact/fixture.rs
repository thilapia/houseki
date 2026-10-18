//! Coordinated malicious fixtures for independent compact-opening checks.

use super::CompactOpening;
use crate::gadgets::OpeningFixture;
use p3_field::PrimeCharacteristicRing;
use p3_goldilocks::Goldilocks;

impl OpeningFixture {
    /// Recomputes both complete hashes while deliberately bypassing key and amount validation.
    ///
    /// Tests use this only after assigning an honest trace to isolate independent validity links.
    pub(super) fn rehash_compact(
        &mut self,
        opening: &CompactOpening,
        rows: &mut [Goldilocks],
        substitute: bool,
    ) {
        for cycle in rows
            .as_chunks_mut::<{ CompactOpening::CYCLE * CompactOpening::WIDTH }>()
            .0
        {
            opening
                .recipient
                .assign(
                    &[
                        &self.input[8..72],
                        &self.input[72..76],
                        &self.input[140..1708],
                    ],
                    &mut cycle[176..],
                    CompactOpening::WIDTH,
                )
                .unwrap();
            let mut binding = [Goldilocks::ZERO; 64];
            opening
                .recipient
                .copy_digest(&cycle[176..], CompactOpening::WIDTH, &mut binding);
            if substitute {
                binding[0] += Goldilocks::ONE;
            }

            for row in cycle.as_chunks_mut::<{ CompactOpening::WIDTH }>().0 {
                row[..64].copy_from_slice(&self.input[76..140]);
                row[64..80].copy_from_slice(&self.input[1708..1724]);
                row[80..112].copy_from_slice(&self.input[1724..]);
                row[112..176].copy_from_slice(&binding);
            }

            opening
                .commitment
                .assign(
                    &[
                        &self.input[8..72],
                        &self.input[..4],
                        &self.input[76..140],
                        &binding,
                        &self.input[1708..1724],
                        &self.input[1724..],
                    ],
                    &mut cycle[52 * CompactOpening::WIDTH + 176..],
                    CompactOpening::WIDTH,
                )
                .unwrap();
            opening.commitment.copy_digest(
                &cycle[52 * CompactOpening::WIDTH + 176..],
                CompactOpening::WIDTH,
                (&mut self.public[80..]).try_into().unwrap(),
            );
        }

        self.public[..64].copy_from_slice(&self.input[8..72]);
        self.public[64..80].copy_from_slice(&self.input[1708..1724]);
    }
}
