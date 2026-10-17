//! Public synthetic inputs shared by constraint and cryptographic opening tests.

use super::{Input, Opening};
use p3_field::PrimeCharacteristicRing;
use p3_goldilocks::Goldilocks;

/// Owns only reproducible public test data, never a caller's native secrets.
pub(crate) struct OpeningFixture {
    /// Full native staging layout with canonical zero coefficients.
    pub(crate) input: [Goldilocks; 1756],

    /// Frozen withdrawal network, amount and independent commitment vector.
    pub(crate) public: [Goldilocks; 144],
}

impl OpeningFixture {
    /// Selects one of three independently recorded native commitment vectors.
    pub(crate) fn new(case: usize) -> Self {
        let mut input = [Goldilocks::ZERO; 1756];
        for index in [0, 4, 72, 1708] {
            input[index] = Goldilocks::ONE;
        }

        let digest = match case {
            0 => concat!(
                "67519504e20c7223a5068feae0c831bdfe180fcc11b6b597c5d8a4506d592c41",
                "decf8a6608538e3c875bcd61322d8a832f554417b2bc5a32f4cde0454adb20f0"
            ),
            1 => {
                for index in 0..64 {
                    input[8 + index] = Goldilocks::from_usize(index);
                    input[76 + index] = Goldilocks::from_usize(64 + index);
                }

                input[1676..1708].fill(Goldilocks::from_u8(0xa5));
                input[1708..1724].copy_from_slice(
                    &((1_u128 << 64) + 0x01020304)
                        .to_le_bytes()
                        .map(Goldilocks::from_u8),
                );
                for index in 0..32 {
                    input[1724 + index] = Goldilocks::from_usize(index);
                }

                concat!(
                    "e4d71a009781bebee473503ea001250799bbe6993cd0f8abd19af0831ebfd7bc9",
                    "613c3c3e38b39b64f3e2669430253fe98e152ec550823b91554f89adf83ec89"
                )
            }
            2 => {
                for range in [8..72, 76..140, 1676..1708, 1724..1756] {
                    input[range].fill(Goldilocks::from_u8(255));
                }

                input[1708..1724].copy_from_slice(
                    &houseki_types::Amount::MAX_ATOMS
                        .to_le_bytes()
                        .map(Goldilocks::from_u8),
                );
                concat!(
                    "4de99cdcc2d1080fca897f80fff6e7de81859b438d21ccc9277cb9b964a14853b",
                    "d2081e4214719bfcbbbae16fdc0f529203dfb118d338517c89209e4930ad825"
                )
            }
            _ => panic!("three independent native fixtures"),
        };
        let mut public = [Goldilocks::ZERO; 144];
        public[..64].copy_from_slice(&input[8..72]);
        public[64..80].copy_from_slice(&input[1708..1724]);
        for byte in 0..64 {
            public[80 + byte] = Goldilocks::from_u8(
                u8::from_str_radix(&digest[byte * 2..byte * 2 + 2], 16).unwrap(),
            );
        }

        Self { input, public }
    }

    /// Borrows fixture inputs through the same boundary as the native adapter.
    pub(crate) fn view(&self) -> Input<'_> {
        Input::new(
            self.input[..4].try_into().unwrap(),
            self.input[4..1708].try_into().unwrap(),
            self.input[1708..1724].try_into().unwrap(),
            self.input[1724..].try_into().unwrap(),
        )
    }

    /// Recomputes both complete hashes while deliberately bypassing key and amount validation.
    ///
    /// Tests use this only after assigning an honest trace to isolate independent validity links.
    pub(crate) fn rehash(&mut self, opening: &Opening, rows: &mut [Goldilocks], substitute: bool) {
        for cycle in rows
            .as_chunks_mut::<{ Opening::CYCLE * Opening::WIDTH }>()
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
                    Opening::WIDTH,
                )
                .unwrap();
            let mut binding = [Goldilocks::ZERO; 64];
            opening
                .recipient
                .copy_digest(&cycle[176..], Opening::WIDTH, &mut binding);
            if substitute {
                binding[0] += Goldilocks::ONE;
            }

            for row in cycle.as_chunks_mut::<{ Opening::WIDTH }>().0 {
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
                    &mut cycle[52 * Opening::WIDTH + 176..],
                    Opening::WIDTH,
                )
                .unwrap();
            opening.commitment.copy_digest(
                &cycle[52 * Opening::WIDTH + 176..],
                Opening::WIDTH,
                (&mut self.public[80..]).try_into().unwrap(),
            );
        }

        self.public[..64].copy_from_slice(&self.input[8..72]);
        self.public[64..80].copy_from_slice(&self.input[1708..1724]);
    }
}
