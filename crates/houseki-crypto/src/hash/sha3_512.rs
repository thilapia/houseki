//! SHA3-512 hashing of streamed public transcripts.

use sha3::{Digest, Sha3_512};

/// Hashes streamed public transcript bytes and releases no digest on failure.
///
/// Domain and canonical encoding selection belong to the invoking operation.
pub(crate) fn sha3_512<E>(
    emit: impl FnOnce(&mut dyn FnMut(&[u8])) -> Result<(), E>,
) -> Result<[u8; 64], E> {
    let mut hasher = Sha3_512::new();
    emit(&mut |chunk| hasher.update(chunk))?;

    Ok(hasher.finalize().into())
}

/// NIST SHA3-512 vectors and fallible streaming behavior.
#[cfg(test)]
mod tests {
    use super::sha3_512;

    /// Formats public fixture bytes as lowercase hexadecimal.
    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    /// Checks SHA3-512 against the NIST empty message vector.
    #[test]
    fn nist_empty_message_known_answer() {
        // NIST SHA3-512_Msg0.pdf, final "Hash val".
        // https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA3-512_Msg0.pdf
        let digest = sha3_512(|_| Ok::<_, ()>(())).unwrap();

        assert_eq!(
            hex(&digest),
            concat!(
                "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a6",
                "15b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"
            )
        );
    }

    /// Checks the NIST vector across different emission boundaries.
    #[test]
    fn nist_1600_bit_known_answer_is_independent_of_stream_boundaries() {
        // NIST SHA3-512_1600.pdf, 200 bytes of A3, final "Hash val".
        // https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA3-512_1600.pdf
        let message = [0xa3; 200];
        for chunk_size in [1, 71, 72, 73, 200] {
            let digest = sha3_512(|sink| {
                sink(&[]);
                for chunk in message.chunks(chunk_size) {
                    sink(chunk);
                    sink(&[]);
                }

                Ok::<_, ()>(())
            })
            .unwrap();

            assert_eq!(
                hex(&digest),
                concat!(
                    "e76dfad22084a8b1467fcf2ffa58361bec7628edf5f3fdc0e4805dc48caeeca8",
                    "1b7c13c30adf52a3659584739a2df46be589c51ca1a4a8416df6545a1ce8ba00"
                )
            );
        }
    }

    /// Checks that a failed emitter never returns a partial digest.
    #[test]
    fn emission_errors_release_no_digest_even_after_a_prefix() {
        assert_eq!(
            sha3_512(|sink| {
                sink(b"prefix");
                Err(17)
            }),
            Err(17)
        );
    }
}
