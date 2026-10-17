//! Streaming encoding of registered cryptographic transcripts.

use super::{CryptoFramingError, Domain};

/// Streams a length prefixed transcript without buffering it in full.
///
/// The header encodes the registered ASCII label with its u16 length, followed by the u32 part
/// count.
///
/// Each caller supplied canonical part then carries a `u64` byte length, even when empty, with
/// all integers encoded in little endian order.
///
/// Because a failed frame may already have emitted a prefix, the sink's result is usable only
/// after `finish` succeeds.
pub(crate) struct Frame<'a> {
    /// Receives each encoded chunk in transcript order.
    sink: &'a mut dyn FnMut(&[u8]),

    /// Number of declared parts still to be emitted.
    remaining: u32,
}

impl<'a> Frame<'a> {
    /// Writes the registered domain and declared part count to the sink.
    pub(crate) fn new(domain: Domain, part_count: u32, sink: &'a mut dyn FnMut(&[u8])) -> Self {
        let label = domain.label();
        let label_length =
            u16::try_from(label.len()).expect("registered Houseki domain labels fit in a u16");

        sink(&label_length.to_le_bytes());
        sink(label);
        sink(&part_count.to_le_bytes());

        Self {
            sink,
            remaining: part_count,
        }
    }

    /// Writes one length prefix and its bytes.
    ///
    /// Returns an error before emission if the declared count is exhausted or the length
    /// exceeds u64.
    pub(crate) fn part(&mut self, bytes: &[u8]) -> Result<(), CryptoFramingError> {
        if self.remaining == 0 {
            return Err(CryptoFramingError::PartCountMismatch);
        }

        let length = u64::try_from(bytes.len()).map_err(|_| CryptoFramingError::PartTooLong)?;
        (self.sink)(&length.to_le_bytes());
        (self.sink)(bytes);

        self.remaining -= 1;

        Ok(())
    }

    /// Confirms that every declared part was emitted.
    ///
    /// Returns a count mismatch if the transcript is incomplete.
    pub(crate) fn finish(self) -> Result<(), CryptoFramingError> {
        if self.remaining != 0 {
            return Err(CryptoFramingError::PartCountMismatch);
        }

        Ok(())
    }
}

/// Exact transcript bytes, part boundaries and count failures.
#[cfg(test)]
mod tests {
    use super::{CryptoFramingError, Domain, Frame};

    /// Collects a frame under the core domain for byte comparisons.
    fn encode(parts: &[&[u8]]) -> Vec<u8> {
        let mut bytes = Vec::new();
        let mut sink = |chunk: &[u8]| bytes.extend_from_slice(chunk);
        let mut frame = Frame::new(
            Domain::NoteEncryptionCore,
            u32::try_from(parts.len()).unwrap(),
            &mut sink,
        );
        for part in parts {
            frame.part(part).unwrap();
        }

        frame.finish().unwrap();

        bytes
    }

    /// Checks exact frame bytes for empty and nonempty parts.
    #[test]
    fn exact_domain_and_length_prefixes_include_empty_parts() {
        let expected = b"\x1f\x00houseki/v1/note/encryption-core\x03\x00\x00\x00\
            \x00\x00\x00\x00\x00\x00\x00\x00\
            \x02\x00\x00\x00\x00\x00\x00\x00ab\
            \x01\x00\x00\x00\x00\x00\x00\x00c";

        assert_eq!(encode(&[b"", b"ab", b"c"]), expected);
        assert_eq!(
            encode(&[]),
            b"\x1f\x00houseki/v1/note/encryption-core\x00\x00\x00\x00"
        );
    }

    /// Checks that distinct part structures produce distinct frames.
    #[test]
    fn boundaries_order_counts_and_multiplicity_are_unambiguous() {
        let cases: &[&[&[u8]]] = &[
            &[],
            &[b""],
            &[b"", b""],
            &[b"ab", b"c"],
            &[b"a", b"bc"],
            &[b"c", b"ab"],
            &[b"abc"],
            &[b"abc", b"abc"],
        ];

        let encodings: Vec<_> = cases.iter().map(|parts| encode(parts)).collect();

        for (index, encoding) in encodings.iter().enumerate() {
            for other in &encodings[index + 1..] {
                assert_ne!(encoding, other);
            }
        }
    }

    /// Checks integer width and byte order in frame prefixes.
    #[test]
    fn counts_and_lengths_use_all_little_endian_bytes() {
        let mut bytes = Vec::new();
        let mut sink = |chunk: &[u8]| bytes.extend_from_slice(chunk);
        let frame = Frame::new(Domain::NoteEncryptionCore, 0x01020304, &mut sink);

        assert_eq!(frame.finish(), Err(CryptoFramingError::PartCountMismatch));
        assert_eq!(&bytes[33..37], &[4, 3, 2, 1]);

        let part = vec![0x55; 0x0102];
        let encoded = encode(&[&part]);

        assert_eq!(&encoded[37..45], &[2, 1, 0, 0, 0, 0, 0, 0]);
        assert_eq!(&encoded[45..], part);
    }

    /// Checks rejection of missing and excess declared parts.
    #[test]
    fn incomplete_and_excess_parts_are_rejected() {
        let mut sink = |_: &[u8]| {};
        let mut incomplete = Frame::new(Domain::NoteEncryptionCore, 2, &mut sink);
        incomplete.part(b"first").unwrap();

        assert_eq!(
            incomplete.finish(),
            Err(CryptoFramingError::PartCountMismatch)
        );

        let mut bytes = Vec::new();
        let mut sink = |chunk: &[u8]| bytes.extend_from_slice(chunk);
        let mut excess = Frame::new(Domain::NoteEncryptionCore, 0, &mut sink);

        assert_eq!(
            excess.part(b"unexpected"),
            Err(CryptoFramingError::PartCountMismatch)
        );
        assert_eq!(bytes, encode(&[]));
    }
}
