use super::{CryptoFramingError, Domain};

/// Streams one frame without allocating a transcript buffer.
///
/// Emits `u16_le(label length) || label || u32_le(part count)`, followed by
/// `u64_le(part length) || part` for each ordered part, including empty parts.
/// Labels come only from the fixed domain registry. Parts must already have
/// their operation's canonical byte representation. Lengths must fit their
/// encoded widths, and the emitted part count must match the declaration.
///
/// A failed operation can have emitted a prefix. Its consumer must discard
/// that output on any error and must call `finish` before using the result.
pub(crate) struct Frame<'a> {
    sink: &'a mut dyn FnMut(&[u8]),
    remaining: u32,
}

impl<'a> Frame<'a> {
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

    pub(crate) fn finish(self) -> Result<(), CryptoFramingError> {
        if self.remaining != 0 {
            return Err(CryptoFramingError::PartCountMismatch);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{CryptoFramingError, Domain, Frame};

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
