//! Full width digest adapters for the fixed hiding backend.

mod byte;
mod field;
mod word;

pub(super) use byte::ByteHash;
pub(super) use field::FieldHash;
pub(super) use word::WordHash;

/// Reinterprets the complete digest as eight portable little endian words.
fn words(bytes: [u8; 64]) -> [u64; 8] {
    std::array::from_fn(|index| {
        u64::from_le_bytes(
            bytes[index * 8..index * 8 + 8]
                .try_into()
                .expect("fixed word"),
        )
    })
}
