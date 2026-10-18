//! Deterministic hostile bytes independent of the decoder's implementation.

use std::ops::Range;

/// Inclusive outer proof ceiling plus one byte used to challenge facade rejection.
pub(crate) const MAX_INPUT: usize = 2_097_153;

/// Advances a reproducible noncryptographic mutation stream with no witness randomness.
fn random(state: &mut u64) -> usize {
    assert_ne!(*state, 0);
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;

    *state as usize
}

/// Produces ten classes of header, scalar, nested frontier and complete-payload mutations.
///
/// Length repairs keep malformed nested structures reachable beyond the outer envelope check.
pub(crate) fn proof(
    original: &[u8],
    frontiers: &[usize],
    iteration: usize,
    state: &mut u64,
) -> Vec<u8> {
    let mut bytes = original.to_vec();
    let value = random(state);
    match iteration % 10 {
        0 => bytes[value % 88] ^= 1 << (value % 8),
        1 => {
            let offset = [96, 100][value % 2];
            bytes[offset..offset + 4].copy_from_slice(&u32::MAX.to_le_bytes());
        }
        2 => {
            let offset = 296 + 8 * (value % 3);
            bytes[offset..offset + 8]
                .copy_from_slice(&18_446_744_069_414_584_321_u64.to_le_bytes());
        }
        3 => {
            let offset = frontiers[value % frontiers.len()];
            bytes[offset..offset + 4].copy_from_slice(&u32::MAX.to_le_bytes());
        }
        4 => {
            bytes.truncate(value % original.len());
            repair_length(&mut bytes);
        }
        5 => {
            let length = [0, 95, 96, 2_097_151, 2_097_152, MAX_INPUT][value % 6];
            bytes.resize(length, 0);
            repair_length(&mut bytes);
        }
        7 | 8 => {
            let offset = frontiers[value % frontiers.len()];
            let count = u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap());
            if count > 0 {
                let node = offset + 4;
                if iteration % 10 == 7 {
                    bytes.drain(node..node + 64);
                    bytes[offset..offset + 4].copy_from_slice(&(count - 1).to_le_bytes());
                } else {
                    let duplicate = bytes[node..node + 64].to_vec();
                    bytes.splice(node..node, duplicate);
                    bytes[offset..offset + 4].copy_from_slice(&(count + 1).to_le_bytes());
                }

                repair_length(&mut bytes);
            } else {
                bytes[offset..offset + 4].copy_from_slice(&1_u32.to_le_bytes());
            }
        }
        _ => {
            for _ in 0..if iteration % 10 == 6 { 1 } else { 8 } {
                let value = random(state);
                let offset = 104 + value % (bytes.len() - 104);
                bytes[offset] ^= 1 << ((value >> 8) % 8);
            }
        }
    }

    assert!(bytes.len() <= MAX_INPUT);

    bytes
}

/// Updates only the outer payload count after a deliberate structural mutation.
fn repair_length(bytes: &mut [u8]) {
    if bytes.len() >= 96 {
        let length = (bytes.len() - 96) as u64;
        bytes[88..96].copy_from_slice(&length.to_le_bytes());
    }
}

/// Returns every field occurrence in the published body layout, including opaque envelopes.
pub(crate) fn body_regions(
    bytes: &[u8],
    inputs: Option<usize>,
    payloads: &[usize],
) -> Vec<Range<usize>> {
    let mut regions = vec![0..4, 4..8, 8..72, 72..76, 76..80, 80..84, 84..92, 92..100];
    let mut cursor = if let Some(inputs) = inputs {
        regions.extend([100..164, 164..172]);
        for index in 0..inputs {
            regions.push(172 + index * 64..236 + index * 64);
        }

        let fee = 172 + 64 * inputs;
        regions.extend([fee..fee + 16, fee + 16..fee + 24]);

        fee + 24
    } else {
        regions.extend([100..164, 164..2756, 2756..2764, 2764..2780, 2780..2796]);

        2796
    };
    for payload in payloads {
        regions.extend([
            cursor..cursor + 64,
            cursor + 64..cursor + 1632,
            cursor + 1632..cursor + 1640,
        ]);
        let start = cursor + 1640;
        let end = start + payload;
        if *payload >= 32 {
            regions.extend([start..start + 4, start + 4..start + 16]);
            if *payload > 32 {
                regions.push(start + 16..end - 16);
            }

            regions.push(end - 16..end);
        } else if *payload > 0 {
            regions.push(start..end);
        }

        cursor += 1640 + payload;
    }

    assert_eq!(cursor, bytes.len());

    regions
}

/// Checks literal wire positions and hostile nested counts without invoking the target decoder.
#[cfg(test)]
mod tests {
    use super::*;

    /// The fourth nullifier and both complete envelopes receive independent mutation regions.
    #[test]
    fn priority_body_regions_cover_each_occurrence() {
        let regions = body_regions(&vec![0; 3738], Some(4), &[3, 3]);

        assert!(regions.contains(&(364..428)));
        assert!(regions.contains(&(452..516)));
        assert!(regions.contains(&(516..2084)));
        assert!(regions.contains(&(2092..2095)));
        assert!(regions.contains(&(2159..3727)));
        assert!(regions.contains(&(3735..3738)));
        assert_eq!(regions.len(), 24);
    }

    /// Encrypted payload suite, nonce, ciphertext and tag are challenged separately.
    #[test]
    fn encrypted_payload_regions_include_nonce_ciphertext_and_tag() {
        let regions = body_regions(&vec![0; 1964], Some(1), &[64]);

        for expected in [1900..1904, 1904..1916, 1916..1948, 1948..1964] {
            assert!(regions.contains(&expected), "missing region {expected:?}");
        }
    }

    /// Forged nested counts preserve the outer header so the decoder must inspect them.
    #[test]
    fn hostile_frontier_keeps_outer_length_valid() {
        let mut original = vec![0; 400];
        repair_length(&mut original);
        let changed = proof(&original, &[320], 3, &mut 7);

        assert_eq!(&changed[88..96], &304_u64.to_le_bytes());
        assert_eq!(&changed[320..324], &u32::MAX.to_le_bytes());
        assert_eq!(changed.len(), 400);
    }
}
