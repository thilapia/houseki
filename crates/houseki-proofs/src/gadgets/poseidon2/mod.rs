//! Constraints for the fixed application hash transcript and its field encoding.

mod extraction;
#[cfg(test)]
mod framed_sponge_air;
mod framing;
#[cfg(test)]
mod hash_air;
mod linear;
mod permutation;
#[cfg(test)]
mod permutation_air;
mod profile;
#[cfg(test)]
mod recipient_hash_air;
mod scheduled;
mod sponge;

#[cfg(test)]
pub(crate) use extraction::ExtractionRowAir;
#[cfg(test)]
pub(crate) use framed_sponge_air::FramedSpongeAir;
pub(crate) use framing::Frame;
#[cfg(test)]
pub(crate) use framing::{BlockAir, FramingAir};
#[cfg(test)]
pub(crate) use hash_air::HashAir;
#[cfg(test)]
pub(crate) use permutation_air::PermutationAir;
#[cfg(test)]
pub(crate) use recipient_hash_air::RecipientHashAir;

#[cfg_attr(
    not(test),
    expect(
        unused_imports,
        reason = "note consumers follow in the next semantic commit"
    )
)]
pub(crate) use scheduled::ScheduledHash;
