//! Constraints for the fixed application hash transcript and its field encoding.

mod framing;

pub(crate) use framing::Frame;
#[cfg(test)]
pub(crate) use framing::FramingAir;
