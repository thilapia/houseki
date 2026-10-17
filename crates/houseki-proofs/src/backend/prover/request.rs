//! Trusted public inputs and dimensions selected for a private proof attempt.

use p3_goldilocks::Goldilocks;

use crate::{backend::codec, profile::ExpectedIdentity};

/// Already selected public relation inputs and trusted output dimensions.
pub(crate) struct Request<'a, A> {
    /// Complete public transcript prefix.
    pub(crate) prefix: &'a [u8],

    /// Internal relation selected by trusted dispatch.
    pub(crate) air: &'a A,

    /// Independently computed public field values.
    pub(crate) public: &'a [Goldilocks],

    /// Exact expected envelope identity.
    pub(crate) identity: &'a ExpectedIdentity,

    /// Trusted dimensions used by the bounded codec.
    pub(crate) layout: codec::Layout,
}
