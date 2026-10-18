//! Shared constraints and assignment helpers composed by individual circuit families.

#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "circuit amount consumers follow in later increments"
    )
)]
mod amount;
mod encoding;
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "complete payment composition follows")
)]
mod merkle;
mod notes;
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "circuit hash consumers follow in later increments"
    )
)]
mod poseidon2;
#[cfg(any(test, feature = "prover"))]
mod scratch;

#[cfg(test)]
pub(crate) use amount::{AdditionAir, AmountAir};
#[cfg(any(test, feature = "prover"))]
pub(crate) use amount::{AmountError, assign_addition, assign_amount};
pub(crate) use amount::{eval_addition, eval_amount};
#[cfg(test)]
pub(crate) use encoding::{ByteAir, BytesAir, FieldAir};
#[cfg(any(test, feature = "prover"))]
#[cfg_attr(
    not(test),
    expect(
        unused_imports,
        reason = "circuit trace builders follow in later increments"
    )
)]
pub(crate) use encoding::{EncodingError, assign_byte, assign_bytes, assign_field_bytes};
pub(crate) use encoding::{eval_byte, eval_bytes, eval_field_bytes};
#[cfg(feature = "prover")]
pub(crate) use merkle::Input as MembershipInput;
pub(crate) use merkle::{Endpoints as MembershipEndpoints, Membership};
#[cfg(any(test, feature = "prover"))]
pub(crate) use notes::OpeningInput;
#[cfg(feature = "prover")]
pub(crate) use notes::SpendInput;
pub(crate) use notes::{CompactOpening, Opening, OpeningSelectors};
#[cfg(test)]
pub(crate) use notes::{
    OpeningAir, OpeningError, OpeningFixture, PaymentOpeningAir, RecipientPairAir,
};
pub(crate) use notes::{Spend, SpendEndpoints};
#[cfg_attr(
    not(test),
    expect(
        unused_imports,
        reason = "circuit hash consumers follow in later increments"
    )
)]
pub(crate) use poseidon2::Frame as HashFrame;
#[cfg(test)]
pub(crate) use poseidon2::{
    BlockAir, ExtractionRowAir, FramedSpongeAir, FramingAir, HashAir, PermutationAir,
    RecipientHashAir,
};

#[cfg(any(test, feature = "prover"))]
pub(crate) use scratch::Scratch;
