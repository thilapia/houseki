//! Trusted snapshot ownership and complete public replay representations.

mod archive;
mod expected;
mod image;
mod native;
pub use archive::ReplayArchive;
pub(crate) use expected::ExpectedCheckpoint;
pub(crate) use image::StoreImage;
pub(crate) use native::NativeCheckpoint;
