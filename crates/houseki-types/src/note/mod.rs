//! Shared public values for notes and their encrypted envelopes.

mod encoded_ml_kem_1024_ciphertext;
mod position;

pub use encoded_ml_kem_1024_ciphertext::{
    EncodedMlKem1024Ciphertext, EncodedMlKem1024CiphertextError,
};
pub use position::NotePosition;
