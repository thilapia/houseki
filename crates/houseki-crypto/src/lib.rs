//! Cryptographic types and reusable operations for Houseki.

#![warn(missing_docs, clippy::missing_docs_in_private_items)]

mod domain;
mod hash;
mod ml_kem_1024;
mod ownership;
mod random;
mod suite;

pub use domain::CryptoFramingError;
pub use ml_kem_1024::{
    MlKem1024DecapsulationKey, MlKem1024DecapsulationKeyError, MlKem1024EncapsulationError,
    MlKem1024EncapsulationKey, MlKem1024EncapsulationKeyError, MlKem1024SharedSecret,
};
pub use ownership::{NullifierKey, NullifierKeyError, SpendingKey, SpendingKeyError};
pub use suite::{
    CryptoSuite, CryptoSuiteError, NoteDecryptionError, NoteEncryptionContext,
    NoteEncryptionContextError, NoteEncryptionError, NotePayloadError, PaymentEncryptionCore,
    PaymentEncryptionCoreError, RewardWithdrawalEncryptionCore,
    RewardWithdrawalEncryptionCoreError,
};
