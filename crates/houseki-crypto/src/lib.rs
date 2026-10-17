//! Cryptographic types and reusable operations for Houseki.

#![warn(missing_docs, clippy::missing_docs_in_private_items)]

mod domain;
mod hash;
mod identity;
mod ml_dsa_87;
mod ml_kem_1024;
mod ownership;
mod random;
mod suite;

pub use domain::CryptoFramingError;
pub use identity::{BodyHashError, payment_transaction_id, withdrawal_transaction_id};
pub use ml_dsa_87::{
    MlDsa87SigningKey, MlDsa87SigningKeyError, MlDsa87VerificationKey, WithdrawalSignatureError,
};
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
