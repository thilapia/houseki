//! Cryptographic types and reusable operations for Houseki.

#![warn(missing_docs, clippy::missing_docs_in_private_items)]

mod address_checksum;
mod domain;
mod hash;
mod identity;
mod ledger;
mod ml_dsa_87;
mod ml_kem_1024;
mod note_tree;
mod ownership;
mod random;
mod suite;

pub use address_checksum::recipient_descriptor_checksum;
pub use domain::CryptoFramingError;
pub use identity::{BodyHashError, payment_transaction_id, withdrawal_transaction_id};
pub use ledger::{
    ledger_execution_artifact, ledger_execution_policy, ledger_fixture_order_stream,
    ledger_fixture_order_unit, ledger_ordered_occurrences, ledger_public_effects, ledger_receipts,
    ledger_reference_state, ledger_system_events,
};
pub use ml_dsa_87::{
    MlDsa87SigningKey, MlDsa87SigningKeyError, MlDsa87VerificationKey, WithdrawalSignatureError,
};
pub use ml_kem_1024::{
    MlKem1024DecapsulationKey, MlKem1024DecapsulationKeyError, MlKem1024EncapsulationError,
    MlKem1024EncapsulationKey, MlKem1024EncapsulationKeyError, MlKem1024SharedSecret,
};
pub use note_tree::{
    NoteTreeHashError, note_membership_root, note_tree_empty_leaf, note_tree_leaf,
    note_tree_parent, note_tree_root,
};
pub use ownership::{NullifierKey, NullifierKeyError, SpendingKey, SpendingKeyError};
pub use suite::{
    CryptoSuite, CryptoSuiteError, NoteDecryptionError, NoteEncryptionContext,
    NoteEncryptionContextError, NoteEncryptionError, NotePayloadError, PaymentEncryptionCore,
    PaymentEncryptionCoreError, RewardWithdrawalEncryptionCore,
    RewardWithdrawalEncryptionCoreError,
};
