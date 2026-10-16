//! Public reward account records.

use super::{EncodedMlDsa87PublicKey, WithdrawalNonce};
use crate::Amount;

/// A declared reward account state with its withdrawal authority, balance and nonce.
///
/// The authority is an encoded ML-DSA-87 public key that remains fixed throughout
/// the account's lifetime. The balance is bounded by [`Amount`], and the next
/// nonce identifies the withdrawal counter expected by execution. An exhausted
/// nonce remains representable so that existing account state can be retained.
///
/// Construction preserves supplied values without registering an account or
/// authenticating its state. Consumers must derive and check the corresponding
/// [`super::RewardAccountId`] under the intended network and selected profile.
/// The identifier is kept separately from this record, as the state lookup key.
///
/// State transitions must preserve the authority. Withdrawal execution must
/// check signatures and gross affordability, then update balances and nonces
/// atomically with note insertion and fee credit. This record provides no
/// mutation operations, initial nonce policy, wire encoding or evidence that
/// a withdrawal is authorized.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RewardAccount {
    withdrawal_authority: EncodedMlDsa87PublicKey,
    balance: Amount,
    next_nonce: WithdrawalNonce,
}

impl RewardAccount {
    /// Groups declared account state without registering or authenticating it.
    pub const fn new(
        withdrawal_authority: EncodedMlDsa87PublicKey,
        balance: Amount,
        next_nonce: WithdrawalNonce,
    ) -> Self {
        Self {
            withdrawal_authority,
            balance,
            next_nonce,
        }
    }

    /// Borrows the encoded public key declared as the immutable authority.
    pub const fn withdrawal_authority(&self) -> &EncodedMlDsa87PublicKey {
        &self.withdrawal_authority
    }

    /// Returns the declared public reward balance.
    pub const fn balance(&self) -> Amount {
        self.balance
    }

    /// Returns the declared next withdrawal nonce, including exhaustion.
    pub const fn next_nonce(&self) -> WithdrawalNonce {
        self.next_nonce
    }

    /// Consumes the record and returns its authority, balance and next nonce.
    pub fn into_parts(self) -> (EncodedMlDsa87PublicKey, Amount, WithdrawalNonce) {
        (self.withdrawal_authority, self.balance, self.next_nonce)
    }
}
