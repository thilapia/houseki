//! Full canonical recovery context retained by accepted output queries.

use houseki_types::{PaymentBody, RewardWithdrawalBody};

/// Borrowed original accepted body with no proof, signature or wallet secret exposure.
#[derive(Debug, Clone, Copy)]
pub enum OutputBody<'a> {
    /// Complete payment body needed by native output slot recovery.
    Payment(
        /// Exact original accepted body.
        &'a PaymentBody,
    ),

    /// Complete withdrawal body needed by native note recovery.
    RewardWithdrawal(
        /// Exact original accepted body.
        &'a RewardWithdrawalBody,
    ),
}
