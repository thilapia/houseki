//! Native withdrawal body checks and semantic public value construction.

use super::{Statement, StatementError, WithdrawalValues, bind, require_identity, reserve};
use crate::{
    context::require_context,
    profile::{ExpectedIdentity, Relation},
};
use houseki_types::{RewardWithdrawalBody, TransactionContext};

impl Statement {
    /// Derives the public amount and sole output without asserting account authorization.
    pub(crate) fn withdrawal(
        body: &RewardWithdrawalBody,
        expected: TransactionContext,
        identity: &ExpectedIdentity,
    ) -> Result<Self, StatementError> {
        require_context(expected, body.context()).map_err(|_| StatementError::ContextMismatch)?;
        require_identity(identity, expected, Relation::RewardWithdrawal, 1)?;

        let body_bytes = body.to_bytes(crate::profile::reward_withdrawal::body_limits())?;

        let mut public = reserve(WithdrawalValues::<u8>::LENGTH)?;
        public.extend_from_slice(expected.network_id().as_bytes());
        public.extend_from_slice(&body.public_amount().atoms().to_le_bytes());
        public.extend_from_slice(body.output().commitment().as_bytes());

        bind(identity, &body_bytes, &[], &public)
    }
}
