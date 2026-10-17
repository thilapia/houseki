//! Native note output reference relations with explicitly bounded responsibilities.

mod withdrawal_output;

pub use withdrawal_output::{WithdrawalOutputRelationError, check_withdrawal_output};
