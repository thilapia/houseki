//! Native note output reference relations with explicitly bounded responsibilities.

mod payment;
mod spend;
mod withdrawal_output;
mod witness;

pub use payment::{PaymentRelationError, check_payment};
pub use spend::{SpendRelationError, check_spend};
pub use withdrawal_output::{WithdrawalOutputRelationError, check_withdrawal_output};
pub use witness::SpendWitness;
