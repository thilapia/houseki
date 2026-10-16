//! Shared DAG and consensus values.

mod validator_id;
mod vertex_id;

pub use validator_id::{ValidatorId, ValidatorIdError};
pub use vertex_id::{VertexId, VertexIdError};
