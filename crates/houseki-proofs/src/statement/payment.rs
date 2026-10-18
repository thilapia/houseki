//! Native payment body checks and semantic public value construction.

use super::{PaymentValues, Statement, StatementError, bind, require_identity, reserve};
use crate::{
    context::require_context,
    profile::{ExpectedIdentity, Relation, payment::SupportedPaymentShape},
};
use houseki_types::{BodyCodecLimits, NoteTreeAnchor, PaymentBody, TransactionContext};

impl Statement {
    /// Derives payment effects only after checking expected context, shape and anchor.
    pub(crate) fn payment(
        body: &PaymentBody,
        anchor: &NoteTreeAnchor,
        expected: TransactionContext,
        identity: &ExpectedIdentity,
        limits: BodyCodecLimits,
    ) -> Result<Self, StatementError> {
        require_context(expected, body.context()).map_err(|_| StatementError::ContextMismatch)?;

        let inputs = body.inputs().input_count();
        let outputs = body.outputs().output_count();
        let shape = SupportedPaymentShape::new(inputs, outputs)
            .map_err(|_| StatementError::UnsupportedShape)?;

        if anchor.network_id() != expected.network_id() || anchor.root() != body.inputs().anchor() {
            return Err(StatementError::AnchorMismatch);
        }

        if anchor.count().value() == 0 {
            return Err(StatementError::EmptyAnchor);
        }

        require_identity(identity, expected, Relation::Payment, shape.code())?;

        let body_bytes = body.to_bytes(limits)?;

        let nullifiers = body.inputs().nullifiers();
        for index in 0..nullifiers.len() {
            if nullifiers[..index].contains(&nullifiers[index]) {
                return Err(StatementError::DuplicateNullifier);
            }
        }

        let mut public = reserve(
            PaymentValues::<u8>::length(shape.inputs(), shape.outputs()).expect("validated shape"),
        )?;
        public.extend_from_slice(expected.network_id().as_bytes());
        public.extend_from_slice(anchor.root().as_bytes());
        public.extend_from_slice(&anchor.count().value().to_le_bytes());
        public.extend_from_slice(&body.public_fee().atoms().to_le_bytes());
        for marker in nullifiers {
            public.extend_from_slice(marker.as_bytes());
        }

        for output in body.outputs().outputs() {
            public.extend_from_slice(output.commitment().as_bytes());
        }

        bind(
            identity,
            &body_bytes,
            &anchor.count().value().to_le_bytes(),
            &public,
        )
    }
}
