//! Single ownership of a caller's cancellation token through validation and backend work.

use super::CancellationToken;

/// A consumed attempt reservation that cannot be cloned or reconstructed after validation fails.
pub(crate) struct Attempt<'a> {
    /// Original cancellation state shared with lifecycle callbacks.
    token: &'a CancellationToken,
}

impl<'a> Attempt<'a> {
    /// Claims the token before public statement or private witness preparation.
    pub(crate) fn new(token: &'a CancellationToken) -> Option<Self> {
        token.claim().then_some(Self { token })
    }

    /// Borrows cancellation state without restoring permission to start another attempt.
    pub(crate) fn token(&self) -> &'a CancellationToken {
        self.token
    }
}

/// Token consumption is independent of how far a failed request progresses.
#[cfg(test)]
mod tests {
    use super::*;

    /// A failed validation path cannot recycle its caller token for a different request.
    #[test]
    fn attempt_reservation_survives_early_failure() {
        let token = CancellationToken::new();
        {
            let attempt = Attempt::new(&token).unwrap();
            assert!(std::ptr::eq(attempt.token(), &token));
        }

        assert!(Attempt::new(&token).is_none());
        assert!(!token.is_cancelled());
    }

    /// A pre-cancelled token never starts private work.
    #[test]
    fn cancelled_attempt_cannot_be_reserved() {
        let token = CancellationToken::new();
        token.cancel();

        assert!(Attempt::new(&token).is_none());
    }
}
