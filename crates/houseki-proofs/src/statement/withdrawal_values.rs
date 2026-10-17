//! Borrowed semantic fields of the frozen withdrawal public vector.

/// Names expected public endpoints without accepting or deriving a statement from witness data.
pub(crate) struct WithdrawalValues<'a, T> {
    /// Exact validated public vector supplied by the caller's statement context.
    values: &'a [T; 144],
}

impl<'a, T> WithdrawalValues<'a, T> {
    /// Number of byte cells in the V1 withdrawal public vector.
    pub(crate) const LENGTH: usize = 144;

    /// Accepts only the exact frozen shape without allocating or changing any cell.
    pub(crate) fn new(values: &'a [T]) -> Option<Self> {
        Some(Self {
            values: values.try_into().ok()?,
        })
    }

    /// Borrows the transaction's expected network bytes.
    pub(crate) fn network(&self) -> &'a [T; 64] {
        self.values[..64].try_into().unwrap()
    }

    /// Borrows all sixteen public amount bytes without reducing their integer value.
    pub(crate) fn amount(&self) -> &'a [T; 16] {
        self.values[64..80].try_into().unwrap()
    }

    /// Borrows the sole expected output commitment.
    pub(crate) fn commitment(&self) -> &'a [T; 64] {
        self.values[80..].try_into().unwrap()
    }
}

/// Exact shape and borrowed field locations.
#[cfg(test)]
mod tests {
    use super::*;

    /// Every endpoint names its frozen byte positions and rejects truncated or extended storage.
    #[test]
    fn withdrawal_view_preserves_exact_fields_and_length() {
        let values: Vec<_> = (0..145).collect();
        let view = WithdrawalValues::new(&values[..144]).unwrap();
        assert_eq!(view.network(), &values[..64]);
        assert_eq!(view.amount(), &values[64..80]);
        assert_eq!(view.commitment(), &values[80..144]);
        assert!(std::ptr::eq(view.network().as_ptr(), values.as_ptr()));
        for length in [0, 143, 145] {
            assert!(WithdrawalValues::new(&values[..length]).is_none());
        }
    }
}
