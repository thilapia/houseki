//! Fixed application permutation geometry shared by constraints and assignment.

/// Number of coordinates in the pinned Goldilocks permutation.
pub(super) const WIDTH: usize = 16;

/// Number of seventh powers across eight full rounds and twenty two partial rounds.
pub(super) const SBOXES: usize = 8 * WIDTH + 22;
