//! Sealed trait marker for Transport implementations.
//!
//! This module prevents external implementations of the `Transport` trait,
//! ensuring all transport implementations undergo security review.

pub(crate) mod private {
    /// Sealed trait marker.
    ///
    /// This trait cannot be implemented outside this crate, preventing
    /// external Transport implementations that might bypass TAP security.
    pub trait Sealed {}
}
