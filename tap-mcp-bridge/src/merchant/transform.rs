//! Request/response transformation utilities.
//!
//! This module provides types and utilities for transforming requests and responses.

/// Operation type for context in transformations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operation {
    /// Get products catalog.
    GetProducts,
    /// Get single product.
    GetProduct,
    /// Get cart state.
    GetCart,
    /// Add item to cart.
    AddToCart,
    /// Update cart item quantity.
    UpdateCartItem,
    /// Remove item from cart.
    RemoveCartItem,
    /// Create order.
    CreateOrder,
    /// Get order details.
    GetOrder,
    /// Process payment.
    ProcessPayment,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_operation_equality() {
        assert_eq!(Operation::GetProducts, Operation::GetProducts);
        assert_ne!(Operation::GetProducts, Operation::GetProduct);
    }

    #[test]
    fn test_operation_all_variants() {
        let operations = vec![
            Operation::GetProducts,
            Operation::GetProduct,
            Operation::GetCart,
            Operation::AddToCart,
            Operation::UpdateCartItem,
            Operation::RemoveCartItem,
            Operation::CreateOrder,
            Operation::GetOrder,
            Operation::ProcessPayment,
        ];

        assert_eq!(operations.len(), 9);
    }

    #[test]
    fn test_operation_clone() {
        let op = Operation::AddToCart;
        let cloned = op;
        assert_eq!(op, cloned);
    }

    #[test]
    fn test_operation_debug() {
        let op = Operation::GetProducts;
        let debug_str = format!("{op:?}");
        assert!(debug_str.contains("GetProducts"));
    }
}
