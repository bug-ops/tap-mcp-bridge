//! E-commerce data models for TAP-MCP bridge.
//!
//! This module defines the data structures used for e-commerce operations
//! including products, shopping carts, orders, and payments.

use chrono::{DateTime, Utc};
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};

/// Product in a merchant catalog.
///
/// Represents a product with pricing, images, and variants.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Product {
    /// Unique product identifier.
    pub id: String,
    /// Product name.
    pub name: String,
    /// Product description.
    pub description: String,
    /// Product price.
    pub price: Decimal,
    /// Currency code (ISO 4217).
    pub currency: String,
    /// Product image URLs.
    pub images: Vec<String>,
    /// Product variants (size, color, etc.).
    pub variants: Vec<ProductVariant>,
    /// Available inventory quantity.
    pub inventory: Option<u32>,
}

/// Product variant (size, color, etc.).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProductVariant {
    /// Variant identifier.
    pub id: String,
    /// Variant name (e.g., "Small", "Red").
    pub name: String,
    /// Variant price (if different from base product).
    pub price: Option<Decimal>,
    /// Variant inventory.
    pub inventory: Option<u32>,
}

/// Product catalog with pagination.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProductCatalog {
    /// Products in current page.
    pub products: Vec<Product>,
    /// Total product count.
    pub total: u32,
    /// Current page number.
    pub page: u32,
    /// Items per page.
    pub per_page: u32,
}

/// Item in shopping cart.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CartItem {
    /// Product identifier.
    pub product_id: String,
    /// Product variant identifier (if applicable).
    pub variant_id: Option<String>,
    /// Item quantity.
    pub quantity: u32,
    /// Item price per unit.
    pub price: Decimal,
    /// Product name.
    pub name: String,
}

/// Shopping cart state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CartState {
    /// Cart identifier.
    pub cart_id: String,
    /// Items in cart.
    pub items: Vec<CartItem>,
    /// Subtotal (before tax and shipping).
    pub subtotal: Decimal,
    /// Tax amount.
    pub tax: Decimal,
    /// Shipping cost.
    pub shipping: Option<Decimal>,
    /// Total amount (subtotal + tax + shipping).
    pub total: Decimal,
    /// Currency code (ISO 4217).
    pub currency: String,
}

/// Order status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OrderStatus {
    /// Order created, awaiting payment.
    Pending,
    /// Payment authorized.
    Authorized,
    /// Payment captured, order processing.
    Processing,
    /// Order shipped.
    Shipped,
    /// Order delivered.
    Delivered,
    /// Order cancelled.
    Cancelled,
    /// Order refunded.
    Refunded,
}

/// Order line item.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrderLineItem {
    /// Product identifier.
    pub product_id: String,
    /// Product variant identifier (if applicable).
    pub variant_id: Option<String>,
    /// Product name.
    pub name: String,
    /// Item quantity.
    pub quantity: u32,
    /// Unit price.
    pub unit_price: Decimal,
    /// Total price (quantity * `unit_price`).
    pub total_price: Decimal,
}

/// Shipping or billing address.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Address {
    /// Recipient name.
    pub name: String,
    /// Street address.
    pub street: String,
    /// City.
    pub city: String,
    /// State or province.
    pub state: String,
    /// Postal code.
    pub postal_code: String,
    /// Country code (ISO 3166-1 alpha-2).
    pub country: String,
    /// Phone number (optional).
    pub phone: Option<String>,
}

/// Order details.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Order {
    /// Order identifier.
    pub order_id: String,
    /// Order status.
    pub status: OrderStatus,
    /// Order line items.
    pub items: Vec<OrderLineItem>,
    /// Subtotal amount.
    pub subtotal: Decimal,
    /// Tax amount.
    pub tax: Decimal,
    /// Shipping cost.
    pub shipping: Decimal,
    /// Total amount.
    pub total: Decimal,
    /// Currency code (ISO 4217).
    pub currency: String,
    /// Shipping address.
    pub shipping_address: Address,
    /// Billing address.
    pub billing_address: Address,
    /// Order creation timestamp.
    pub created_at: DateTime<Utc>,
}

/// Payment status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PaymentStatus {
    /// Payment approved.
    Approved,
    /// Payment declined.
    Declined,
    /// Payment pending processing.
    Pending,
    /// Payment error occurred.
    Error,
}

/// Payment processing result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentResult {
    /// Transaction identifier.
    pub transaction_id: String,
    /// Payment status.
    pub status: PaymentStatus,
    /// Order identifier.
    pub order_id: String,
    /// Payment amount.
    pub amount: Decimal,
    /// Currency code (ISO 4217).
    pub currency: String,
    /// Status message (optional).
    pub message: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_product_creation() {
        let product = Product {
            id: "prod-123".to_owned(),
            name: "Test Product".to_owned(),
            description: "A test product".to_owned(),
            price: Decimal::new(1999, 2),
            currency: "USD".to_owned(),
            images: vec!["https://example.com/image.jpg".to_owned()],
            variants: vec![],
            inventory: Some(100),
        };

        assert_eq!(product.id, "prod-123");
        assert_eq!(product.price, Decimal::new(1999, 2));
    }

    #[test]
    fn test_product_serialization() {
        let product = Product {
            id: "prod-456".to_owned(),
            name: "Widget".to_owned(),
            description: "A useful widget".to_owned(),
            price: Decimal::new(2999, 2),
            currency: "USD".to_owned(),
            images: vec![],
            variants: vec![],
            inventory: None,
        };

        let json = serde_json::to_string(&product).unwrap();
        assert!(json.contains("\"id\":\"prod-456\""));
        assert!(json.contains("\"name\":\"Widget\""));

        let parsed: Product = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.id, "prod-456");
        assert_eq!(parsed.price, Decimal::new(2999, 2));
    }

    #[test]
    fn test_product_with_variants() {
        let variant = ProductVariant {
            id: "var-small".to_owned(),
            name: "Small".to_owned(),
            price: Some(Decimal::new(1999, 2)),
            inventory: Some(50),
        };

        let product = Product {
            id: "prod-789".to_owned(),
            name: "T-Shirt".to_owned(),
            description: "Cotton t-shirt".to_owned(),
            price: Decimal::new(2499, 2),
            currency: "USD".to_owned(),
            images: vec![],
            variants: vec![variant],
            inventory: Some(100),
        };

        assert_eq!(product.variants.len(), 1);
        assert_eq!(product.variants[0].name, "Small");
    }

    #[test]
    fn test_product_catalog_serialization() {
        let catalog = ProductCatalog { products: vec![], total: 42, page: 2, per_page: 20 };

        let json = serde_json::to_string(&catalog).unwrap();
        assert!(json.contains("\"total\":42"));
        assert!(json.contains("\"page\":2"));

        let parsed: ProductCatalog = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.total, 42);
        assert_eq!(parsed.page, 2);
    }

    #[test]
    fn test_cart_item_creation() {
        let item = CartItem {
            product_id: "prod-123".to_owned(),
            variant_id: Some("var-xl".to_owned()),
            quantity: 3,
            price: Decimal::new(2999, 2),
            name: "Blue Shirt".to_owned(),
        };

        assert_eq!(item.quantity, 3);
        assert!(item.variant_id.is_some());
    }

    #[test]
    fn test_cart_item_serialization() {
        let item = CartItem {
            product_id: "prod-999".to_owned(),
            variant_id: None,
            quantity: 1,
            price: Decimal::new(4999, 2),
            name: "Premium Widget".to_owned(),
        };

        let json = serde_json::to_string(&item).unwrap();
        assert!(json.contains("\"product_id\":\"prod-999\""));
        assert!(json.contains("\"quantity\":1"));

        let parsed: CartItem = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.product_id, "prod-999");
        assert!(parsed.variant_id.is_none());
    }

    #[test]
    fn test_cart_state_creation() {
        let cart = CartState {
            cart_id: "cart-456".to_owned(),
            items: vec![],
            subtotal: Decimal::new(5000, 2),
            tax: Decimal::new(400, 2),
            shipping: Some(Decimal::new(500, 2)),
            total: Decimal::new(5900, 2),
            currency: "USD".to_owned(),
        };

        assert_eq!(cart.cart_id, "cart-456");
        assert_eq!(cart.total, Decimal::new(5900, 2));
    }

    #[test]
    fn test_cart_state_with_items() {
        let item = CartItem {
            product_id: "prod-123".to_owned(),
            variant_id: None,
            quantity: 2,
            price: Decimal::new(2500, 2),
            name: "Widget".to_owned(),
        };

        let cart = CartState {
            cart_id: "cart-789".to_owned(),
            items: vec![item],
            subtotal: Decimal::new(5000, 2),
            tax: Decimal::new(400, 2),
            shipping: None,
            total: Decimal::new(5400, 2),
            currency: "EUR".to_owned(),
        };

        assert_eq!(cart.items.len(), 1);
        assert_eq!(cart.currency, "EUR");
        assert!(cart.shipping.is_none());
    }

    #[test]
    fn test_cart_state_empty() {
        let cart = CartState {
            cart_id: "cart-empty".to_owned(),
            items: vec![],
            subtotal: Decimal::ZERO,
            tax: Decimal::ZERO,
            shipping: None,
            total: Decimal::ZERO,
            currency: "USD".to_owned(),
        };

        assert!(cart.items.is_empty());
        assert_eq!(cart.total, Decimal::ZERO);
    }

    #[test]
    fn test_order_status_all_variants() {
        let statuses = vec![
            OrderStatus::Pending,
            OrderStatus::Authorized,
            OrderStatus::Processing,
            OrderStatus::Shipped,
            OrderStatus::Delivered,
            OrderStatus::Cancelled,
            OrderStatus::Refunded,
        ];

        for status in statuses {
            let json = serde_json::to_string(&status).unwrap();
            let parsed: OrderStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(status, parsed);
        }
    }

    #[test]
    fn test_order_status_serialization() {
        let status = OrderStatus::Processing;
        let json = serde_json::to_string(&status).unwrap();
        assert!(json.contains("Processing"));
    }

    #[test]
    fn test_order_status_deserialization() {
        let json = "\"Shipped\"";
        let status: OrderStatus = serde_json::from_str(json).unwrap();
        assert_eq!(status, OrderStatus::Shipped);
    }

    #[test]
    fn test_order_line_item() {
        let item = OrderLineItem {
            product_id: "prod-123".to_owned(),
            variant_id: Some("var-red".to_owned()),
            name: "Red Widget".to_owned(),
            quantity: 5,
            unit_price: Decimal::new(1000, 2),
            total_price: Decimal::new(5000, 2),
        };

        assert_eq!(item.quantity, 5);
        assert_eq!(item.total_price, Decimal::new(5000, 2));
    }

    #[test]
    fn test_order_line_item_serialization() {
        let item = OrderLineItem {
            product_id: "prod-999".to_owned(),
            variant_id: None,
            name: "Standard Widget".to_owned(),
            quantity: 2,
            unit_price: Decimal::new(2500, 2),
            total_price: Decimal::new(5000, 2),
        };

        let json = serde_json::to_string(&item).unwrap();
        let parsed: OrderLineItem = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.product_id, "prod-999");
        assert_eq!(parsed.quantity, 2);
    }

    #[test]
    fn test_address_creation() {
        let address = Address {
            name: "John Doe".to_owned(),
            street: "123 Main St".to_owned(),
            city: "San Francisco".to_owned(),
            state: "CA".to_owned(),
            postal_code: "94102".to_owned(),
            country: "US".to_owned(),
            phone: Some("+1-555-1234".to_owned()),
        };

        assert_eq!(address.country, "US");
        assert!(address.phone.is_some());
    }

    #[test]
    fn test_address_without_phone() {
        let address = Address {
            name: "Jane Smith".to_owned(),
            street: "456 Oak Ave".to_owned(),
            city: "Portland".to_owned(),
            state: "OR".to_owned(),
            postal_code: "97201".to_owned(),
            country: "US".to_owned(),
            phone: None,
        };

        assert!(address.phone.is_none());
    }

    #[test]
    fn test_address_serialization() {
        let address = Address {
            name: "Test User".to_owned(),
            street: "789 Pine St".to_owned(),
            city: "Seattle".to_owned(),
            state: "WA".to_owned(),
            postal_code: "98101".to_owned(),
            country: "US".to_owned(),
            phone: Some("+1-206-555-0100".to_owned()),
        };

        let json = serde_json::to_string(&address).unwrap();
        let parsed: Address = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.name, "Test User");
        assert_eq!(parsed.city, "Seattle");
    }

    #[test]
    fn test_order_creation() {
        let address = Address {
            name: "John Doe".to_owned(),
            street: "123 Main St".to_owned(),
            city: "San Francisco".to_owned(),
            state: "CA".to_owned(),
            postal_code: "94102".to_owned(),
            country: "US".to_owned(),
            phone: None,
        };

        let order = Order {
            order_id: "order-123".to_owned(),
            status: OrderStatus::Pending,
            items: vec![],
            subtotal: Decimal::new(10000, 2),
            tax: Decimal::new(850, 2),
            shipping: Decimal::new(500, 2),
            total: Decimal::new(11350, 2),
            currency: "USD".to_owned(),
            shipping_address: address.clone(),
            billing_address: address,
            created_at: Utc::now(),
        };

        assert_eq!(order.order_id, "order-123");
        assert_eq!(order.status, OrderStatus::Pending);
    }

    #[test]
    fn test_payment_status_equality() {
        assert_eq!(PaymentStatus::Approved, PaymentStatus::Approved);
        assert_ne!(PaymentStatus::Approved, PaymentStatus::Declined);
    }

    #[test]
    fn test_payment_status_all_variants() {
        let statuses = vec![
            PaymentStatus::Approved,
            PaymentStatus::Declined,
            PaymentStatus::Pending,
            PaymentStatus::Error,
        ];

        for status in statuses {
            let json = serde_json::to_string(&status).unwrap();
            let parsed: PaymentStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(status, parsed);
        }
    }

    #[test]
    fn test_payment_result_creation() {
        let result = PaymentResult {
            transaction_id: "txn-abc123".to_owned(),
            status: PaymentStatus::Approved,
            order_id: "order-456".to_owned(),
            amount: Decimal::new(9999, 2),
            currency: "USD".to_owned(),
            message: Some("Payment successful".to_owned()),
        };

        assert_eq!(result.transaction_id, "txn-abc123");
        assert_eq!(result.status, PaymentStatus::Approved);
        assert!(result.message.is_some());
    }

    #[test]
    fn test_payment_result_declined() {
        let result = PaymentResult {
            transaction_id: "txn-xyz789".to_owned(),
            status: PaymentStatus::Declined,
            order_id: "order-789".to_owned(),
            amount: Decimal::new(5000, 2),
            currency: "EUR".to_owned(),
            message: Some("Insufficient funds".to_owned()),
        };

        assert_eq!(result.status, PaymentStatus::Declined);
        assert_eq!(result.message.as_ref().unwrap(), "Insufficient funds");
    }

    #[test]
    fn test_payment_result_serialization() {
        let result = PaymentResult {
            transaction_id: "txn-test".to_owned(),
            status: PaymentStatus::Pending,
            order_id: "order-test".to_owned(),
            amount: Decimal::new(12345, 2),
            currency: "GBP".to_owned(),
            message: None,
        };

        let json = serde_json::to_string(&result).unwrap();
        let parsed: PaymentResult = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.transaction_id, "txn-test");
        assert_eq!(parsed.status, PaymentStatus::Pending);
        assert!(parsed.message.is_none());
    }

    #[test]
    fn test_decimal_zero_edge_case() {
        let cart = CartState {
            cart_id: "cart-zero".to_owned(),
            items: vec![],
            subtotal: Decimal::ZERO,
            tax: Decimal::ZERO,
            shipping: Some(Decimal::ZERO),
            total: Decimal::ZERO,
            currency: "USD".to_owned(),
        };

        assert_eq!(cart.total, Decimal::ZERO);
        assert_eq!(cart.shipping.unwrap(), Decimal::ZERO);
    }

    #[test]
    fn test_large_quantity_edge_case() {
        let item = CartItem {
            product_id: "prod-bulk".to_owned(),
            variant_id: None,
            quantity: u32::MAX,
            price: Decimal::new(100, 2),
            name: "Bulk Item".to_owned(),
        };

        assert_eq!(item.quantity, u32::MAX);
    }

    #[test]
    fn test_empty_string_fields() {
        let address = Address {
            name: String::new(),
            street: String::new(),
            city: String::new(),
            state: String::new(),
            postal_code: String::new(),
            country: String::new(),
            phone: None,
        };

        assert!(address.name.is_empty());
        assert!(address.street.is_empty());
    }

    #[test]
    fn test_currency_codes() {
        let currencies = vec!["USD", "EUR", "GBP", "JPY", "CHF"];

        for currency in currencies {
            let cart = CartState {
                cart_id: "cart-currency-test".to_owned(),
                items: vec![],
                subtotal: Decimal::new(1000, 2),
                tax: Decimal::ZERO,
                shipping: None,
                total: Decimal::new(1000, 2),
                currency: currency.to_owned(),
            };

            assert_eq!(cart.currency, currency);
        }
    }
}
