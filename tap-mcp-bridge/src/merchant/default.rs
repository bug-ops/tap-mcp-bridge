//! Default merchant implementation.
//!
//! This module provides a default merchant implementation using standard TAP conventions.

use std::path::Path;

use crate::{
    error::{BridgeError, Result},
    mcp::models,
    merchant::{
        ConfigurableEndpointResolver, ConfigurableFieldMapper, EndpointResolver, FieldMapper,
        MerchantApi, MerchantConfig,
    },
};

/// Default merchant implementation using standard TAP conventions.
///
/// This implementation provides out-of-box compatibility with merchants
/// following the standard TAP API specification.
#[derive(Debug, Clone)]
pub struct DefaultMerchant {
    config: MerchantConfig,
    endpoint_resolver: ConfigurableEndpointResolver,
    field_mapper: ConfigurableFieldMapper,
}

impl DefaultMerchant {
    /// Creates a new default merchant with standard configuration.
    #[must_use]
    pub fn new() -> Self {
        Self::with_config(MerchantConfig::default())
    }

    /// Creates a merchant from TOML configuration.
    ///
    /// # Errors
    ///
    /// Returns error if TOML parsing fails or configuration validation fails.
    pub fn from_toml(toml_str: &str) -> Result<Self> {
        let config: MerchantConfig = toml::from_str(toml_str)
            .map_err(|e| BridgeError::InvalidInput(format!("invalid TOML config: {e}")))?;
        config.validate()?;
        Ok(Self::with_config(config))
    }

    /// Creates a merchant from configuration file path.
    ///
    /// # Errors
    ///
    /// Returns error if file cannot be read or TOML parsing fails.
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content = std::fs::read_to_string(path.as_ref())
            .map_err(|e| BridgeError::InvalidInput(format!("cannot read config file: {e}")))?;
        Self::from_toml(&content)
    }

    /// Creates a merchant with the given configuration.
    #[must_use]
    pub fn with_config(config: MerchantConfig) -> Self {
        let endpoint_resolver = ConfigurableEndpointResolver::new(&config.endpoints);
        let field_mapper = ConfigurableFieldMapper::new(&config.field_mappings);
        Self { config, endpoint_resolver, field_mapper }
    }

    /// Returns the merchant configuration.
    #[must_use]
    pub fn config(&self) -> &MerchantConfig {
        &self.config
    }
}

impl Default for DefaultMerchant {
    fn default() -> Self {
        Self::new()
    }
}

impl MerchantApi for DefaultMerchant {
    type CartState = models::CartState;
    type Order = models::Order;
    type PaymentResult = models::PaymentResult;
    type Product = models::Product;
    // For DefaultMerchant, associated types match standard models
    type ProductCatalog = models::ProductCatalog;

    fn endpoint_resolver(&self) -> &dyn EndpointResolver {
        &self.endpoint_resolver
    }

    fn field_mapper(&self) -> &dyn FieldMapper {
        &self.field_mapper
    }

    // Conversion is identity for default merchant
    fn to_standard_catalog(&self, catalog: Self::ProductCatalog) -> Result<models::ProductCatalog> {
        Ok(catalog)
    }

    fn to_standard_product(&self, product: Self::Product) -> Result<models::Product> {
        Ok(product)
    }

    fn to_standard_cart(&self, cart: Self::CartState) -> Result<models::CartState> {
        Ok(cart)
    }

    fn to_standard_order(&self, order: Self::Order) -> Result<models::Order> {
        Ok(order)
    }

    fn to_standard_payment(&self, result: Self::PaymentResult) -> Result<models::PaymentResult> {
        Ok(result)
    }
}

#[cfg(test)]
#[allow(
    clippy::unreachable,
    reason = "test code uses unreachable for expected-path assertions"
)]
mod tests {
    use super::*;

    #[test]
    fn test_default_merchant_new() {
        let merchant = DefaultMerchant::new();
        assert_eq!(merchant.config().name, "Default Merchant");
    }

    #[test]
    fn test_default_merchant_default() {
        let merchant = DefaultMerchant::default();
        assert_eq!(merchant.config().name, "Default Merchant");
    }

    #[test]
    fn test_default_merchant_from_toml() {
        let toml = r#"
            name = "Test Merchant"
            base_url = "https://api.test.com"
            api_prefix = "/api/v1"
        "#;

        let merchant = DefaultMerchant::from_toml(toml).unwrap();
        assert_eq!(merchant.config().name, "Test Merchant");
        assert_eq!(merchant.config().base_url, "https://api.test.com");
        assert_eq!(merchant.config().api_prefix, "/api/v1");
    }

    #[test]
    fn test_default_merchant_from_toml_invalid() {
        let toml = "invalid toml {{{";
        let result = DefaultMerchant::from_toml(toml);
        assert!(result.is_err());
    }

    #[test]
    fn test_default_merchant_with_config() {
        let config = MerchantConfig {
            name: "Custom Merchant".to_owned(),
            base_url: "https://custom.com".to_owned(),
            ..Default::default()
        };

        let merchant = DefaultMerchant::with_config(config);
        assert_eq!(merchant.config().name, "Custom Merchant");
    }

    #[test]
    fn test_default_merchant_endpoint_resolver() {
        let merchant = DefaultMerchant::new();
        let resolver = merchant.endpoint_resolver();
        assert_eq!(resolver.checkout_endpoint(), "/checkout");
    }

    #[test]
    fn test_default_merchant_field_mapper() {
        let merchant = DefaultMerchant::new();
        let mapper = merchant.field_mapper();
        assert_eq!(mapper.map_request_field("consumer_id"), "consumer_id");
        assert!(!mapper.has_custom_mappings());
    }

    #[test]
    fn test_default_merchant_identity_conversions() {
        use chrono::Utc;
        use rust_decimal::Decimal;

        let merchant = DefaultMerchant::new();

        // Test product catalog conversion (identity)
        let catalog = models::ProductCatalog { products: vec![], total: 10, page: 1, per_page: 20 };
        let result = merchant.to_standard_catalog(catalog.clone()).unwrap();
        assert_eq!(result.total, catalog.total);

        // Test product conversion (identity)
        let product = models::Product {
            id: "prod-123".to_owned(),
            name: "Test Product".to_owned(),
            description: "A test product".to_owned(),
            price: Decimal::new(1999, 2),
            currency: "USD".to_owned(),
            images: vec![],
            variants: vec![],
            inventory: Some(100),
        };
        let result = merchant.to_standard_product(product.clone()).unwrap();
        assert_eq!(result.id, product.id);

        // Test cart conversion (identity)
        let cart = models::CartState {
            cart_id: "cart-456".to_owned(),
            items: vec![],
            subtotal: Decimal::new(5000, 2),
            tax: Decimal::new(400, 2),
            shipping: None,
            total: Decimal::new(5400, 2),
            currency: "USD".to_owned(),
        };
        let result = merchant.to_standard_cart(cart.clone()).unwrap();
        assert_eq!(result.cart_id, cart.cart_id);

        // Test order conversion (identity)
        let address = models::Address {
            name: "John Doe".to_owned(),
            street: "123 Main St".to_owned(),
            city: "San Francisco".to_owned(),
            state: "CA".to_owned(),
            postal_code: "94102".to_owned(),
            country: "US".to_owned(),
            phone: None,
        };
        let order = models::Order {
            order_id: "order-789".to_owned(),
            status: models::OrderStatus::Pending,
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
        let result = merchant.to_standard_order(order.clone()).unwrap();
        assert_eq!(result.order_id, order.order_id);

        // Test payment result conversion (identity)
        let payment = models::PaymentResult {
            transaction_id: "txn-abc".to_owned(),
            status: models::PaymentStatus::Approved,
            order_id: "order-789".to_owned(),
            amount: Decimal::new(11350, 2),
            currency: "USD".to_owned(),
            message: Some("Payment successful".to_owned()),
        };
        let result = merchant.to_standard_payment(payment.clone()).unwrap();
        assert_eq!(result.transaction_id, payment.transaction_id);
    }

    #[test]
    fn test_default_merchant_with_custom_endpoints() {
        use crate::merchant::traits::ProductQueryParams;

        let toml = r#"
            name = "Custom Endpoints Merchant"
            base_url = "https://merchant.com"

            [endpoints]
            products = "/catalog"
            product = "/catalog/{id}"
        "#;

        let merchant = DefaultMerchant::from_toml(toml).unwrap();
        let resolver = merchant.endpoint_resolver();

        let params = ProductQueryParams::default();
        assert_eq!(resolver.products_endpoint(&params), "/catalog");
        assert_eq!(resolver.product_endpoint("sku-123"), "/catalog/sku-123");
    }

    #[test]
    fn test_default_merchant_with_field_mappings() {
        let toml = r#"
            name = "Field Mapping Merchant"
            base_url = "https://merchant.com"

            [field_mappings.request]
            consumer_id = "customerId"
            product_id = "sku"

            [field_mappings.response]
            customerId = "consumer_id"
        "#;

        let merchant = DefaultMerchant::from_toml(toml).unwrap();
        let mapper = merchant.field_mapper();

        assert_eq!(mapper.map_request_field("consumer_id"), "customerId");
        assert_eq!(mapper.map_request_field("product_id"), "sku");
        assert_eq!(mapper.map_response_field("customerId"), "consumer_id");
        assert!(mapper.has_custom_mappings());
    }

    #[test]
    fn test_default_merchant_from_file_not_found() {
        let result = DefaultMerchant::from_file("/nonexistent/path/config.toml");
        let Err(BridgeError::InvalidInput(msg)) = result else {
            unreachable!("expected InvalidInput error")
        };
        assert!(msg.contains("cannot read config file"));
    }

    #[test]
    fn test_default_merchant_from_toml_empty() {
        let toml = "";
        let result = DefaultMerchant::from_toml(toml);
        assert!(result.is_err());
    }

    #[test]
    fn test_default_merchant_from_toml_missing_name() {
        let toml = r#"
            base_url = "https://test.com"
        "#;
        let result = DefaultMerchant::from_toml(toml);
        assert!(result.is_err());
    }

    #[test]
    fn test_default_merchant_config_accessor() {
        let config = MerchantConfig {
            name: "Test Config".to_owned(),
            base_url: "https://test.com".to_owned(),
            ..Default::default()
        };
        let merchant = DefaultMerchant::with_config(config.clone());

        assert_eq!(merchant.config().name, "Test Config");
        assert_eq!(merchant.config().base_url, "https://test.com");
    }

    #[test]
    fn test_default_merchant_no_transformers() {
        let merchant = DefaultMerchant::new();
        assert!(merchant.request_transformer().is_none());
        assert!(merchant.response_transformer().is_none());
    }

    #[test]
    fn test_default_merchant_clone() {
        let merchant = DefaultMerchant::new();
        let cloned = merchant.clone();
        assert_eq!(merchant.config().name, cloned.config().name);
    }

    #[test]
    fn test_default_merchant_minimal_config() {
        let toml = r#"
            name = "Minimal"
            base_url = "https://minimal.com"
        "#;

        let merchant = DefaultMerchant::from_toml(toml).unwrap();
        assert_eq!(merchant.config().name, "Minimal");
        assert_eq!(merchant.config().api_prefix, "");
        assert!(merchant.config().auth.is_none());
    }

    #[test]
    fn test_default_merchant_with_all_auth_types() {
        let toml_api_key = r#"
            name = "Test"
            base_url = "https://test.com"

            [auth]
            type = "api_key"
            header = "X-API-Key"
            env_var = "API_KEY"
        "#;
        let merchant = DefaultMerchant::from_toml(toml_api_key).unwrap();
        assert!(merchant.config().auth.is_some());

        let toml_bearer = r#"
            name = "Test"
            base_url = "https://test.com"

            [auth]
            type = "bearer"
            env_var = "BEARER_TOKEN"
        "#;
        let merchant = DefaultMerchant::from_toml(toml_bearer).unwrap();
        assert!(merchant.config().auth.is_some());

        let toml_oauth2 = r#"
            name = "Test"
            base_url = "https://test.com"

            [auth]
            type = "o_auth2"
            token_url = "https://auth.test.com/token"
            client_id_env = "CLIENT_ID"
            client_secret_env = "CLIENT_SECRET"
        "#;
        let merchant = DefaultMerchant::from_toml(toml_oauth2).unwrap();
        assert!(merchant.config().auth.is_some());
    }

    #[test]
    fn test_default_merchant_identity_conversion_with_empty_collections() {
        let merchant = DefaultMerchant::new();

        let catalog = models::ProductCatalog { products: vec![], total: 0, page: 1, per_page: 20 };
        let result = merchant.to_standard_catalog(catalog.clone()).unwrap();
        assert!(result.products.is_empty());

        let cart = models::CartState {
            cart_id: "empty".to_owned(),
            items: vec![],
            subtotal: rust_decimal::Decimal::ZERO,
            tax: rust_decimal::Decimal::ZERO,
            shipping: None,
            total: rust_decimal::Decimal::ZERO,
            currency: "USD".to_owned(),
        };
        let result = merchant.to_standard_cart(cart.clone()).unwrap();
        assert!(result.items.is_empty());
    }

    #[test]
    fn test_default_merchant_with_unicode_config() {
        let toml = r#"
            name = "测试商家"
            base_url = "https://测试.com"
            api_prefix = "/api/v1"
        "#;

        let merchant = DefaultMerchant::from_toml(toml).unwrap();
        assert_eq!(merchant.config().name, "测试商家");
    }

    #[test]
    fn test_default_merchant_with_all_pagination_styles() {
        let toml_page = r#"
            name = "Test"
            base_url = "https://test.com"
            pagination = "page_based"
        "#;
        let merchant = DefaultMerchant::from_toml(toml_page).unwrap();
        assert!(matches!(
            merchant.config().pagination,
            crate::merchant::PaginationStyle::PageBased
        ));

        let toml_offset = r#"
            name = "Test"
            base_url = "https://test.com"
            pagination = "offset_based"
        "#;
        let merchant = DefaultMerchant::from_toml(toml_offset).unwrap();
        assert!(matches!(
            merchant.config().pagination,
            crate::merchant::PaginationStyle::OffsetBased
        ));

        let toml_cursor = r#"
            name = "Test"
            base_url = "https://test.com"
            pagination = "cursor_based"
        "#;
        let merchant = DefaultMerchant::from_toml(toml_cursor).unwrap();
        assert!(matches!(
            merchant.config().pagination,
            crate::merchant::PaginationStyle::CursorBased
        ));
    }
}
