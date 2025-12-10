//! Integration tests for merchant abstraction layer.
//!
//! Tests end-to-end merchant configuration and API integration.

use tap_mcp_bridge::merchant::{
    ConfigurableEndpointResolver, ConfigurableFieldMapper, DefaultMerchant, EndpointConfig,
    EndpointResolver, FieldMapper, FieldMappingConfig, MerchantApi, PaginationStyle,
    traits::ProductQueryParams,
};

#[test]
fn test_full_merchant_configuration_flow() {
    let toml = r#"
        name = "Integration Test Merchant"
        base_url = "https://api.testmerchant.com"
        api_prefix = "/api/v2"
        pagination = "offset_based"

        [endpoints]
        products = "/catalog"
        product = "/catalog/{id}"
        cart = "/basket"
        add_to_cart = "/basket/add"
        cart_item = "/basket/items/{id}"
        orders = "/purchases"
        order = "/purchases/{id}"
        checkout = "/payment"

        [field_mappings.request]
        consumer_id = "customerId"
        product_id = "sku"
        cart_id = "basketId"

        [field_mappings.response]
        customerId = "consumer_id"
        sku = "product_id"
        basketId = "cart_id"
    "#;

    let merchant = DefaultMerchant::from_toml(toml).expect("should parse valid TOML");

    // Verify configuration
    assert_eq!(merchant.config().name, "Integration Test Merchant");
    assert_eq!(merchant.config().base_url, "https://api.testmerchant.com");
    assert_eq!(merchant.config().api_prefix, "/api/v2");
    assert!(matches!(merchant.config().pagination, PaginationStyle::OffsetBased));

    // Verify endpoint resolution
    let resolver = merchant.endpoint_resolver();
    let params = ProductQueryParams::default();
    assert_eq!(resolver.products_endpoint(&params), "/catalog");
    assert_eq!(resolver.product_endpoint("prod-123"), "/catalog/prod-123");
    assert_eq!(resolver.cart_endpoint("cart-456"), "/basket");
    assert_eq!(resolver.add_to_cart_endpoint(), "/basket/add");
    assert_eq!(resolver.update_cart_item_endpoint("item-789"), "/basket/items/item-789");
    assert_eq!(resolver.create_order_endpoint(), "/purchases");
    assert_eq!(resolver.order_endpoint("order-111"), "/purchases/order-111");
    assert_eq!(resolver.checkout_endpoint(), "/payment");

    // Verify field mapping
    let mapper = merchant.field_mapper();
    assert_eq!(mapper.map_request_field("consumer_id"), "customerId");
    assert_eq!(mapper.map_request_field("product_id"), "sku");
    assert_eq!(mapper.map_request_field("cart_id"), "basketId");
    assert_eq!(mapper.map_response_field("customerId"), "consumer_id");
    assert_eq!(mapper.map_response_field("sku"), "product_id");
    assert_eq!(mapper.map_response_field("basketId"), "cart_id");
    assert!(mapper.has_custom_mappings());
}

#[test]
fn test_merchant_with_minimal_configuration() {
    let toml = r#"
        name = "Minimal Merchant"
        base_url = "https://minimal.com"
    "#;

    let merchant = DefaultMerchant::from_toml(toml).expect("should parse minimal TOML");

    // Verify defaults are applied
    assert_eq!(merchant.config().api_prefix, "");
    assert!(merchant.config().auth.is_none());
    assert!(matches!(merchant.config().pagination, PaginationStyle::PageBased));

    // Verify default endpoints
    let resolver = merchant.endpoint_resolver();
    let params = ProductQueryParams::default();
    assert_eq!(resolver.products_endpoint(&params), "/products");
    assert_eq!(resolver.checkout_endpoint(), "/checkout");

    // Verify identity field mapping
    let mapper = merchant.field_mapper();
    assert_eq!(mapper.map_request_field("consumer_id"), "consumer_id");
    assert!(!mapper.has_custom_mappings());
}

#[test]
fn test_merchant_endpoint_resolver_integration() {
    let config = EndpointConfig {
        products: Some("/api/items".to_owned()),
        product: Some("/api/items/{id}/details".to_owned()),
        cart: Some("/api/shopping-cart".to_owned()),
        add_to_cart: Some("/api/shopping-cart/items".to_owned()),
        cart_item: Some("/api/shopping-cart/items/{id}".to_owned()),
        orders: Some("/api/orders".to_owned()),
        order: Some("/api/orders/{id}".to_owned()),
        checkout: Some("/api/checkout/process".to_owned()),
    };

    let resolver = ConfigurableEndpointResolver::new(&config);

    // Test all endpoints with various IDs
    let params = ProductQueryParams::default();
    assert_eq!(resolver.products_endpoint(&params), "/api/items");
    assert_eq!(resolver.product_endpoint("sku-abc-123"), "/api/items/sku-abc-123/details");
    assert_eq!(resolver.cart_endpoint("cart-xyz"), "/api/shopping-cart");
    assert_eq!(resolver.add_to_cart_endpoint(), "/api/shopping-cart/items");
    assert_eq!(
        resolver.update_cart_item_endpoint("item-456"),
        "/api/shopping-cart/items/item-456"
    );
    assert_eq!(
        resolver.remove_cart_item_endpoint("item-789"),
        "/api/shopping-cart/items/item-789"
    );
    assert_eq!(resolver.create_order_endpoint(), "/api/orders");
    assert_eq!(resolver.order_endpoint("order-999"), "/api/orders/order-999");
    assert_eq!(resolver.checkout_endpoint(), "/api/checkout/process");
}

#[test]
fn test_merchant_field_mapper_integration() {
    let mut request_mappings = std::collections::HashMap::new();
    request_mappings.insert("consumer_id".to_owned(), "customer_identifier".to_owned());
    request_mappings.insert("product_id".to_owned(), "item_sku".to_owned());
    request_mappings.insert("cart_id".to_owned(), "shopping_basket_id".to_owned());
    request_mappings.insert("order_id".to_owned(), "purchase_number".to_owned());

    let mut response_mappings = std::collections::HashMap::new();
    response_mappings.insert("customer_identifier".to_owned(), "consumer_id".to_owned());
    response_mappings.insert("item_sku".to_owned(), "product_id".to_owned());
    response_mappings.insert("shopping_basket_id".to_owned(), "cart_id".to_owned());
    response_mappings.insert("purchase_number".to_owned(), "order_id".to_owned());

    let config = FieldMappingConfig { request: request_mappings, response: response_mappings };

    let mapper = ConfigurableFieldMapper::new(&config);

    // Test request mappings
    assert_eq!(mapper.map_request_field("consumer_id"), "customer_identifier");
    assert_eq!(mapper.map_request_field("product_id"), "item_sku");
    assert_eq!(mapper.map_request_field("cart_id"), "shopping_basket_id");
    assert_eq!(mapper.map_request_field("order_id"), "purchase_number");

    // Test response mappings
    assert_eq!(mapper.map_response_field("customer_identifier"), "consumer_id");
    assert_eq!(mapper.map_response_field("item_sku"), "product_id");
    assert_eq!(mapper.map_response_field("shopping_basket_id"), "cart_id");
    assert_eq!(mapper.map_response_field("purchase_number"), "order_id");

    // Test unmapped fields (should pass through)
    assert_eq!(mapper.map_request_field("unmapped"), "unmapped");
    assert_eq!(mapper.map_response_field("unknown"), "unknown");

    assert!(mapper.has_custom_mappings());
}

#[test]
fn test_merchant_with_product_query_params() {
    let merchant = DefaultMerchant::new();
    let resolver = merchant.endpoint_resolver();

    let params = ProductQueryParams {
        consumer_id: "user-123".to_owned(),
        category: Some("electronics".to_owned()),
        search: Some("laptop".to_owned()),
        page: Some(2),
        per_page: Some(50),
    };

    // Endpoint resolver should handle params (even if not used in default implementation)
    let endpoint = resolver.products_endpoint(&params);
    assert!(!endpoint.is_empty());
}

#[test]
fn test_merchant_identity_conversions() {
    use chrono::Utc;
    use rust_decimal::Decimal;
    use tap_mcp_bridge::mcp::models::{
        Address, CartState, Order, OrderStatus, PaymentResult, PaymentStatus, Product,
        ProductCatalog,
    };

    let merchant = DefaultMerchant::new();

    // Test catalog conversion
    let catalog = ProductCatalog { products: vec![], total: 100, page: 1, per_page: 20 };
    let converted = merchant
        .to_standard_catalog(catalog.clone())
        .expect("conversion should succeed");
    assert_eq!(converted.total, 100);

    // Test product conversion
    let product = Product {
        id: "prod-123".to_owned(),
        name: "Test Product".to_owned(),
        description: "Description".to_owned(),
        price: Decimal::new(9999, 2),
        currency: "USD".to_owned(),
        images: vec![],
        variants: vec![],
        inventory: Some(50),
    };
    let converted = merchant
        .to_standard_product(product.clone())
        .expect("conversion should succeed");
    assert_eq!(converted.id, "prod-123");

    // Test cart conversion
    let cart = CartState {
        cart_id: "cart-456".to_owned(),
        items: vec![],
        subtotal: Decimal::new(5000, 2),
        tax: Decimal::new(400, 2),
        shipping: None,
        total: Decimal::new(5400, 2),
        currency: "USD".to_owned(),
    };
    let converted = merchant.to_standard_cart(cart.clone()).expect("conversion should succeed");
    assert_eq!(converted.cart_id, "cart-456");

    // Test order conversion
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
        order_id: "order-789".to_owned(),
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
    let converted = merchant.to_standard_order(order.clone()).expect("conversion should succeed");
    assert_eq!(converted.order_id, "order-789");

    // Test payment result conversion
    let payment = PaymentResult {
        transaction_id: "txn-abc".to_owned(),
        status: PaymentStatus::Approved,
        order_id: "order-789".to_owned(),
        amount: Decimal::new(11350, 2),
        currency: "USD".to_owned(),
        message: Some("Payment successful".to_owned()),
    };
    let converted = merchant
        .to_standard_payment(payment.clone())
        .expect("conversion should succeed");
    assert_eq!(converted.transaction_id, "txn-abc");
}

#[test]
fn test_merchant_config_roundtrip() {
    let original_toml = r#"
        name = "Roundtrip Test"
        base_url = "https://test.com"
        api_prefix = "/v1"
        pagination = "cursor_based"

        [endpoints]
        products = "/items"

        [field_mappings.request]
        test_field = "mapped_field"
    "#;

    let merchant = DefaultMerchant::from_toml(original_toml).expect("should parse TOML");
    let config = merchant.config();

    assert_eq!(config.name, "Roundtrip Test");
    assert_eq!(config.base_url, "https://test.com");
    assert_eq!(config.api_prefix, "/v1");
    assert!(matches!(config.pagination, PaginationStyle::CursorBased));
    assert_eq!(config.endpoints.products.as_ref().unwrap(), "/items");
    assert_eq!(&config.field_mappings.request["test_field"], "mapped_field");
}

#[test]
fn test_multiple_merchants_isolation() {
    let toml1 = r#"
        name = "Merchant 1"
        base_url = "https://merchant1.com"

        [endpoints]
        products = "/catalog1"
    "#;

    let toml2 = r#"
        name = "Merchant 2"
        base_url = "https://merchant2.com"

        [endpoints]
        products = "/catalog2"
    "#;

    let merchant1 = DefaultMerchant::from_toml(toml1).unwrap();
    let merchant2 = DefaultMerchant::from_toml(toml2).unwrap();

    // Verify merchants are isolated
    assert_eq!(merchant1.config().name, "Merchant 1");
    assert_eq!(merchant2.config().name, "Merchant 2");

    let params = ProductQueryParams::default();
    assert_eq!(merchant1.endpoint_resolver().products_endpoint(&params), "/catalog1");
    assert_eq!(merchant2.endpoint_resolver().products_endpoint(&params), "/catalog2");
}
