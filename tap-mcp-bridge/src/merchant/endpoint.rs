//! Endpoint resolution implementations.
//!
//! This module provides endpoint resolvers for merchant APIs.

use crate::merchant::{EndpointConfig, EndpointResolver, traits::ProductQueryParams};

/// Default endpoint resolver using standard TAP paths.
#[derive(Debug, Clone)]
pub struct DefaultEndpointResolver;

impl Default for DefaultEndpointResolver {
    fn default() -> Self {
        Self::new()
    }
}

impl DefaultEndpointResolver {
    /// Creates a new default endpoint resolver.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl EndpointResolver for DefaultEndpointResolver {
    fn products_endpoint(&self, _params: &ProductQueryParams) -> String {
        "/products".to_owned()
    }

    fn product_endpoint(&self, product_id: &str) -> String {
        format!("/products/{product_id}")
    }

    fn cart_endpoint(&self, _cart_id: &str) -> String {
        "/cart".to_owned()
    }

    fn add_to_cart_endpoint(&self) -> String {
        "/cart/add".to_owned()
    }

    fn update_cart_item_endpoint(&self, item_id: &str) -> String {
        format!("/cart/items/{item_id}")
    }

    fn remove_cart_item_endpoint(&self, item_id: &str) -> String {
        format!("/cart/items/{item_id}")
    }

    fn create_order_endpoint(&self) -> String {
        "/orders".to_owned()
    }

    fn order_endpoint(&self, order_id: &str) -> String {
        format!("/orders/{order_id}")
    }

    fn checkout_endpoint(&self) -> String {
        "/checkout".to_owned()
    }
}

/// Configurable endpoint resolver using merchant configuration.
#[derive(Debug, Clone)]
pub struct ConfigurableEndpointResolver {
    config: EndpointConfig,
}

impl ConfigurableEndpointResolver {
    /// Creates a new configurable endpoint resolver.
    #[must_use]
    pub fn new(config: &EndpointConfig) -> Self {
        Self { config: config.clone() }
    }
}

impl EndpointResolver for ConfigurableEndpointResolver {
    fn products_endpoint(&self, _params: &ProductQueryParams) -> String {
        self.config
            .products
            .as_ref()
            .map_or_else(|| "/products".to_owned(), Clone::clone)
    }

    fn product_endpoint(&self, product_id: &str) -> String {
        self.config.product.as_ref().map_or_else(
            || format!("/products/{product_id}"),
            |template| template.replace("{id}", product_id),
        )
    }

    fn cart_endpoint(&self, _cart_id: &str) -> String {
        self.config.cart.as_ref().map_or_else(|| "/cart".to_owned(), Clone::clone)
    }

    fn add_to_cart_endpoint(&self) -> String {
        self.config
            .add_to_cart
            .as_ref()
            .map_or_else(|| "/cart/add".to_owned(), Clone::clone)
    }

    fn update_cart_item_endpoint(&self, item_id: &str) -> String {
        self.config.cart_item.as_ref().map_or_else(
            || format!("/cart/items/{item_id}"),
            |template| template.replace("{id}", item_id),
        )
    }

    fn remove_cart_item_endpoint(&self, item_id: &str) -> String {
        self.config.cart_item.as_ref().map_or_else(
            || format!("/cart/items/{item_id}"),
            |template| template.replace("{id}", item_id),
        )
    }

    fn create_order_endpoint(&self) -> String {
        self.config.orders.as_ref().map_or_else(|| "/orders".to_owned(), Clone::clone)
    }

    fn order_endpoint(&self, order_id: &str) -> String {
        self.config.order.as_ref().map_or_else(
            || format!("/orders/{order_id}"),
            |template| template.replace("{id}", order_id),
        )
    }

    fn checkout_endpoint(&self) -> String {
        self.config
            .checkout
            .as_ref()
            .map_or_else(|| "/checkout".to_owned(), Clone::clone)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_endpoint_resolver() {
        let resolver = DefaultEndpointResolver::new();
        let params = ProductQueryParams::default();

        assert_eq!(resolver.products_endpoint(&params), "/products");
        assert_eq!(resolver.product_endpoint("prod-123"), "/products/prod-123");
        assert_eq!(resolver.cart_endpoint("cart-456"), "/cart");
        assert_eq!(resolver.add_to_cart_endpoint(), "/cart/add");
        assert_eq!(resolver.update_cart_item_endpoint("item-789"), "/cart/items/item-789");
        assert_eq!(resolver.remove_cart_item_endpoint("item-999"), "/cart/items/item-999");
        assert_eq!(resolver.create_order_endpoint(), "/orders");
        assert_eq!(resolver.order_endpoint("order-111"), "/orders/order-111");
        assert_eq!(resolver.checkout_endpoint(), "/checkout");
    }

    #[test]
    fn test_configurable_endpoint_resolver_defaults() {
        let config = EndpointConfig::default();
        let resolver = ConfigurableEndpointResolver::new(&config);
        let params = ProductQueryParams::default();

        assert_eq!(resolver.products_endpoint(&params), "/products");
        assert_eq!(resolver.product_endpoint("prod-123"), "/products/prod-123");
    }

    #[test]
    fn test_configurable_endpoint_resolver_custom() {
        let config = EndpointConfig {
            products: Some("/api/catalog".to_owned()),
            product: Some("/api/catalog/{id}".to_owned()),
            cart: Some("/basket".to_owned()),
            add_to_cart: Some("/basket/add".to_owned()),
            cart_item: Some("/basket/items/{id}".to_owned()),
            orders: Some("/purchases".to_owned()),
            order: Some("/purchases/{id}".to_owned()),
            checkout: Some("/payment".to_owned()),
        };

        let resolver = ConfigurableEndpointResolver::new(&config);
        let params = ProductQueryParams::default();

        assert_eq!(resolver.products_endpoint(&params), "/api/catalog");
        assert_eq!(resolver.product_endpoint("sku-789"), "/api/catalog/sku-789");
        assert_eq!(resolver.cart_endpoint("cart-123"), "/basket");
        assert_eq!(resolver.add_to_cart_endpoint(), "/basket/add");
        assert_eq!(resolver.update_cart_item_endpoint("item-456"), "/basket/items/item-456");
        assert_eq!(resolver.remove_cart_item_endpoint("item-999"), "/basket/items/item-999");
        assert_eq!(resolver.create_order_endpoint(), "/purchases");
        assert_eq!(resolver.order_endpoint("order-abc"), "/purchases/order-abc");
        assert_eq!(resolver.checkout_endpoint(), "/payment");
    }

    #[test]
    fn test_configurable_endpoint_resolver_partial() {
        let config = EndpointConfig { products: Some("/catalog".to_owned()), ..Default::default() };

        let resolver = ConfigurableEndpointResolver::new(&config);
        let params = ProductQueryParams::default();

        assert_eq!(resolver.products_endpoint(&params), "/catalog");
        assert_eq!(resolver.product_endpoint("prod-123"), "/products/prod-123");
    }

    #[test]
    fn test_template_substitution() {
        let config = EndpointConfig {
            product: Some("/items/{id}/details".to_owned()),
            ..Default::default()
        };

        let resolver = ConfigurableEndpointResolver::new(&config);
        assert_eq!(resolver.product_endpoint("xyz"), "/items/xyz/details");
    }

    #[test]
    fn test_default_endpoint_resolver_default_trait() {
        let resolver = <DefaultEndpointResolver as Default>::default();
        assert_eq!(resolver.checkout_endpoint(), "/checkout");
    }

    #[test]
    fn test_product_endpoint_with_special_characters() {
        let resolver = DefaultEndpointResolver::new();
        assert_eq!(resolver.product_endpoint("prod-123_abc.xyz"), "/products/prod-123_abc.xyz");
    }

    #[test]
    fn test_product_endpoint_with_unicode() {
        let resolver = DefaultEndpointResolver::new();
        assert_eq!(resolver.product_endpoint("产品-123"), "/products/产品-123");
    }

    #[test]
    fn test_empty_product_id() {
        let resolver = DefaultEndpointResolver::new();
        assert_eq!(resolver.product_endpoint(""), "/products/");
    }

    #[test]
    fn test_empty_cart_id() {
        let resolver = DefaultEndpointResolver::new();
        assert_eq!(resolver.cart_endpoint(""), "/cart");
    }

    #[test]
    fn test_empty_order_id() {
        let resolver = DefaultEndpointResolver::new();
        assert_eq!(resolver.order_endpoint(""), "/orders/");
    }

    #[test]
    fn test_configurable_multiple_template_placeholders() {
        let config = EndpointConfig {
            product: Some("/api/{id}/details/{id}".to_owned()),
            ..Default::default()
        };

        let resolver = ConfigurableEndpointResolver::new(&config);
        assert_eq!(resolver.product_endpoint("xyz"), "/api/xyz/details/xyz");
    }

    #[test]
    fn test_configurable_no_template_placeholder() {
        let config =
            EndpointConfig { product: Some("/static-product".to_owned()), ..Default::default() };

        let resolver = ConfigurableEndpointResolver::new(&config);
        assert_eq!(resolver.product_endpoint("ignored"), "/static-product");
    }

    #[test]
    fn test_configurable_template_with_special_chars() {
        let config = EndpointConfig {
            product: Some("/items/{id}?format=json".to_owned()),
            ..Default::default()
        };

        let resolver = ConfigurableEndpointResolver::new(&config);
        assert_eq!(resolver.product_endpoint("123"), "/items/123?format=json");
    }

    #[test]
    fn test_update_cart_item_with_empty_id() {
        let resolver = DefaultEndpointResolver::new();
        assert_eq!(resolver.update_cart_item_endpoint(""), "/cart/items/");
    }

    #[test]
    fn test_remove_cart_item_with_long_id() {
        let resolver = DefaultEndpointResolver::new();
        let long_id = "a".repeat(1000);
        assert_eq!(resolver.remove_cart_item_endpoint(&long_id), format!("/cart/items/{long_id}"));
    }

    #[test]
    fn test_all_endpoints_with_same_resolver() {
        let resolver = DefaultEndpointResolver::new();
        let params = ProductQueryParams::default();

        // Verify all methods work with same resolver instance
        let _ = resolver.products_endpoint(&params);
        let _ = resolver.product_endpoint("1");
        let _ = resolver.cart_endpoint("2");
        let _ = resolver.add_to_cart_endpoint();
        let _ = resolver.update_cart_item_endpoint("3");
        let _ = resolver.remove_cart_item_endpoint("4");
        let _ = resolver.create_order_endpoint();
        let _ = resolver.order_endpoint("5");
        let _ = resolver.checkout_endpoint();
    }

    #[test]
    fn test_configurable_clone() {
        let config = EndpointConfig { products: Some("/catalog".to_owned()), ..Default::default() };
        let resolver = ConfigurableEndpointResolver::new(&config);
        let cloned = resolver.clone();

        let params = ProductQueryParams::default();
        assert_eq!(resolver.products_endpoint(&params), cloned.products_endpoint(&params));
    }
}
