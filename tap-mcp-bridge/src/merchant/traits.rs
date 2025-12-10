//! Core merchant API abstraction traits.
//!
//! This module defines the trait interfaces for flexible merchant integration.

use std::borrow::Cow;

use serde::de::DeserializeOwned;

use crate::{error::Result, mcp::models};

/// Abstraction over merchant-specific API behaviors.
///
/// This trait enables the bridge to communicate with merchants that have
/// different API conventions while maintaining type safety.
///
/// # Type Parameters
///
/// Each associated type represents a merchant's response format for that
/// operation. For standard TAP merchants, use the default models from
/// `crate::mcp::models`.
///
/// # Implementation Notes
///
/// - Implementors MUST ensure response types can deserialize merchant responses
/// - Field mapping is handled by `FieldMapper` trait
/// - Endpoint paths are resolved by `EndpointResolver` trait
pub trait MerchantApi: Send + Sync {
    /// Product catalog response type.
    type ProductCatalog: DeserializeOwned + Send;

    /// Single product response type.
    type Product: DeserializeOwned + Send;

    /// Cart state response type.
    type CartState: DeserializeOwned + Send;

    /// Order response type.
    type Order: DeserializeOwned + Send;

    /// Payment result response type.
    type PaymentResult: DeserializeOwned + Send;

    /// Returns the endpoint resolver for this merchant.
    fn endpoint_resolver(&self) -> &dyn EndpointResolver;

    /// Returns the field mapper for this merchant.
    fn field_mapper(&self) -> &dyn FieldMapper;

    /// Returns the request transformer (if any custom transformation needed).
    fn request_transformer(&self) -> Option<&dyn RequestTransformer> {
        None
    }

    /// Returns the response transformer (if any custom transformation needed).
    fn response_transformer(&self) -> Option<&dyn ResponseTransformer> {
        None
    }

    /// Converts this merchant's product catalog to standard format.
    ///
    /// # Errors
    ///
    /// Returns error if conversion fails due to incompatible data formats.
    fn to_standard_catalog(&self, catalog: Self::ProductCatalog) -> Result<models::ProductCatalog>;

    /// Converts this merchant's product to standard format.
    ///
    /// # Errors
    ///
    /// Returns error if conversion fails due to incompatible data formats.
    fn to_standard_product(&self, product: Self::Product) -> Result<models::Product>;

    /// Converts this merchant's cart state to standard format.
    ///
    /// # Errors
    ///
    /// Returns error if conversion fails due to incompatible data formats.
    fn to_standard_cart(&self, cart: Self::CartState) -> Result<models::CartState>;

    /// Converts this merchant's order to standard format.
    ///
    /// # Errors
    ///
    /// Returns error if conversion fails due to incompatible data formats.
    fn to_standard_order(&self, order: Self::Order) -> Result<models::Order>;

    /// Converts this merchant's payment result to standard format.
    ///
    /// # Errors
    ///
    /// Returns error if conversion fails due to incompatible data formats.
    fn to_standard_payment(&self, result: Self::PaymentResult) -> Result<models::PaymentResult>;
}

/// Query parameters for product listing.
#[derive(Debug, Clone, Default)]
pub struct ProductQueryParams {
    /// Consumer identifier.
    pub consumer_id: String,
    /// Product category filter.
    pub category: Option<String>,
    /// Search query.
    pub search: Option<String>,
    /// Page number.
    pub page: Option<u32>,
    /// Items per page.
    pub per_page: Option<u32>,
}

/// Resolves API endpoint paths for merchant operations.
///
/// Different merchants use different URL structures for their APIs.
/// This trait abstracts endpoint path resolution.
pub trait EndpointResolver: Send + Sync {
    /// Resolves the products list endpoint.
    ///
    /// # Arguments
    /// * `params` - Query parameters to include
    ///
    /// # Returns
    /// Full path with query string (e.g., "/api/v1/catalog?limit=20")
    fn products_endpoint(&self, params: &ProductQueryParams) -> String;

    /// Resolves the single product endpoint.
    fn product_endpoint(&self, product_id: &str) -> String;

    /// Resolves the cart retrieval endpoint.
    fn cart_endpoint(&self, cart_id: &str) -> String;

    /// Resolves the add-to-cart endpoint.
    fn add_to_cart_endpoint(&self) -> String;

    /// Resolves the cart item update endpoint.
    fn update_cart_item_endpoint(&self, item_id: &str) -> String;

    /// Resolves the cart item removal endpoint.
    fn remove_cart_item_endpoint(&self, item_id: &str) -> String;

    /// Resolves the order creation endpoint.
    fn create_order_endpoint(&self) -> String;

    /// Resolves the order retrieval endpoint.
    fn order_endpoint(&self, order_id: &str) -> String;

    /// Resolves the checkout/payment endpoint.
    fn checkout_endpoint(&self) -> String;
}

/// Maps field names between standard TAP format and merchant-specific format.
///
/// This trait handles the translation of field names in request and response
/// bodies. For example, mapping `consumer_id` to `customerId` or `buyer_id`.
pub trait FieldMapper: Send + Sync {
    /// Maps a standard field name to merchant-specific name.
    ///
    /// # Arguments
    /// * `standard_name` - The field name in standard TAP format
    ///
    /// # Returns
    /// The merchant-specific field name, or the original if no mapping exists
    fn map_request_field<'a>(&self, standard_name: &'a str) -> Cow<'a, str>;

    /// Maps a merchant-specific field name to standard name.
    fn map_response_field<'a>(&self, merchant_name: &'a str) -> Cow<'a, str>;

    /// Returns true if this mapper has any custom mappings.
    fn has_custom_mappings(&self) -> bool;
}

/// Transforms outgoing requests before sending to merchant.
///
/// Use this trait when requests need structural changes beyond field renaming.
pub trait RequestTransformer: Send + Sync {
    /// Transforms a request body before sending.
    ///
    /// # Arguments
    /// * `body` - The JSON value to transform
    /// * `operation` - The operation type (products, cart, order, payment)
    ///
    /// # Returns
    /// Transformed JSON value ready to send to merchant
    ///
    /// # Errors
    ///
    /// Returns error if transformation fails due to invalid structure or data.
    fn transform_request(
        &self,
        body: serde_json::Value,
        operation: crate::merchant::Operation,
    ) -> Result<serde_json::Value>;
}

/// Transforms incoming responses after receiving from merchant.
pub trait ResponseTransformer: Send + Sync {
    /// Transforms a response body after receiving.
    ///
    /// # Errors
    ///
    /// Returns error if transformation fails due to invalid structure or data.
    fn transform_response(
        &self,
        body: serde_json::Value,
        operation: crate::merchant::Operation,
    ) -> Result<serde_json::Value>;
}
