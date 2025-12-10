//! Order management tools for TAP-MCP bridge.
//!
//! This module provides functions for creating and retrieving orders
//! with TAP authentication.

use serde::{Deserialize, Serialize};
use tracing::{info, instrument};

use crate::{
    error::Result,
    mcp::{
        http::{
            HttpMethod, build_url_with_query, create_http_client, execute_tap_request_with_acro,
        },
        models::{Address, Order},
    },
    tap::{InteractionType, TapSigner, acro::ContextualData},
};

/// Parameters for creating an order.
#[derive(Debug, Deserialize)]
pub struct CreateOrderParams {
    /// Merchant URL.
    pub merchant_url: String,
    /// Consumer identifier.
    pub consumer_id: String,
    /// Cart ID.
    pub cart_id: String,
    /// Shipping address.
    pub shipping_address: Address,
    /// Billing address (None uses shipping address).
    pub billing_address: Option<Address>,
    /// Delivery option (e.g., "standard", "express").
    pub delivery_option: Option<String>,
    /// Promotional code.
    pub promo_code: Option<String>,

    // ACRO contextual data fields
    /// ISO 3166-1 alpha-2 country code (e.g., "US").
    pub country_code: String,
    /// Postal code or city/state (max 16 chars).
    pub zip: String,
    /// Consumer device IP address.
    pub ip_address: String,
    /// Browser/device user agent.
    pub user_agent: String,
    /// Operating system platform.
    pub platform: String,
}

/// Parameters for retrieving an order.
#[derive(Debug, Deserialize)]
pub struct GetOrderParams {
    /// Merchant URL.
    pub merchant_url: String,
    /// Consumer identifier.
    pub consumer_id: String,
    /// Order ID.
    pub order_id: String,

    // ACRO contextual data fields
    /// ISO 3166-1 alpha-2 country code (e.g., "US").
    pub country_code: String,
    /// Postal code or city/state (max 16 chars).
    pub zip: String,
    /// Consumer device IP address.
    pub ip_address: String,
    /// Browser/device user agent.
    pub user_agent: String,
    /// Operating system platform.
    pub platform: String,
}

/// Request body for creating an order.
#[derive(Debug, Serialize)]
struct CreateOrderRequest {
    cart_id: String,
    shipping_address: Address,
    billing_address: Address,
    #[serde(skip_serializing_if = "Option::is_none")]
    delivery_option: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    promo_code: Option<String>,
}

/// Creates an order from a shopping cart with TAP authentication.
///
/// # Errors
///
/// Returns error if signature generation, HTTP request, or response parsing fails.
///
/// # Examples
///
/// ```no_run
/// use ed25519_dalek::SigningKey;
/// use tap_mcp_bridge::{
///     mcp::{
///         models::Address,
///         orders::{CreateOrderParams, create_order},
///     },
///     tap::TapSigner,
/// };
///
/// # async fn example() -> tap_mcp_bridge::error::Result<()> {
/// let signing_key = SigningKey::from_bytes(&[0u8; 32]);
/// let signer = TapSigner::new(signing_key, "agent-123", "https://agent.example.com");
///
/// let shipping_address = Address {
///     name: "John Doe".into(),
///     street: "123 Main St".into(),
///     city: "San Francisco".into(),
///     state: "CA".into(),
///     postal_code: "94102".into(),
///     country: "US".into(),
///     phone: Some("+1-555-1234".into()),
/// };
///
/// let params = CreateOrderParams {
///     merchant_url: "https://merchant.com".into(),
///     consumer_id: "user-123".into(),
///     cart_id: "cart-456".into(),
///     shipping_address,
///     billing_address: None,
///     delivery_option: Some("standard".into()),
///     promo_code: None,
///     country_code: "US".into(),
///     zip: "94025".into(),
///     ip_address: "192.168.1.100".into(),
///     user_agent: "Mozilla/5.0".into(),
///     platform: "macOS".into(),
/// };
///
/// let order = create_order(&signer, params).await?;
/// println!("Order ID: {}", order.order_id);
/// # Ok(())
/// # }
/// ```
#[instrument(skip(signer, params), fields(merchant_url = %params.merchant_url, consumer_id = %params.consumer_id))]
pub async fn create_order(signer: &TapSigner, params: CreateOrderParams) -> Result<Order> {
    info!("creating order");

    let contextual_data = ContextualData {
        country_code: params.country_code,
        zip: params.zip,
        ip_address: params.ip_address,
        device_data: crate::tap::acro::DeviceData {
            user_agent: params.user_agent,
            platform: params.platform,
        },
    };

    let billing_address = params
        .billing_address
        .clone()
        .unwrap_or_else(|| params.shipping_address.clone());

    let request_body = CreateOrderRequest {
        cart_id: params.cart_id,
        shipping_address: params.shipping_address,
        billing_address,
        delivery_option: params.delivery_option,
        promo_code: params.promo_code,
    };

    let path = build_url_with_query("/orders", &[("consumer_id", &params.consumer_id)])?;

    let client = create_http_client()?;
    let response = execute_tap_request_with_acro(
        &client,
        signer,
        &params.merchant_url,
        &params.consumer_id,
        HttpMethod::Post,
        &path,
        InteractionType::Checkout,
        contextual_data,
        Some(&request_body),
    )
    .await?;

    let order: Order = serde_json::from_slice(&response).map_err(|e| {
        crate::error::BridgeError::MerchantError(format!("failed to parse order: {e}"))
    })?;

    Ok(order)
}

/// Retrieves order details with TAP authentication.
///
/// # Errors
///
/// Returns error if signature generation, HTTP request, or response parsing fails.
///
/// # Examples
///
/// ```no_run
/// use ed25519_dalek::SigningKey;
/// use tap_mcp_bridge::{
///     mcp::orders::{GetOrderParams, get_order},
///     tap::TapSigner,
/// };
///
/// # async fn example() -> tap_mcp_bridge::error::Result<()> {
/// let signing_key = SigningKey::from_bytes(&[0u8; 32]);
/// let signer = TapSigner::new(signing_key, "agent-123", "https://agent.example.com");
///
/// let params = GetOrderParams {
///     merchant_url: "https://merchant.com".into(),
///     consumer_id: "user-123".into(),
///     order_id: "order-789".into(),
///     country_code: "US".into(),
///     zip: "94025".into(),
///     ip_address: "192.168.1.100".into(),
///     user_agent: "Mozilla/5.0".into(),
///     platform: "macOS".into(),
/// };
///
/// let order = get_order(&signer, params).await?;
/// println!("Order status: {:?}", order.status);
/// # Ok(())
/// # }
/// ```
#[instrument(skip(signer, params), fields(merchant_url = %params.merchant_url, order_id = %params.order_id))]
pub async fn get_order(signer: &TapSigner, params: GetOrderParams) -> Result<Order> {
    info!("fetching order details");

    let contextual_data = ContextualData {
        country_code: params.country_code,
        zip: params.zip,
        ip_address: params.ip_address,
        device_data: crate::tap::acro::DeviceData {
            user_agent: params.user_agent,
            platform: params.platform,
        },
    };

    let path = build_url_with_query(&format!("/orders/{}", params.order_id), &[(
        "consumer_id",
        &params.consumer_id,
    )])?;

    let client = create_http_client()?;
    let response = execute_tap_request_with_acro(
        &client,
        signer,
        &params.merchant_url,
        &params.consumer_id,
        HttpMethod::Get,
        &path,
        InteractionType::Browse,
        contextual_data,
        None::<&()>,
    )
    .await?;

    let order: Order = serde_json::from_slice(&response).map_err(|e| {
        crate::error::BridgeError::MerchantError(format!("failed to parse order: {e}"))
    })?;

    Ok(order)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_order_params() {
        let address = Address {
            name: "John Doe".to_owned(),
            street: "123 Main St".to_owned(),
            city: "San Francisco".to_owned(),
            state: "CA".to_owned(),
            postal_code: "94102".to_owned(),
            country: "US".to_owned(),
            phone: Some("+1-555-1234".to_owned()),
        };

        let params = CreateOrderParams {
            merchant_url: "https://merchant.com".to_owned(),
            consumer_id: "user-123".to_owned(),
            cart_id: "cart-456".to_owned(),
            shipping_address: address,
            billing_address: None,
            delivery_option: Some("express".to_owned()),
            promo_code: None,
            country_code: "US".to_owned(),
            zip: "94025".to_owned(),
            ip_address: "192.168.1.1".to_owned(),
            user_agent: "Mozilla/5.0".to_owned(),
            platform: "Linux".to_owned(),
        };

        assert_eq!(params.cart_id, "cart-456");
        assert_eq!(params.delivery_option.as_ref().unwrap(), "express");
    }

    #[test]
    fn test_create_order_params_separate_billing() {
        let shipping = Address {
            name: "John Doe".to_owned(),
            street: "123 Main St".to_owned(),
            city: "San Francisco".to_owned(),
            state: "CA".to_owned(),
            postal_code: "94102".to_owned(),
            country: "US".to_owned(),
            phone: Some("+1-555-1234".to_owned()),
        };

        let billing = Address {
            name: "John Doe".to_owned(),
            street: "456 Billing Ave".to_owned(),
            city: "Los Angeles".to_owned(),
            state: "CA".to_owned(),
            postal_code: "90001".to_owned(),
            country: "US".to_owned(),
            phone: None,
        };

        let params = CreateOrderParams {
            merchant_url: "https://merchant.com".to_owned(),
            consumer_id: "user-456".to_owned(),
            cart_id: "cart-789".to_owned(),
            shipping_address: shipping,
            billing_address: Some(billing),
            delivery_option: Some("standard".to_owned()),
            promo_code: Some("SAVE10".to_owned()),
            country_code: "US".to_owned(),
            zip: "94025".to_owned(),
            ip_address: "192.168.1.1".to_owned(),
            user_agent: "Chrome/120.0".to_owned(),
            platform: "Windows".to_owned(),
        };

        assert!(params.billing_address.is_some());
        assert_eq!(params.promo_code.as_ref().unwrap(), "SAVE10");
    }

    #[test]
    fn test_create_order_params_no_options() {
        let address = Address {
            name: "Jane Smith".to_owned(),
            street: "789 Oak St".to_owned(),
            city: "Portland".to_owned(),
            state: "OR".to_owned(),
            postal_code: "97201".to_owned(),
            country: "US".to_owned(),
            phone: None,
        };

        let params = CreateOrderParams {
            merchant_url: "https://shop.example.com".to_owned(),
            consumer_id: "user-999".to_owned(),
            cart_id: "cart-abc".to_owned(),
            shipping_address: address,
            billing_address: None,
            delivery_option: None,
            promo_code: None,
            country_code: "CA".to_owned(),
            zip: "M5H2N2".to_owned(),
            ip_address: "10.0.0.1".to_owned(),
            user_agent: "Safari/17.0".to_owned(),
            platform: "macOS".to_owned(),
        };

        assert!(params.delivery_option.is_none());
        assert!(params.promo_code.is_none());
        assert!(params.billing_address.is_none());
    }

    #[test]
    fn test_get_order_params_creation() {
        let params = GetOrderParams {
            merchant_url: "https://merchant.com".to_owned(),
            consumer_id: "user-123".to_owned(),
            order_id: "order-456".to_owned(),
            country_code: "GB".to_owned(),
            zip: "SW1A1AA".to_owned(),
            ip_address: "192.168.0.100".to_owned(),
            user_agent: "Firefox/121.0".to_owned(),
            platform: "Linux".to_owned(),
        };

        assert_eq!(params.order_id, "order-456");
    }

    #[test]
    fn test_create_order_request_serialization() {
        let shipping = Address {
            name: "Test User".to_owned(),
            street: "123 Test St".to_owned(),
            city: "Test City".to_owned(),
            state: "TS".to_owned(),
            postal_code: "12345".to_owned(),
            country: "US".to_owned(),
            phone: None,
        };

        let billing = Address {
            name: "Test User".to_owned(),
            street: "456 Bill St".to_owned(),
            city: "Bill City".to_owned(),
            state: "TS".to_owned(),
            postal_code: "67890".to_owned(),
            country: "US".to_owned(),
            phone: Some("+1-555-0000".to_owned()),
        };

        let request = CreateOrderRequest {
            cart_id: "cart-test".to_owned(),
            shipping_address: shipping,
            billing_address: billing,
            delivery_option: Some("overnight".to_owned()),
            promo_code: Some("TEST20".to_owned()),
        };

        let json = serde_json::to_string(&request).unwrap();
        assert!(json.contains("\"cart_id\":\"cart-test\""));
        assert!(json.contains("\"delivery_option\":\"overnight\""));
        assert!(json.contains("\"promo_code\":\"TEST20\""));
    }

    #[test]
    fn test_create_order_request_no_optionals() {
        let address = Address {
            name: "Test".to_owned(),
            street: "Test".to_owned(),
            city: "Test".to_owned(),
            state: "TS".to_owned(),
            postal_code: "12345".to_owned(),
            country: "US".to_owned(),
            phone: None,
        };

        let request = CreateOrderRequest {
            cart_id: "cart-minimal".to_owned(),
            shipping_address: address.clone(),
            billing_address: address,
            delivery_option: None,
            promo_code: None,
        };

        let json = serde_json::to_string(&request).unwrap();
        assert!(!json.contains("delivery_option"));
        assert!(!json.contains("promo_code"));
    }

    #[test]
    fn test_delivery_options() {
        let options = vec!["standard", "express", "overnight", "same_day", "economy"];

        for option in options {
            let address = Address {
                name: "Test".to_owned(),
                street: "Test".to_owned(),
                city: "Test".to_owned(),
                state: "TS".to_owned(),
                postal_code: "12345".to_owned(),
                country: "US".to_owned(),
                phone: None,
            };

            let params = CreateOrderParams {
                merchant_url: "https://merchant.com".to_owned(),
                consumer_id: "user-test".to_owned(),
                cart_id: "cart-test".to_owned(),
                shipping_address: address,
                billing_address: None,
                delivery_option: Some(option.to_owned()),
                promo_code: None,
                country_code: "US".to_owned(),
                zip: "12345".to_owned(),
                ip_address: "192.168.1.1".to_owned(),
                user_agent: "Test/1.0".to_owned(),
                platform: "Test".to_owned(),
            };

            assert_eq!(params.delivery_option.as_ref().unwrap(), option);
        }
    }

    #[test]
    fn test_promo_codes() {
        let promo_codes = vec!["SAVE10", "WELCOME20", "FREESHIP", "SPECIAL50", ""];

        for code in promo_codes {
            let address = Address {
                name: "Test".to_owned(),
                street: "Test".to_owned(),
                city: "Test".to_owned(),
                state: "TS".to_owned(),
                postal_code: "12345".to_owned(),
                country: "US".to_owned(),
                phone: None,
            };

            let params = CreateOrderParams {
                merchant_url: "https://merchant.com".to_owned(),
                consumer_id: "user-test".to_owned(),
                cart_id: "cart-test".to_owned(),
                shipping_address: address,
                billing_address: None,
                delivery_option: None,
                promo_code: Some(code.to_owned()),
                country_code: "US".to_owned(),
                zip: "12345".to_owned(),
                ip_address: "192.168.1.1".to_owned(),
                user_agent: "Test/1.0".to_owned(),
                platform: "Test".to_owned(),
            };

            assert_eq!(params.promo_code.as_ref().unwrap(), code);
        }
    }

    #[test]
    fn test_order_id_formats() {
        let order_ids = vec![
            "order-simple",
            "ORDER-UPPERCASE",
            "order_with_underscore",
            "order-123-abc-xyz",
            "o",
        ];

        for order_id in order_ids {
            let params = GetOrderParams {
                merchant_url: "https://merchant.com".to_owned(),
                consumer_id: "user-test".to_owned(),
                order_id: order_id.to_owned(),
                country_code: "US".to_owned(),
                zip: "12345".to_owned(),
                ip_address: "192.168.1.1".to_owned(),
                user_agent: "Test/1.0".to_owned(),
                platform: "Test".to_owned(),
            };

            assert_eq!(params.order_id, order_id);
        }
    }
}
