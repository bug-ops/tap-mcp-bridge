//! Shopping cart management tools for TAP-MCP bridge.
//!
//! This module provides functions for managing shopping cart operations
//! with TAP authentication.

use reqwest::Client;
use serde::{Deserialize, Serialize};
use tracing::{info, instrument};

use crate::{
    error::{BridgeError, Result},
    mcp::models::CartState,
    tap::{InteractionType, TapSigner, acro::ContextualData},
};

/// Parameters for adding item to cart.
#[derive(Debug, Deserialize)]
pub struct AddToCartParams {
    /// Merchant URL.
    pub merchant_url: String,
    /// Consumer identifier.
    pub consumer_id: String,
    /// Cart ID (None creates new cart).
    pub cart_id: Option<String>,
    /// Product ID to add.
    pub product_id: String,
    /// Product variant ID (optional).
    pub variant_id: Option<String>,
    /// Quantity to add.
    pub quantity: u32,

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

/// Parameters for getting cart state.
#[derive(Debug, Deserialize)]
pub struct GetCartParams {
    /// Merchant URL.
    pub merchant_url: String,
    /// Consumer identifier.
    pub consumer_id: String,
    /// Cart ID.
    pub cart_id: String,

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

/// Parameters for updating cart item.
#[derive(Debug, Deserialize)]
pub struct UpdateCartItemParams {
    /// Merchant URL.
    pub merchant_url: String,
    /// Consumer identifier.
    pub consumer_id: String,
    /// Cart ID.
    pub cart_id: String,
    /// Cart item ID.
    pub item_id: String,
    /// New quantity.
    pub quantity: u32,

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

/// Parameters for removing item from cart.
#[derive(Debug, Deserialize)]
pub struct RemoveFromCartParams {
    /// Merchant URL.
    pub merchant_url: String,
    /// Consumer identifier.
    pub consumer_id: String,
    /// Cart ID.
    pub cart_id: String,
    /// Cart item ID to remove.
    pub item_id: String,

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

/// Request body for add to cart.
#[derive(Debug, Serialize, Deserialize)]
struct AddToCartRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    cart_id: Option<String>,
    product_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    variant_id: Option<String>,
    quantity: u32,
}

/// Request body for update cart item.
#[derive(Debug, Serialize, Deserialize)]
struct UpdateCartItemRequest {
    quantity: u32,
}

/// Adds item to shopping cart with TAP authentication.
///
/// # Errors
///
/// Returns error if signature generation, HTTP request, or response parsing fails.
#[instrument(skip(signer, params), fields(merchant_url = %params.merchant_url, consumer_id = %params.consumer_id))]
pub async fn add_to_cart(signer: &TapSigner, params: AddToCartParams) -> Result<CartState> {
    info!("adding item to cart");

    let contextual_data = ContextualData {
        country_code: params.country_code,
        zip: params.zip,
        ip_address: params.ip_address,
        device_data: crate::tap::acro::DeviceData {
            user_agent: params.user_agent,
            platform: params.platform,
        },
    };

    let request_body = AddToCartRequest {
        cart_id: params.cart_id,
        product_id: params.product_id,
        variant_id: params.variant_id,
        quantity: params.quantity,
    };

    let path = format!("/cart/add?consumer_id={}", params.consumer_id);

    let response = execute_tap_request_with_acro(
        signer,
        &params.merchant_url,
        &params.consumer_id,
        "POST",
        path,
        InteractionType::Checkout,
        contextual_data,
        Some(&request_body),
    )
    .await?;

    let cart: CartState = serde_json::from_slice(&response)
        .map_err(|e| BridgeError::MerchantError(format!("failed to parse cart state: {e}")))?;

    Ok(cart)
}

/// Retrieves current cart state with TAP authentication.
///
/// # Errors
///
/// Returns error if signature generation, HTTP request, or response parsing fails.
#[instrument(skip(signer, params), fields(merchant_url = %params.merchant_url, cart_id = %params.cart_id))]
pub async fn get_cart(signer: &TapSigner, params: GetCartParams) -> Result<CartState> {
    info!("fetching cart state");

    let contextual_data = ContextualData {
        country_code: params.country_code,
        zip: params.zip,
        ip_address: params.ip_address,
        device_data: crate::tap::acro::DeviceData {
            user_agent: params.user_agent,
            platform: params.platform,
        },
    };

    let path = format!("/cart?cart_id={}&consumer_id={}", params.cart_id, params.consumer_id);

    let response = execute_tap_request_with_acro(
        signer,
        &params.merchant_url,
        &params.consumer_id,
        "GET",
        path,
        InteractionType::Browse,
        contextual_data,
        None::<&()>,
    )
    .await?;

    let cart: CartState = serde_json::from_slice(&response)
        .map_err(|e| BridgeError::MerchantError(format!("failed to parse cart state: {e}")))?;

    Ok(cart)
}

/// Updates cart item quantity with TAP authentication.
///
/// # Errors
///
/// Returns error if signature generation, HTTP request, or response parsing fails.
#[instrument(skip(signer, params), fields(merchant_url = %params.merchant_url, item_id = %params.item_id))]
pub async fn update_cart_item(
    signer: &TapSigner,
    params: UpdateCartItemParams,
) -> Result<CartState> {
    info!("updating cart item");

    let contextual_data = ContextualData {
        country_code: params.country_code,
        zip: params.zip,
        ip_address: params.ip_address,
        device_data: crate::tap::acro::DeviceData {
            user_agent: params.user_agent,
            platform: params.platform,
        },
    };

    let request_body = UpdateCartItemRequest { quantity: params.quantity };

    let path = format!("/cart/items/{}?consumer_id={}", params.item_id, params.consumer_id);

    let response = execute_tap_request_with_acro(
        signer,
        &params.merchant_url,
        &params.consumer_id,
        "PUT",
        path,
        InteractionType::Checkout,
        contextual_data,
        Some(&request_body),
    )
    .await?;

    let cart: CartState = serde_json::from_slice(&response)
        .map_err(|e| BridgeError::MerchantError(format!("failed to parse cart state: {e}")))?;

    Ok(cart)
}

/// Removes item from cart with TAP authentication.
///
/// # Errors
///
/// Returns error if signature generation, HTTP request, or response parsing fails.
#[instrument(skip(signer, params), fields(merchant_url = %params.merchant_url, item_id = %params.item_id))]
pub async fn remove_from_cart(
    signer: &TapSigner,
    params: RemoveFromCartParams,
) -> Result<CartState> {
    info!("removing item from cart");

    let contextual_data = ContextualData {
        country_code: params.country_code,
        zip: params.zip,
        ip_address: params.ip_address,
        device_data: crate::tap::acro::DeviceData {
            user_agent: params.user_agent,
            platform: params.platform,
        },
    };

    let path = format!("/cart/items/{}?consumer_id={}", params.item_id, params.consumer_id);

    let response = execute_tap_request_with_acro(
        signer,
        &params.merchant_url,
        &params.consumer_id,
        "DELETE",
        path,
        InteractionType::Checkout,
        contextual_data,
        None::<&()>,
    )
    .await?;

    let cart: CartState = serde_json::from_slice(&response)
        .map_err(|e| BridgeError::MerchantError(format!("failed to parse cart state: {e}")))?;

    Ok(cart)
}

/// Executes a TAP-authenticated HTTP request with ACRO and optional request body.
#[instrument(
    skip(signer, contextual_data, request_body),
    fields(merchant_url, consumer_id, method, path)
)]
#[allow(
    clippy::too_many_arguments,
    reason = "helper function needs all parameters"
)]
async fn execute_tap_request_with_acro<T: Serialize>(
    signer: &TapSigner,
    merchant_url: &str,
    consumer_id: &str,
    method: &str,
    path: String,
    interaction_type: InteractionType,
    contextual_data: ContextualData,
    request_body: Option<&T>,
) -> Result<Vec<u8>> {
    crate::mcp::tools::validate_consumer_id(consumer_id)?;

    let url = crate::mcp::tools::parse_merchant_url(merchant_url)?;
    let authority = url.host_str().ok_or_else(|| {
        BridgeError::InvalidMerchantUrl(format!("URL missing host: {merchant_url}"))
    })?;

    let nonce = uuid::Uuid::new_v4().to_string();
    let id_token = signer.generate_id_token(consumer_id, merchant_url, &nonce)?;
    let acro = signer.generate_acro(&nonce, &id_token.token, contextual_data)?;

    let body = if let Some(req_body) = request_body {
        serde_json::to_vec(req_body).map_err(|e| {
            BridgeError::CryptoError(format!("request body serialization failed: {e}"))
        })?
    } else {
        serde_json::to_vec(&acro)
            .map_err(|e| BridgeError::CryptoError(format!("ACRO serialization failed: {e}")))?
    };

    let signature = signer.sign_request(method, authority, &path, &body, interaction_type)?;

    let client = Client::new();

    let request = match method {
        "POST" => client.post(format!("{url}{path}")),
        "GET" => client.get(format!("{url}{path}")),
        "PUT" => client.put(format!("{url}{path}")),
        "DELETE" => client.delete(format!("{url}{path}")),
        _ => {
            return Err(BridgeError::InvalidMerchantUrl(format!(
                "unsupported HTTP method: {method}"
            )));
        }
    };

    let content_digest = TapSigner::compute_content_digest(&body);

    let response = request
        .header("Signature", &signature.signature)
        .header("Signature-Input", &signature.signature_input)
        .header("Signature-Agent", signature.agent_directory.as_ref())
        .header("Content-Digest", &content_digest)
        .header("Content-Type", "application/json")
        .body(body)
        .send()
        .await?;

    if !response.status().is_success() {
        return Err(BridgeError::MerchantError(format!(
            "merchant returned status {}",
            response.status()
        )));
    }

    let response_body = response.bytes().await.map_err(BridgeError::HttpError)?.to_vec();

    Ok(response_body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add_to_cart_params_creation() {
        let params = AddToCartParams {
            merchant_url: "https://merchant.com".to_owned(),
            consumer_id: "user-123".to_owned(),
            cart_id: Some("cart-456".to_owned()),
            product_id: "prod-789".to_owned(),
            variant_id: None,
            quantity: 2,
            country_code: "US".to_owned(),
            zip: "94025".to_owned(),
            ip_address: "192.168.1.1".to_owned(),
            user_agent: "Mozilla/5.0".to_owned(),
            platform: "Linux".to_owned(),
        };

        assert_eq!(params.product_id, "prod-789");
        assert_eq!(params.quantity, 2);
    }

    #[test]
    fn test_add_to_cart_params_new_cart() {
        let params = AddToCartParams {
            merchant_url: "https://shop.example.com".to_owned(),
            consumer_id: "new-user".to_owned(),
            cart_id: None,
            product_id: "prod-abc".to_owned(),
            variant_id: Some("var-small".to_owned()),
            quantity: 1,
            country_code: "CA".to_owned(),
            zip: "M5H2N2".to_owned(),
            ip_address: "10.0.0.1".to_owned(),
            user_agent: "Chrome/120.0".to_owned(),
            platform: "Windows".to_owned(),
        };

        assert!(params.cart_id.is_none());
        assert!(params.variant_id.is_some());
    }

    #[test]
    fn test_add_to_cart_params_quantity_edge_cases() {
        let quantities = vec![0, 1, 10, 100, u32::MAX];

        for qty in quantities {
            let params = AddToCartParams {
                merchant_url: "https://merchant.com".to_owned(),
                consumer_id: "user-test".to_owned(),
                cart_id: Some("cart-test".to_owned()),
                product_id: "prod-test".to_owned(),
                variant_id: None,
                quantity: qty,
                country_code: "US".to_owned(),
                zip: "12345".to_owned(),
                ip_address: "192.168.1.1".to_owned(),
                user_agent: "Test/1.0".to_owned(),
                platform: "Test".to_owned(),
            };

            assert_eq!(params.quantity, qty);
        }
    }

    #[test]
    fn test_get_cart_params_creation() {
        let params = GetCartParams {
            merchant_url: "https://merchant.com".to_owned(),
            consumer_id: "user-123".to_owned(),
            cart_id: "cart-abc".to_owned(),
            country_code: "GB".to_owned(),
            zip: "SW1A1AA".to_owned(),
            ip_address: "192.168.0.100".to_owned(),
            user_agent: "Safari/17.0".to_owned(),
            platform: "macOS".to_owned(),
        };

        assert_eq!(params.cart_id, "cart-abc");
        assert_eq!(params.country_code, "GB");
    }

    #[test]
    fn test_update_cart_item_params_creation() {
        let params = UpdateCartItemParams {
            merchant_url: "https://merchant.com".to_owned(),
            consumer_id: "user-456".to_owned(),
            cart_id: "cart-789".to_owned(),
            item_id: "item-xyz".to_owned(),
            quantity: 5,
            country_code: "FR".to_owned(),
            zip: "75001".to_owned(),
            ip_address: "172.16.0.1".to_owned(),
            user_agent: "Firefox/121.0".to_owned(),
            platform: "Linux".to_owned(),
        };

        assert_eq!(params.item_id, "item-xyz");
        assert_eq!(params.quantity, 5);
    }

    #[test]
    fn test_update_cart_item_params_zero_quantity() {
        let params = UpdateCartItemParams {
            merchant_url: "https://merchant.com".to_owned(),
            consumer_id: "user-test".to_owned(),
            cart_id: "cart-test".to_owned(),
            item_id: "item-test".to_owned(),
            quantity: 0,
            country_code: "US".to_owned(),
            zip: "12345".to_owned(),
            ip_address: "192.168.1.1".to_owned(),
            user_agent: "Test/1.0".to_owned(),
            platform: "Test".to_owned(),
        };

        assert_eq!(params.quantity, 0);
    }

    #[test]
    fn test_remove_from_cart_params_creation() {
        let params = RemoveFromCartParams {
            merchant_url: "https://merchant.com".to_owned(),
            consumer_id: "user-999".to_owned(),
            cart_id: "cart-remove".to_owned(),
            item_id: "item-remove".to_owned(),
            country_code: "DE".to_owned(),
            zip: "10115".to_owned(),
            ip_address: "192.168.100.1".to_owned(),
            user_agent: "Edge/120.0".to_owned(),
            platform: "Windows".to_owned(),
        };

        assert_eq!(params.item_id, "item-remove");
    }

    #[test]
    fn test_add_to_cart_request_serialization() {
        let request = AddToCartRequest {
            cart_id: Some("cart-123".to_owned()),
            product_id: "prod-456".to_owned(),
            variant_id: Some("var-large".to_owned()),
            quantity: 3,
        };

        let json = serde_json::to_string(&request).unwrap();
        assert!(json.contains("\"cart_id\":\"cart-123\""));
        assert!(json.contains("\"product_id\":\"prod-456\""));
        assert!(json.contains("\"variant_id\":\"var-large\""));
        assert!(json.contains("\"quantity\":3"));
    }

    #[test]
    fn test_add_to_cart_request_no_cart_id() {
        let request = AddToCartRequest {
            cart_id: None,
            product_id: "prod-new".to_owned(),
            variant_id: None,
            quantity: 1,
        };

        let json = serde_json::to_string(&request).unwrap();
        assert!(!json.contains("cart_id"));
        assert!(json.contains("\"product_id\":\"prod-new\""));
    }

    #[test]
    fn test_update_cart_item_request() {
        let request = UpdateCartItemRequest { quantity: 5 };
        let json = serde_json::to_string(&request).unwrap();
        assert!(json.contains("\"quantity\":5"));
    }

    #[test]
    fn test_update_cart_item_request_deserialization() {
        let json = r#"{"quantity":10}"#;
        let request: UpdateCartItemRequest = serde_json::from_str(json).unwrap();
        assert_eq!(request.quantity, 10);
    }

    #[test]
    fn test_add_to_cart_request_with_variant() {
        let request = AddToCartRequest {
            cart_id: Some("cart-variant".to_owned()),
            product_id: "prod-shirt".to_owned(),
            variant_id: Some("var-xl-red".to_owned()),
            quantity: 2,
        };

        let json = serde_json::to_string(&request).unwrap();
        let parsed: AddToCartRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.product_id, "prod-shirt");
        assert_eq!(parsed.variant_id.as_ref().unwrap(), "var-xl-red");
    }

    #[test]
    fn test_cart_id_formats() {
        let cart_ids =
            vec!["cart-simple", "CART-UPPERCASE", "cart_with_underscore", "cart-123-abc-xyz", "c"];

        for cart_id in cart_ids {
            let params = GetCartParams {
                merchant_url: "https://merchant.com".to_owned(),
                consumer_id: "user-test".to_owned(),
                cart_id: cart_id.to_owned(),
                country_code: "US".to_owned(),
                zip: "12345".to_owned(),
                ip_address: "192.168.1.1".to_owned(),
                user_agent: "Test/1.0".to_owned(),
                platform: "Test".to_owned(),
            };

            assert_eq!(params.cart_id, cart_id);
        }
    }

    #[test]
    fn test_item_id_formats() {
        let item_ids =
            vec!["item-simple", "ITEM-UPPERCASE", "item_with_underscore", "item-123-abc-xyz", "i"];

        for item_id in item_ids {
            let params = RemoveFromCartParams {
                merchant_url: "https://merchant.com".to_owned(),
                consumer_id: "user-test".to_owned(),
                cart_id: "cart-test".to_owned(),
                item_id: item_id.to_owned(),
                country_code: "US".to_owned(),
                zip: "12345".to_owned(),
                ip_address: "192.168.1.1".to_owned(),
                user_agent: "Test/1.0".to_owned(),
                platform: "Test".to_owned(),
            };

            assert_eq!(params.item_id, item_id);
        }
    }

    #[test]
    fn test_variant_id_none_vs_some() {
        let params_without = AddToCartParams {
            merchant_url: "https://merchant.com".to_owned(),
            consumer_id: "user-test".to_owned(),
            cart_id: Some("cart-test".to_owned()),
            product_id: "prod-test".to_owned(),
            variant_id: None,
            quantity: 1,
            country_code: "US".to_owned(),
            zip: "12345".to_owned(),
            ip_address: "192.168.1.1".to_owned(),
            user_agent: "Test/1.0".to_owned(),
            platform: "Test".to_owned(),
        };

        let params_with = AddToCartParams {
            merchant_url: "https://merchant.com".to_owned(),
            consumer_id: "user-test".to_owned(),
            cart_id: Some("cart-test".to_owned()),
            product_id: "prod-test".to_owned(),
            variant_id: Some("var-test".to_owned()),
            quantity: 1,
            country_code: "US".to_owned(),
            zip: "12345".to_owned(),
            ip_address: "192.168.1.1".to_owned(),
            user_agent: "Test/1.0".to_owned(),
            platform: "Test".to_owned(),
        };

        assert!(params_without.variant_id.is_none());
        assert!(params_with.variant_id.is_some());
    }

    #[test]
    fn test_multiple_operations_same_cart() {
        let cart_id = "cart-shared";

        let add_params = AddToCartParams {
            merchant_url: "https://merchant.com".to_owned(),
            consumer_id: "user-test".to_owned(),
            cart_id: Some(cart_id.to_owned()),
            product_id: "prod-1".to_owned(),
            variant_id: None,
            quantity: 1,
            country_code: "US".to_owned(),
            zip: "12345".to_owned(),
            ip_address: "192.168.1.1".to_owned(),
            user_agent: "Test/1.0".to_owned(),
            platform: "Test".to_owned(),
        };

        let get_params = GetCartParams {
            merchant_url: "https://merchant.com".to_owned(),
            consumer_id: "user-test".to_owned(),
            cart_id: cart_id.to_owned(),
            country_code: "US".to_owned(),
            zip: "12345".to_owned(),
            ip_address: "192.168.1.1".to_owned(),
            user_agent: "Test/1.0".to_owned(),
            platform: "Test".to_owned(),
        };

        assert_eq!(add_params.cart_id.as_ref().unwrap(), &get_params.cart_id);
    }
}
