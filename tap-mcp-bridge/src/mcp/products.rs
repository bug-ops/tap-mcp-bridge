//! Product catalog tools for TAP-MCP bridge.
//!
//! This module provides functions for browsing merchant product catalogs
//! with TAP authentication.

use serde::Deserialize;
use tracing::{info, instrument};

use crate::{
    error::Result,
    mcp::{
        http::{
            HttpMethod, build_url_with_query, create_http_client, execute_tap_request_with_acro,
            validate_search_param,
        },
        models::{Product, ProductCatalog},
    },
    tap::{InteractionType, TapSigner, acro::ContextualData},
};

/// Parameters for getting product catalog.
#[derive(Debug, Deserialize)]
pub struct GetProductsParams {
    /// Merchant URL.
    pub merchant_url: String,
    /// Consumer identifier.
    pub consumer_id: String,

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

    // Filters
    /// Product category filter (optional).
    pub category: Option<String>,
    /// Search query (optional).
    pub search: Option<String>,
    /// Page number (optional, default 1).
    pub page: Option<u32>,
    /// Items per page (optional, default 20).
    pub per_page: Option<u32>,
}

/// Parameters for getting a single product.
#[derive(Debug, Deserialize)]
pub struct GetProductParams {
    /// Merchant URL.
    pub merchant_url: String,
    /// Consumer identifier.
    pub consumer_id: String,
    /// Product ID.
    pub product_id: String,

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

/// Response from merchant's product catalog endpoint.
#[derive(Debug, Deserialize)]
struct ProductCatalogResponse {
    products: Vec<Product>,
    total: u32,
    page: u32,
    #[serde(rename = "perPage")]
    per_page: u32,
}

/// Retrieves product catalog from merchant with TAP authentication.
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
///     mcp::products::{GetProductsParams, get_products},
///     tap::TapSigner,
/// };
///
/// # async fn example() -> tap_mcp_bridge::error::Result<()> {
/// let signing_key = SigningKey::from_bytes(&[0u8; 32]);
/// let signer = TapSigner::new(signing_key, "agent-123", "https://agent.example.com");
///
/// let params = GetProductsParams {
///     merchant_url: "https://merchant.com".into(),
///     consumer_id: "user-123".into(),
///     country_code: "US".into(),
///     zip: "94025".into(),
///     ip_address: "192.168.1.100".into(),
///     user_agent: "Mozilla/5.0".into(),
///     platform: "macOS".into(),
///     category: Some("electronics".into()),
///     search: None,
///     page: Some(1),
///     per_page: Some(20),
/// };
///
/// let catalog = get_products(&signer, params).await?;
/// println!("Found {} products", catalog.products.len());
/// # Ok(())
/// # }
/// ```
#[instrument(skip(signer, params), fields(merchant_url = %params.merchant_url, consumer_id = %params.consumer_id))]
pub async fn get_products(signer: &TapSigner, params: GetProductsParams) -> Result<ProductCatalog> {
    info!("fetching product catalog");

    let contextual_data = ContextualData {
        country_code: params.country_code,
        zip: params.zip,
        ip_address: params.ip_address,
        device_data: crate::tap::acro::DeviceData {
            user_agent: params.user_agent,
            platform: params.platform,
        },
    };

    // Validate search parameters
    if let Some(ref category) = params.category {
        validate_search_param(category, "category")?;
    }
    if let Some(ref search) = params.search {
        validate_search_param(search, "search")?;
    }

    // Build query parameters with proper URL encoding
    let mut query_params = vec![("consumer_id", params.consumer_id.as_str())];

    let category_str;
    if let Some(ref category) = params.category {
        category_str = category.as_str();
        query_params.push(("category", category_str));
    }

    let search_str;
    if let Some(ref search) = params.search {
        search_str = search.as_str();
        query_params.push(("search", search_str));
    }

    let page = params.page.unwrap_or(1);
    let per_page = params.per_page.unwrap_or(20);
    let page_str = page.to_string();
    let per_page_str = per_page.to_string();
    query_params.push(("page", &page_str));
    query_params.push(("per_page", &per_page_str));

    let path = build_url_with_query("/products", &query_params)?;

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

    let catalog: ProductCatalogResponse = serde_json::from_slice(&response).map_err(|e| {
        crate::error::BridgeError::MerchantError(format!("failed to parse catalog: {e}"))
    })?;

    Ok(ProductCatalog {
        products: catalog.products,
        total: catalog.total,
        page: catalog.page,
        per_page: catalog.per_page,
    })
}

/// Retrieves a single product from merchant with TAP authentication.
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
///     mcp::products::{GetProductParams, get_product},
///     tap::TapSigner,
/// };
///
/// # async fn example() -> tap_mcp_bridge::error::Result<()> {
/// let signing_key = SigningKey::from_bytes(&[0u8; 32]);
/// let signer = TapSigner::new(signing_key, "agent-123", "https://agent.example.com");
///
/// let params = GetProductParams {
///     merchant_url: "https://merchant.com".into(),
///     consumer_id: "user-123".into(),
///     product_id: "prod-456".into(),
///     country_code: "US".into(),
///     zip: "94025".into(),
///     ip_address: "192.168.1.100".into(),
///     user_agent: "Mozilla/5.0".into(),
///     platform: "macOS".into(),
/// };
///
/// let product = get_product(&signer, params).await?;
/// println!("Product: {}", product.name);
/// # Ok(())
/// # }
/// ```
#[instrument(skip(signer, params), fields(merchant_url = %params.merchant_url, product_id = %params.product_id))]
pub async fn get_product(signer: &TapSigner, params: GetProductParams) -> Result<Product> {
    info!("fetching product details");

    let contextual_data = ContextualData {
        country_code: params.country_code,
        zip: params.zip,
        ip_address: params.ip_address,
        device_data: crate::tap::acro::DeviceData {
            user_agent: params.user_agent,
            platform: params.platform,
        },
    };

    let path = build_url_with_query(&format!("/products/{}", params.product_id), &[(
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

    let product: Product = serde_json::from_slice(&response).map_err(|e| {
        crate::error::BridgeError::MerchantError(format!("failed to parse product: {e}"))
    })?;

    Ok(product)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_products_params_creation() {
        let params = GetProductsParams {
            merchant_url: "https://merchant.com".to_owned(),
            consumer_id: "user-123".to_owned(),
            country_code: "US".to_owned(),
            zip: "94025".to_owned(),
            ip_address: "192.168.1.1".to_owned(),
            user_agent: "Mozilla/5.0".to_owned(),
            platform: "Linux".to_owned(),
            category: Some("electronics".to_owned()),
            search: None,
            page: Some(1),
            per_page: Some(20),
        };

        assert_eq!(params.merchant_url, "https://merchant.com");
        assert_eq!(params.category.as_ref().unwrap(), "electronics");
    }

    #[test]
    fn test_get_products_params_no_filters() {
        let params = GetProductsParams {
            merchant_url: "https://shop.example.com".to_owned(),
            consumer_id: "consumer-abc".to_owned(),
            country_code: "CA".to_owned(),
            zip: "M5H2N2".to_owned(),
            ip_address: "10.0.0.1".to_owned(),
            user_agent: "Chrome/120.0".to_owned(),
            platform: "Windows".to_owned(),
            category: None,
            search: None,
            page: None,
            per_page: None,
        };

        assert!(params.category.is_none());
        assert!(params.search.is_none());
        assert!(params.page.is_none());
        assert!(params.per_page.is_none());
    }

    #[test]
    fn test_get_products_params_with_search() {
        let params = GetProductsParams {
            merchant_url: "https://merchant.com".to_owned(),
            consumer_id: "user-456".to_owned(),
            country_code: "GB".to_owned(),
            zip: "SW1A1AA".to_owned(),
            ip_address: "192.168.1.100".to_owned(),
            user_agent: "Safari/17.0".to_owned(),
            platform: "macOS".to_owned(),
            category: Some("books".to_owned()),
            search: Some("rust programming".to_owned()),
            page: Some(2),
            per_page: Some(50),
        };

        assert_eq!(params.search.as_ref().unwrap(), "rust programming");
        assert_eq!(params.page, Some(2));
        assert_eq!(params.per_page, Some(50));
    }

    #[test]
    fn test_get_products_params_edge_case_large_page() {
        let params = GetProductsParams {
            merchant_url: "https://merchant.com".to_owned(),
            consumer_id: "user-789".to_owned(),
            country_code: "US".to_owned(),
            zip: "10001".to_owned(),
            ip_address: "172.16.0.1".to_owned(),
            user_agent: "Firefox/121.0".to_owned(),
            platform: "Linux".to_owned(),
            category: None,
            search: None,
            page: Some(u32::MAX),
            per_page: Some(100),
        };

        assert_eq!(params.page, Some(u32::MAX));
    }

    #[test]
    fn test_get_product_params_creation() {
        let params = GetProductParams {
            merchant_url: "https://merchant.com".to_owned(),
            consumer_id: "user-123".to_owned(),
            product_id: "prod-456".to_owned(),
            country_code: "US".to_owned(),
            zip: "94025".to_owned(),
            ip_address: "192.168.1.1".to_owned(),
            user_agent: "Mozilla/5.0".to_owned(),
            platform: "Linux".to_owned(),
        };

        assert_eq!(params.product_id, "prod-456");
    }

    #[test]
    fn test_get_product_params_various_ids() {
        let product_ids =
            vec!["prod-simple", "PROD-UPPERCASE", "prod_with_underscore", "prod-123-abc-xyz", "a"];

        for product_id in product_ids {
            let params = GetProductParams {
                merchant_url: "https://merchant.com".to_owned(),
                consumer_id: "test-user".to_owned(),
                product_id: product_id.to_owned(),
                country_code: "FR".to_owned(),
                zip: "75001".to_owned(),
                ip_address: "192.168.0.1".to_owned(),
                user_agent: "TestAgent/1.0".to_owned(),
                platform: "iOS".to_owned(),
            };

            assert_eq!(params.product_id, product_id);
        }
    }

    #[test]
    fn test_product_catalog_response_deserialization() {
        let json = r#"{
            "products": [],
            "total": 150,
            "page": 3,
            "perPage": 25
        }"#;

        let response: ProductCatalogResponse = serde_json::from_str(json).unwrap();
        assert_eq!(response.products.len(), 0);
        assert_eq!(response.total, 150);
        assert_eq!(response.page, 3);
        assert_eq!(response.per_page, 25);
    }

    #[test]
    fn test_product_catalog_response_with_products() {
        let json = r#"{
            "products": [
                {
                    "id": "prod-1",
                    "name": "Widget",
                    "description": "A widget",
                    "price": "19.99",
                    "currency": "USD",
                    "images": [],
                    "variants": [],
                    "inventory": 50
                }
            ],
            "total": 1,
            "page": 1,
            "perPage": 20
        }"#;

        let response: ProductCatalogResponse = serde_json::from_str(json).unwrap();
        assert_eq!(response.products.len(), 1);
        assert_eq!(response.products[0].id, "prod-1");
    }

    #[test]
    fn test_contextual_data_country_codes() {
        let country_codes = vec!["US", "CA", "GB", "FR", "DE", "JP", "AU"];

        for code in country_codes {
            let params = GetProductsParams {
                merchant_url: "https://merchant.com".to_owned(),
                consumer_id: "user-test".to_owned(),
                country_code: code.to_owned(),
                zip: "12345".to_owned(),
                ip_address: "192.168.1.1".to_owned(),
                user_agent: "Test/1.0".to_owned(),
                platform: "Test".to_owned(),
                category: None,
                search: None,
                page: None,
                per_page: None,
            };

            assert_eq!(params.country_code, code);
        }
    }

    #[test]
    fn test_zip_code_formats() {
        let zip_codes = vec!["94025", "M5H 2N2", "SW1A 1AA", "75001", "10001-1234", "K1A0B1"];

        for zip in zip_codes {
            let params = GetProductParams {
                merchant_url: "https://merchant.com".to_owned(),
                consumer_id: "user-test".to_owned(),
                product_id: "prod-test".to_owned(),
                country_code: "US".to_owned(),
                zip: zip.to_owned(),
                ip_address: "192.168.1.1".to_owned(),
                user_agent: "Test/1.0".to_owned(),
                platform: "Test".to_owned(),
            };

            assert_eq!(params.zip, zip);
        }
    }

    #[test]
    fn test_ip_address_formats() {
        let ip_addresses = vec![
            "192.168.1.1",
            "10.0.0.1",
            "172.16.0.1",
            "8.8.8.8",
            "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
        ];

        for ip in ip_addresses {
            let params = GetProductsParams {
                merchant_url: "https://merchant.com".to_owned(),
                consumer_id: "user-test".to_owned(),
                country_code: "US".to_owned(),
                zip: "12345".to_owned(),
                ip_address: ip.to_owned(),
                user_agent: "Test/1.0".to_owned(),
                platform: "Test".to_owned(),
                category: None,
                search: None,
                page: None,
                per_page: None,
            };

            assert_eq!(params.ip_address, ip);
        }
    }

    #[test]
    fn test_user_agent_strings() {
        let user_agents = vec![
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            "Chrome/120.0.0.0",
            "Safari/17.0",
            "Edge/120.0.0.0",
            "Custom-Agent/1.0",
        ];

        for ua in user_agents {
            let params = GetProductParams {
                merchant_url: "https://merchant.com".to_owned(),
                consumer_id: "user-test".to_owned(),
                product_id: "prod-test".to_owned(),
                country_code: "US".to_owned(),
                zip: "12345".to_owned(),
                ip_address: "192.168.1.1".to_owned(),
                user_agent: ua.to_owned(),
                platform: "Test".to_owned(),
            };

            assert_eq!(params.user_agent, ua);
        }
    }

    #[test]
    fn test_platform_values() {
        let platforms = vec!["Windows", "macOS", "Linux", "iOS", "Android"];

        for platform in platforms {
            let params = GetProductsParams {
                merchant_url: "https://merchant.com".to_owned(),
                consumer_id: "user-test".to_owned(),
                country_code: "US".to_owned(),
                zip: "12345".to_owned(),
                ip_address: "192.168.1.1".to_owned(),
                user_agent: "Test/1.0".to_owned(),
                platform: platform.to_owned(),
                category: None,
                search: None,
                page: None,
                per_page: None,
            };

            assert_eq!(params.platform, platform);
        }
    }

    #[test]
    fn test_empty_search_query() {
        let params = GetProductsParams {
            merchant_url: "https://merchant.com".to_owned(),
            consumer_id: "user-test".to_owned(),
            country_code: "US".to_owned(),
            zip: "12345".to_owned(),
            ip_address: "192.168.1.1".to_owned(),
            user_agent: "Test/1.0".to_owned(),
            platform: "Test".to_owned(),
            category: None,
            search: Some(String::new()),
            page: None,
            per_page: None,
        };

        assert_eq!(params.search.as_ref().unwrap(), "");
    }

    #[test]
    fn test_pagination_edge_cases() {
        let params = GetProductsParams {
            merchant_url: "https://merchant.com".to_owned(),
            consumer_id: "user-test".to_owned(),
            country_code: "US".to_owned(),
            zip: "12345".to_owned(),
            ip_address: "192.168.1.1".to_owned(),
            user_agent: "Test/1.0".to_owned(),
            platform: "Test".to_owned(),
            category: None,
            search: None,
            page: Some(0),
            per_page: Some(0),
        };

        assert_eq!(params.page, Some(0));
        assert_eq!(params.per_page, Some(0));
    }
}
