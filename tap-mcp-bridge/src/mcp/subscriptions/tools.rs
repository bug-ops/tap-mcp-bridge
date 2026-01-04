//! MCP tools for subscription management.
//!
//! Provides TAP-authenticated subscription operations.

use std::{sync::LazyLock, time::Duration};

use chrono::{DateTime, Utc};
use reqwest::Client;
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use tracing::{info, instrument};

use super::{
    lifecycle::SubscriptionResponse,
    models::{PlanCatalog, SubscriptionPlan, UsageAction, UsageRecord, UsageSummary},
};
use crate::{
    error::Result,
    mcp::{
        http::{HttpMethod, build_url_with_query, execute_tap_request_with_acro},
        models::Address,
    },
    tap::{InteractionType, TapSigner, acro::ContextualData},
};

/// Timeout for subscription HTTP requests in seconds.
const SUBSCRIPTION_REQUEST_TIMEOUT_SECS: u64 = 30;

/// Shared HTTP client for all subscription requests.
///
/// This static client is initialized once and reused across all requests,
/// providing connection pooling and reducing per-request overhead.
static SUBSCRIPTION_HTTP_CLIENT: LazyLock<Client> = LazyLock::new(|| {
    Client::builder()
        .timeout(Duration::from_secs(SUBSCRIPTION_REQUEST_TIMEOUT_SECS))
        .pool_max_idle_per_host(100)
        .http2_prior_knowledge()
        .build()
        .expect("failed to create subscription HTTP client")
});

// ============================================================================
// Tool Parameters
// ============================================================================

/// Parameters for retrieving subscription plans.
#[derive(Debug, Deserialize)]
pub struct GetPlansParams {
    /// Merchant URL.
    pub merchant_url: String,
    /// Consumer identifier.
    pub consumer_id: String,
    /// Filter by billing cycle type.
    pub billing_cycle: Option<String>,
    /// Filter by pricing model type.
    pub pricing_type: Option<String>,
    /// Include inactive plans.
    pub include_inactive: Option<bool>,
    /// Page number.
    pub page: Option<u32>,
    /// Items per page.
    pub per_page: Option<u32>,
    /// Country code for ACRO contextual data (ISO 3166-1 alpha-2).
    pub country_code: String,
    /// Postal/ZIP code for ACRO contextual data.
    pub zip: String,
    /// Client IP address for ACRO contextual data.
    pub ip_address: String,
    /// User agent string for ACRO contextual data.
    pub user_agent: String,
    /// Platform identifier for ACRO contextual data.
    pub platform: String,
}

/// Parameters for retrieving a single plan.
#[derive(Debug, Deserialize)]
pub struct GetPlanParams {
    /// Merchant URL.
    pub merchant_url: String,
    /// Consumer identifier.
    pub consumer_id: String,
    /// Plan identifier.
    pub plan_id: String,
    /// Country code for ACRO contextual data (ISO 3166-1 alpha-2).
    pub country_code: String,
    /// Postal/ZIP code for ACRO contextual data.
    pub zip: String,
    /// Client IP address for ACRO contextual data.
    pub ip_address: String,
    /// User agent string for ACRO contextual data.
    pub user_agent: String,
    /// Platform identifier for ACRO contextual data.
    pub platform: String,
}

/// Parameters for creating a subscription.
#[derive(Debug, Deserialize)]
pub struct CreateSubscriptionParams {
    /// Merchant URL.
    pub merchant_url: String,
    /// Consumer identifier.
    pub consumer_id: String,
    /// Plan identifier.
    pub plan_id: String,
    /// Initial quantity (seats, licenses).
    pub quantity: Option<u32>,
    /// Whether to start with trial (if available).
    pub start_trial: Option<bool>,
    /// Billing address.
    pub billing_address: Option<Address>,
    /// Payment method (encrypted via APC).
    pub payment_method: Option<crate::mcp::payment::PaymentMethodParams>,
    /// Merchant RSA public key for APC.
    pub merchant_public_key_pem: Option<String>,
    /// Promo code.
    pub promo_code: Option<String>,
    /// Country code for ACRO contextual data (ISO 3166-1 alpha-2).
    pub country_code: String,
    /// Postal/ZIP code for ACRO contextual data.
    pub zip: String,
    /// Client IP address for ACRO contextual data.
    pub ip_address: String,
    /// User agent string for ACRO contextual data.
    pub user_agent: String,
    /// Platform identifier for ACRO contextual data.
    pub platform: String,
}

/// Parameters for retrieving a subscription.
#[derive(Debug, Deserialize)]
pub struct GetSubscriptionParams {
    /// Merchant URL.
    pub merchant_url: String,
    /// Consumer identifier.
    pub consumer_id: String,
    /// Subscription identifier.
    pub subscription_id: String,
    /// Country code for ACRO contextual data (ISO 3166-1 alpha-2).
    pub country_code: String,
    /// Postal/ZIP code for ACRO contextual data.
    pub zip: String,
    /// Client IP address for ACRO contextual data.
    pub ip_address: String,
    /// User agent string for ACRO contextual data.
    pub user_agent: String,
    /// Platform identifier for ACRO contextual data.
    pub platform: String,
}

/// Parameters for updating a subscription.
#[derive(Debug, Deserialize)]
pub struct UpdateSubscriptionParams {
    /// Merchant URL.
    pub merchant_url: String,
    /// Consumer identifier.
    pub consumer_id: String,
    /// Subscription identifier.
    pub subscription_id: String,
    /// New quantity (triggers proration).
    pub quantity: Option<u32>,
    /// New plan ID (upgrade/downgrade).
    pub plan_id: Option<String>,
    /// Proration behavior.
    pub proration_behavior: Option<ProrationBehavior>,
    /// Country code for ACRO contextual data (ISO 3166-1 alpha-2).
    pub country_code: String,
    /// Postal/ZIP code for ACRO contextual data.
    pub zip: String,
    /// Client IP address for ACRO contextual data.
    pub ip_address: String,
    /// User agent string for ACRO contextual data.
    pub user_agent: String,
    /// Platform identifier for ACRO contextual data.
    pub platform: String,
}

/// Proration behavior for mid-cycle changes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProrationBehavior {
    /// Create prorated invoice immediately.
    CreateProrations,
    /// Apply proration to next invoice.
    None,
    /// Always charge full price (no credit).
    AlwaysInvoice,
}

/// Parameters for canceling a subscription.
#[derive(Debug, Deserialize)]
pub struct CancelSubscriptionParams {
    /// Merchant URL.
    pub merchant_url: String,
    /// Consumer identifier.
    pub consumer_id: String,
    /// Subscription identifier.
    pub subscription_id: String,
    /// Cancel immediately or at period end.
    pub cancel_at_period_end: Option<bool>,
    /// Cancellation reason.
    pub reason: Option<String>,
    /// Request refund for unused time.
    pub request_refund: Option<bool>,
    /// Country code for ACRO contextual data (ISO 3166-1 alpha-2).
    pub country_code: String,
    /// Postal/ZIP code for ACRO contextual data.
    pub zip: String,
    /// Client IP address for ACRO contextual data.
    pub ip_address: String,
    /// User agent string for ACRO contextual data.
    pub user_agent: String,
    /// Platform identifier for ACRO contextual data.
    pub platform: String,
}

/// Parameters for pausing a subscription.
#[derive(Debug, Deserialize)]
pub struct PauseSubscriptionParams {
    /// Merchant base URL.
    pub merchant_url: String,
    /// Consumer identifier.
    pub consumer_id: String,
    /// Subscription identifier.
    pub subscription_id: String,
    /// When to automatically resume (optional).
    pub resume_at: Option<DateTime<Utc>>,
    /// Pause reason.
    pub reason: Option<String>,
    /// Consumer country code (ACRO contextual data).
    pub country_code: String,
    /// Consumer postal/ZIP code (ACRO contextual data).
    pub zip: String,
    /// Consumer IP address (ACRO contextual data).
    pub ip_address: String,
    /// Consumer user agent (ACRO contextual data).
    pub user_agent: String,
    /// Consumer platform (ACRO contextual data).
    pub platform: String,
}

/// Parameters for resuming a subscription.
#[derive(Debug, Deserialize)]
pub struct ResumeSubscriptionParams {
    /// Merchant base URL.
    pub merchant_url: String,
    /// Consumer identifier.
    pub consumer_id: String,
    /// Subscription identifier.
    pub subscription_id: String,
    /// Whether to charge immediately for resumed period.
    pub charge_immediately: Option<bool>,
    /// Consumer country code (ACRO contextual data).
    pub country_code: String,
    /// Consumer postal/ZIP code (ACRO contextual data).
    pub zip: String,
    /// Consumer IP address (ACRO contextual data).
    pub ip_address: String,
    /// Consumer user agent (ACRO contextual data).
    pub user_agent: String,
    /// Consumer platform (ACRO contextual data).
    pub platform: String,
}

/// Parameters for reporting usage.
#[derive(Debug, Deserialize)]
pub struct ReportUsageParams {
    /// Merchant base URL.
    pub merchant_url: String,
    /// Consumer identifier.
    pub consumer_id: String,
    /// Subscription identifier.
    pub subscription_id: String,
    /// Metric identifier.
    pub metric_id: String,
    /// Usage quantity.
    pub quantity: u64,
    /// Idempotency key.
    pub idempotency_key: Option<String>,
    /// Action (set or increment).
    pub action: Option<UsageAction>,
    /// Consumer country code (ACRO contextual data).
    pub country_code: String,
    /// Consumer postal/ZIP code (ACRO contextual data).
    pub zip: String,
    /// Consumer IP address (ACRO contextual data).
    pub ip_address: String,
    /// Consumer user agent (ACRO contextual data).
    pub user_agent: String,
    /// Consumer platform (ACRO contextual data).
    pub platform: String,
}

/// Parameters for getting usage summary.
#[derive(Debug, Deserialize)]
pub struct GetUsageParams {
    /// Merchant base URL.
    pub merchant_url: String,
    /// Consumer identifier.
    pub consumer_id: String,
    /// Subscription identifier.
    pub subscription_id: String,
    /// Consumer country code (ACRO contextual data).
    pub country_code: String,
    /// Consumer postal/ZIP code (ACRO contextual data).
    pub zip: String,
    /// Consumer IP address (ACRO contextual data).
    pub ip_address: String,
    /// Consumer user agent (ACRO contextual data).
    pub user_agent: String,
    /// Consumer platform (ACRO contextual data).
    pub platform: String,
}

/// Parameters for updating payment method.
#[derive(Debug, Deserialize)]
pub struct UpdatePaymentMethodParams {
    /// Merchant base URL.
    pub merchant_url: String,
    /// Consumer identifier.
    pub consumer_id: String,
    /// Subscription identifier.
    pub subscription_id: String,
    /// New payment method (encrypted via APC).
    pub payment_method: crate::mcp::payment::PaymentMethodParams,
    /// Merchant RSA public key for APC.
    pub merchant_public_key_pem: String,
    /// Consumer country code (ACRO contextual data).
    pub country_code: String,
    /// Consumer postal/ZIP code (ACRO contextual data).
    pub zip: String,
    /// Consumer IP address (ACRO contextual data).
    pub ip_address: String,
    /// Consumer user agent (ACRO contextual data).
    pub user_agent: String,
    /// Consumer platform (ACRO contextual data).
    pub platform: String,
}

/// Parameters for previewing proration.
#[derive(Debug, Deserialize)]
pub struct PreviewProrationParams {
    /// Merchant base URL.
    pub merchant_url: String,
    /// Consumer identifier.
    pub consumer_id: String,
    /// Subscription identifier.
    pub subscription_id: String,
    /// Target plan ID (for plan change).
    pub target_plan_id: Option<String>,
    /// Target quantity (for quantity change).
    pub target_quantity: Option<u32>,
    /// Consumer country code (ACRO contextual data).
    pub country_code: String,
    /// Consumer postal/ZIP code (ACRO contextual data).
    pub zip: String,
    /// Consumer IP address (ACRO contextual data).
    pub ip_address: String,
    /// Consumer user agent (ACRO contextual data).
    pub user_agent: String,
    /// Consumer platform (ACRO contextual data).
    pub platform: String,
}

// ============================================================================
// Response Types
// ============================================================================

/// Proration preview response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProrationPreview {
    /// Credit for unused time on current plan.
    pub credit_amount: Decimal,
    /// Charge for new plan prorated.
    pub charge_amount: Decimal,
    /// Net amount (charge - credit).
    pub net_amount: Decimal,
    /// When proration would apply.
    pub effective_date: DateTime<Utc>,
    /// Currency code.
    pub currency: String,
    /// Line items breakdown.
    pub line_items: Vec<ProrationLineItem>,
}

/// Single line item in proration preview.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProrationLineItem {
    /// Item description.
    pub description: String,
    /// Item amount.
    pub amount: Decimal,
    /// Item quantity.
    pub quantity: Option<u32>,
    /// Period start.
    pub period_start: DateTime<Utc>,
    /// Period end.
    pub period_end: DateTime<Utc>,
}

// ============================================================================
// Tool Implementations
// ============================================================================

/// Retrieves available subscription plans from merchant.
///
/// # Errors
///
/// Returns error if signature generation, HTTP request, or response parsing fails.
#[instrument(skip(signer, params), fields(merchant_url = %params.merchant_url))]
pub async fn get_subscription_plans(
    signer: &TapSigner,
    params: GetPlansParams,
) -> Result<PlanCatalog> {
    info!("fetching subscription plans");

    let contextual_data = ContextualData {
        country_code: params.country_code,
        zip: params.zip,
        ip_address: params.ip_address,
        device_data: crate::tap::acro::DeviceData {
            user_agent: params.user_agent,
            platform: params.platform,
        },
    };

    let mut query_params = vec![("consumer_id", params.consumer_id.clone())];
    if let Some(ref cycle) = params.billing_cycle {
        query_params.push(("billing_cycle", cycle.clone()));
    }
    if let Some(ref pricing) = params.pricing_type {
        query_params.push(("pricing_type", pricing.clone()));
    }
    if params.include_inactive.unwrap_or(false) {
        query_params.push(("include_inactive", "true".to_owned()));
    }
    if let Some(page) = params.page {
        query_params.push(("page", page.to_string()));
    }
    if let Some(per_page) = params.per_page {
        query_params.push(("per_page", per_page.to_string()));
    }

    let path = build_url_with_query(
        "/subscriptions/plans",
        &query_params.iter().map(|(k, v)| (*k, v.as_str())).collect::<Vec<_>>(),
    )?;

    let client = &*SUBSCRIPTION_HTTP_CLIENT;
    let response = execute_tap_request_with_acro(
        client,
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

    let catalog: PlanCatalog = serde_json::from_slice(&response).map_err(|e| {
        crate::error::BridgeError::MerchantError(format!("failed to parse plan catalog: {e}"))
    })?;

    Ok(catalog)
}

/// Retrieves a single subscription plan.
///
/// # Errors
///
/// Returns error if signature generation, HTTP request, or response parsing fails.
#[instrument(skip(signer, params), fields(merchant_url = %params.merchant_url, plan_id = %params.plan_id))]
pub async fn get_subscription_plan(
    signer: &TapSigner,
    params: GetPlanParams,
) -> Result<SubscriptionPlan> {
    info!("fetching subscription plan");

    let contextual_data = ContextualData {
        country_code: params.country_code,
        zip: params.zip,
        ip_address: params.ip_address,
        device_data: crate::tap::acro::DeviceData {
            user_agent: params.user_agent,
            platform: params.platform,
        },
    };

    let path = build_url_with_query(&format!("/subscriptions/plans/{}", params.plan_id), &[(
        "consumer_id",
        &params.consumer_id,
    )])?;

    let client = &*SUBSCRIPTION_HTTP_CLIENT;
    let response = execute_tap_request_with_acro(
        client,
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

    let plan: SubscriptionPlan = serde_json::from_slice(&response).map_err(|e| {
        crate::error::BridgeError::MerchantError(format!("failed to parse plan: {e}"))
    })?;

    Ok(plan)
}

/// Request body for creating a subscription.
#[derive(Debug, Serialize)]
struct CreateSubscriptionRequest {
    plan_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    quantity: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    start_trial: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    billing_address: Option<Address>,
    #[serde(skip_serializing_if = "Option::is_none")]
    apc: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    promo_code: Option<String>,
}

/// Creates a new subscription.
///
/// # Errors
///
/// Returns error if signature generation, HTTP request, or response parsing fails.
#[instrument(skip(signer, params), fields(merchant_url = %params.merchant_url, plan_id = %params.plan_id))]
pub async fn create_subscription(
    signer: &TapSigner,
    params: CreateSubscriptionParams,
) -> Result<SubscriptionResponse> {
    info!("creating subscription");

    let contextual_data = ContextualData {
        country_code: params.country_code,
        zip: params.zip,
        ip_address: params.ip_address,
        device_data: crate::tap::acro::DeviceData {
            user_agent: params.user_agent,
            platform: params.platform,
        },
    };

    let apc = if let (Some(payment_method), Some(merchant_key_pem)) =
        (params.payment_method, params.merchant_public_key_pem)
    {
        let merchant_public_key =
            crate::tap::apc::RsaPublicKey::from_pem(merchant_key_pem.as_bytes())?;
        let payment_method = payment_method.into();
        let nonce = uuid::Uuid::new_v4().to_string();
        let apc_jwe = signer.generate_apc(&nonce, &payment_method, &merchant_public_key)?;
        Some(serde_json::to_string(&apc_jwe).map_err(|e| {
            crate::error::BridgeError::CryptoError(format!("APC serialization failed: {e}"))
        })?)
    } else {
        None
    };

    let request_body = CreateSubscriptionRequest {
        plan_id: params.plan_id,
        quantity: params.quantity,
        start_trial: params.start_trial,
        billing_address: params.billing_address,
        apc,
        promo_code: params.promo_code,
    };

    let path = build_url_with_query("/subscriptions", &[("consumer_id", &params.consumer_id)])?;

    let client = &*SUBSCRIPTION_HTTP_CLIENT;
    let response = execute_tap_request_with_acro(
        client,
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

    let subscription: SubscriptionResponse = serde_json::from_slice(&response).map_err(|e| {
        crate::error::BridgeError::MerchantError(format!("failed to parse subscription: {e}"))
    })?;

    Ok(subscription)
}

/// Retrieves subscription details.
///
/// # Errors
///
/// Returns error if signature generation, HTTP request, or response parsing fails.
#[instrument(skip(signer, params), fields(merchant_url = %params.merchant_url, subscription_id = %params.subscription_id))]
pub async fn get_subscription(
    signer: &TapSigner,
    params: GetSubscriptionParams,
) -> Result<SubscriptionResponse> {
    info!("fetching subscription");

    let contextual_data = ContextualData {
        country_code: params.country_code,
        zip: params.zip,
        ip_address: params.ip_address,
        device_data: crate::tap::acro::DeviceData {
            user_agent: params.user_agent,
            platform: params.platform,
        },
    };

    let path = build_url_with_query(&format!("/subscriptions/{}", params.subscription_id), &[(
        "consumer_id",
        &params.consumer_id,
    )])?;

    let client = &*SUBSCRIPTION_HTTP_CLIENT;
    let response = execute_tap_request_with_acro(
        client,
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

    let subscription: SubscriptionResponse = serde_json::from_slice(&response).map_err(|e| {
        crate::error::BridgeError::MerchantError(format!("failed to parse subscription: {e}"))
    })?;

    Ok(subscription)
}

/// Request body for updating a subscription.
#[derive(Debug, Serialize)]
struct UpdateSubscriptionRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    quantity: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    plan_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    proration_behavior: Option<ProrationBehavior>,
}

/// Updates subscription (quantity, plan change).
///
/// # Errors
///
/// Returns error if signature generation, HTTP request, or response parsing fails.
#[instrument(skip(signer, params), fields(merchant_url = %params.merchant_url, subscription_id = %params.subscription_id))]
pub async fn update_subscription(
    signer: &TapSigner,
    params: UpdateSubscriptionParams,
) -> Result<SubscriptionResponse> {
    info!("updating subscription");

    let contextual_data = ContextualData {
        country_code: params.country_code,
        zip: params.zip,
        ip_address: params.ip_address,
        device_data: crate::tap::acro::DeviceData {
            user_agent: params.user_agent,
            platform: params.platform,
        },
    };

    let request_body = UpdateSubscriptionRequest {
        quantity: params.quantity,
        plan_id: params.plan_id,
        proration_behavior: params.proration_behavior,
    };

    let path = build_url_with_query(&format!("/subscriptions/{}", params.subscription_id), &[(
        "consumer_id",
        &params.consumer_id,
    )])?;

    let client = &*SUBSCRIPTION_HTTP_CLIENT;
    let response = execute_tap_request_with_acro(
        client,
        signer,
        &params.merchant_url,
        &params.consumer_id,
        HttpMethod::Put,
        &path,
        InteractionType::Checkout,
        contextual_data,
        Some(&request_body),
    )
    .await?;

    let subscription: SubscriptionResponse = serde_json::from_slice(&response).map_err(|e| {
        crate::error::BridgeError::MerchantError(format!("failed to parse subscription: {e}"))
    })?;

    Ok(subscription)
}

/// Request body for canceling a subscription.
#[derive(Debug, Serialize)]
struct CancelSubscriptionRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    cancel_at_period_end: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    request_refund: Option<bool>,
}

/// Cancels a subscription.
///
/// # Errors
///
/// Returns error if signature generation, HTTP request, or response parsing fails.
#[instrument(skip(signer, params), fields(merchant_url = %params.merchant_url, subscription_id = %params.subscription_id))]
pub async fn cancel_subscription(
    signer: &TapSigner,
    params: CancelSubscriptionParams,
) -> Result<SubscriptionResponse> {
    info!("canceling subscription");

    let contextual_data = ContextualData {
        country_code: params.country_code,
        zip: params.zip,
        ip_address: params.ip_address,
        device_data: crate::tap::acro::DeviceData {
            user_agent: params.user_agent,
            platform: params.platform,
        },
    };

    let request_body = CancelSubscriptionRequest {
        cancel_at_period_end: params.cancel_at_period_end,
        reason: params.reason,
        request_refund: params.request_refund,
    };

    let path = build_url_with_query(
        &format!("/subscriptions/{}/cancel", params.subscription_id),
        &[("consumer_id", &params.consumer_id)],
    )?;

    let client = &*SUBSCRIPTION_HTTP_CLIENT;
    let response = execute_tap_request_with_acro(
        client,
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

    let subscription: SubscriptionResponse = serde_json::from_slice(&response).map_err(|e| {
        crate::error::BridgeError::MerchantError(format!("failed to parse subscription: {e}"))
    })?;

    Ok(subscription)
}

/// Request body for pausing a subscription.
#[derive(Debug, Serialize)]
struct PauseSubscriptionRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    resume_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
}

/// Pauses a subscription.
///
/// # Errors
///
/// Returns error if signature generation, HTTP request, or response parsing fails.
#[instrument(skip(signer, params), fields(merchant_url = %params.merchant_url, subscription_id = %params.subscription_id))]
pub async fn pause_subscription(
    signer: &TapSigner,
    params: PauseSubscriptionParams,
) -> Result<SubscriptionResponse> {
    info!("pausing subscription");

    let contextual_data = ContextualData {
        country_code: params.country_code,
        zip: params.zip,
        ip_address: params.ip_address,
        device_data: crate::tap::acro::DeviceData {
            user_agent: params.user_agent,
            platform: params.platform,
        },
    };

    let request_body =
        PauseSubscriptionRequest { resume_at: params.resume_at, reason: params.reason };

    let path = build_url_with_query(
        &format!("/subscriptions/{}/pause", params.subscription_id),
        &[("consumer_id", &params.consumer_id)],
    )?;

    let client = &*SUBSCRIPTION_HTTP_CLIENT;
    let response = execute_tap_request_with_acro(
        client,
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

    let subscription: SubscriptionResponse = serde_json::from_slice(&response).map_err(|e| {
        crate::error::BridgeError::MerchantError(format!("failed to parse subscription: {e}"))
    })?;

    Ok(subscription)
}

/// Request body for resuming a subscription.
#[derive(Debug, Serialize)]
struct ResumeSubscriptionRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    charge_immediately: Option<bool>,
}

/// Resumes a paused subscription.
///
/// # Errors
///
/// Returns error if signature generation, HTTP request, or response parsing fails.
#[instrument(skip(signer, params), fields(merchant_url = %params.merchant_url, subscription_id = %params.subscription_id))]
pub async fn resume_subscription(
    signer: &TapSigner,
    params: ResumeSubscriptionParams,
) -> Result<SubscriptionResponse> {
    info!("resuming subscription");

    let contextual_data = ContextualData {
        country_code: params.country_code,
        zip: params.zip,
        ip_address: params.ip_address,
        device_data: crate::tap::acro::DeviceData {
            user_agent: params.user_agent,
            platform: params.platform,
        },
    };

    let request_body = ResumeSubscriptionRequest { charge_immediately: params.charge_immediately };

    let path = build_url_with_query(
        &format!("/subscriptions/{}/resume", params.subscription_id),
        &[("consumer_id", &params.consumer_id)],
    )?;

    let client = &*SUBSCRIPTION_HTTP_CLIENT;
    let response = execute_tap_request_with_acro(
        client,
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

    let subscription: SubscriptionResponse = serde_json::from_slice(&response).map_err(|e| {
        crate::error::BridgeError::MerchantError(format!("failed to parse subscription: {e}"))
    })?;

    Ok(subscription)
}

/// Request body for reporting usage.
#[derive(Debug, Serialize)]
struct ReportUsageRequest {
    metric_id: String,
    quantity: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    idempotency_key: Option<String>,
    action: UsageAction,
}

/// Reports usage for usage-based subscription.
///
/// # Errors
///
/// Returns error if signature generation, HTTP request, or response parsing fails.
#[instrument(skip(signer, params), fields(merchant_url = %params.merchant_url, subscription_id = %params.subscription_id, metric_id = %params.metric_id))]
pub async fn report_usage(signer: &TapSigner, params: ReportUsageParams) -> Result<UsageRecord> {
    info!("reporting usage");

    let contextual_data = ContextualData {
        country_code: params.country_code,
        zip: params.zip,
        ip_address: params.ip_address,
        device_data: crate::tap::acro::DeviceData {
            user_agent: params.user_agent,
            platform: params.platform,
        },
    };

    let request_body = ReportUsageRequest {
        metric_id: params.metric_id,
        quantity: params.quantity,
        idempotency_key: params.idempotency_key,
        action: params.action.unwrap_or(UsageAction::Increment),
    };

    let path = build_url_with_query(
        &format!("/subscriptions/{}/usage", params.subscription_id),
        &[("consumer_id", &params.consumer_id)],
    )?;

    let client = &*SUBSCRIPTION_HTTP_CLIENT;
    let response = execute_tap_request_with_acro(
        client,
        signer,
        &params.merchant_url,
        &params.consumer_id,
        HttpMethod::Post,
        &path,
        InteractionType::Browse,
        contextual_data,
        Some(&request_body),
    )
    .await?;

    let usage_record: UsageRecord = serde_json::from_slice(&response).map_err(|e| {
        crate::error::BridgeError::MerchantError(format!("failed to parse usage record: {e}"))
    })?;

    Ok(usage_record)
}

/// Gets current usage summary.
///
/// # Errors
///
/// Returns error if signature generation, HTTP request, or response parsing fails.
#[instrument(skip(signer, params), fields(merchant_url = %params.merchant_url, subscription_id = %params.subscription_id))]
pub async fn get_usage(signer: &TapSigner, params: GetUsageParams) -> Result<UsageSummary> {
    info!("fetching usage summary");

    let contextual_data = ContextualData {
        country_code: params.country_code,
        zip: params.zip,
        ip_address: params.ip_address,
        device_data: crate::tap::acro::DeviceData {
            user_agent: params.user_agent,
            platform: params.platform,
        },
    };

    let path = build_url_with_query(
        &format!("/subscriptions/{}/usage/summary", params.subscription_id),
        &[("consumer_id", &params.consumer_id)],
    )?;

    let client = &*SUBSCRIPTION_HTTP_CLIENT;
    let response = execute_tap_request_with_acro(
        client,
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

    let usage_summary: UsageSummary = serde_json::from_slice(&response).map_err(|e| {
        crate::error::BridgeError::MerchantError(format!("failed to parse usage summary: {e}"))
    })?;

    Ok(usage_summary)
}

/// Request body for updating payment method.
#[derive(Debug, Serialize)]
struct UpdatePaymentMethodRequest {
    apc: String,
}

/// Updates payment method for subscription.
///
/// # Errors
///
/// Returns error if signature generation, HTTP request, or response parsing fails.
#[instrument(skip(signer, params), fields(merchant_url = %params.merchant_url, subscription_id = %params.subscription_id))]
pub async fn update_payment_method(
    signer: &TapSigner,
    params: UpdatePaymentMethodParams,
) -> Result<SubscriptionResponse> {
    info!("updating payment method");

    let contextual_data = ContextualData {
        country_code: params.country_code,
        zip: params.zip,
        ip_address: params.ip_address,
        device_data: crate::tap::acro::DeviceData {
            user_agent: params.user_agent,
            platform: params.platform,
        },
    };

    let merchant_public_key =
        crate::tap::apc::RsaPublicKey::from_pem(params.merchant_public_key_pem.as_bytes())?;
    let payment_method = params.payment_method.into();
    let nonce = uuid::Uuid::new_v4().to_string();
    let apc_jwe = signer.generate_apc(&nonce, &payment_method, &merchant_public_key)?;
    let apc_json = serde_json::to_string(&apc_jwe).map_err(|e| {
        crate::error::BridgeError::CryptoError(format!("APC serialization failed: {e}"))
    })?;

    let request_body = UpdatePaymentMethodRequest { apc: apc_json };

    let path = build_url_with_query(
        &format!("/subscriptions/{}/payment-method", params.subscription_id),
        &[("consumer_id", &params.consumer_id)],
    )?;

    let client = &*SUBSCRIPTION_HTTP_CLIENT;
    let response = execute_tap_request_with_acro(
        client,
        signer,
        &params.merchant_url,
        &params.consumer_id,
        HttpMethod::Put,
        &path,
        InteractionType::Checkout,
        contextual_data,
        Some(&request_body),
    )
    .await?;

    let subscription: SubscriptionResponse = serde_json::from_slice(&response).map_err(|e| {
        crate::error::BridgeError::MerchantError(format!("failed to parse subscription: {e}"))
    })?;

    Ok(subscription)
}

/// Request body for proration preview.
#[derive(Debug, Serialize)]
struct PreviewProrationRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    target_plan_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    target_quantity: Option<u32>,
}

/// Previews proration for a planned change.
///
/// # Errors
///
/// Returns error if signature generation, HTTP request, or response parsing fails.
#[instrument(skip(signer, params), fields(merchant_url = %params.merchant_url, subscription_id = %params.subscription_id))]
pub async fn preview_proration(
    signer: &TapSigner,
    params: PreviewProrationParams,
) -> Result<ProrationPreview> {
    info!("previewing proration");

    let contextual_data = ContextualData {
        country_code: params.country_code,
        zip: params.zip,
        ip_address: params.ip_address,
        device_data: crate::tap::acro::DeviceData {
            user_agent: params.user_agent,
            platform: params.platform,
        },
    };

    let request_body = PreviewProrationRequest {
        target_plan_id: params.target_plan_id,
        target_quantity: params.target_quantity,
    };

    let path = build_url_with_query(
        &format!("/subscriptions/{}/proration-preview", params.subscription_id),
        &[("consumer_id", &params.consumer_id)],
    )?;

    let client = &*SUBSCRIPTION_HTTP_CLIENT;
    let response = execute_tap_request_with_acro(
        client,
        signer,
        &params.merchant_url,
        &params.consumer_id,
        HttpMethod::Post,
        &path,
        InteractionType::Browse,
        contextual_data,
        Some(&request_body),
    )
    .await?;

    let proration_preview: ProrationPreview = serde_json::from_slice(&response).map_err(|e| {
        crate::error::BridgeError::MerchantError(format!("failed to parse proration preview: {e}"))
    })?;

    Ok(proration_preview)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ========================================================================
    // ProrationBehavior Serialization Tests
    // ========================================================================

    #[test]
    fn test_proration_behavior_create_prorations_serialization() {
        let behavior = ProrationBehavior::CreateProrations;
        let json = serde_json::to_string(&behavior).unwrap();
        assert_eq!(json, "\"create_prorations\"");

        let deserialized: ProrationBehavior = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, ProrationBehavior::CreateProrations);
    }

    #[test]
    fn test_proration_behavior_none_serialization() {
        let behavior = ProrationBehavior::None;
        let json = serde_json::to_string(&behavior).unwrap();
        assert_eq!(json, "\"none\"");

        let deserialized: ProrationBehavior = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, ProrationBehavior::None);
    }

    #[test]
    fn test_proration_behavior_always_invoice_serialization() {
        let behavior = ProrationBehavior::AlwaysInvoice;
        let json = serde_json::to_string(&behavior).unwrap();
        assert_eq!(json, "\"always_invoice\"");

        let deserialized: ProrationBehavior = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, ProrationBehavior::AlwaysInvoice);
    }

    #[test]
    fn test_proration_behavior_all_variants() {
        let variants = vec![
            ProrationBehavior::CreateProrations,
            ProrationBehavior::None,
            ProrationBehavior::AlwaysInvoice,
        ];

        for variant in variants {
            let json = serde_json::to_string(&variant).unwrap();
            let deserialized: ProrationBehavior = serde_json::from_str(&json).unwrap();
            assert_eq!(deserialized, variant);
        }
    }
}
