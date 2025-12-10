//! Subscription merchant API traits.
//!
//! Extends `MerchantApi` with subscription-specific operations.

use serde::de::DeserializeOwned;

use crate::{
    error::Result,
    mcp::subscriptions::{
        lifecycle::SubscriptionResponse,
        models::{PlanCatalog, SubscriptionPlan, UsageSummary},
        tools::ProrationPreview,
    },
    merchant::traits::MerchantApi,
};

/// URL-encode a string for use in query parameters.
fn url_encode(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' || c == '~' {
                c.to_string()
            } else {
                format!("%{:02X}", c as u8)
            }
        })
        .collect()
}

/// Extension of `MerchantApi` for subscription operations.
///
/// This trait extends the base `MerchantApi` with subscription-specific
/// type mappings and conversions. Implementors can map merchant-specific
/// subscription response formats to the standard types.
///
/// # Sealed Trait Pattern
///
/// This trait uses the sealed pattern to prevent external implementations
/// while allowing the library to evolve the API without breaking changes.
pub trait SubscriptionMerchantApi: MerchantApi + private::Sealed {
    /// Subscription plan catalog response type.
    type PlanCatalog: DeserializeOwned + Send;

    /// Single subscription plan response type.
    type Plan: DeserializeOwned + Send;

    /// Subscription response type.
    type Subscription: DeserializeOwned + Send;

    /// Usage summary response type.
    type UsageSummary: DeserializeOwned + Send;

    /// Proration preview response type.
    type ProrationPreview: DeserializeOwned + Send;

    /// Returns the subscription endpoint resolver.
    fn subscription_endpoints(&self) -> &dyn SubscriptionEndpointResolver;

    /// Converts merchant plan catalog to standard format.
    ///
    /// # Errors
    ///
    /// Returns error if conversion fails.
    fn to_standard_plan_catalog(&self, catalog: Self::PlanCatalog) -> Result<PlanCatalog>;

    /// Converts merchant plan to standard format.
    ///
    /// # Errors
    ///
    /// Returns error if conversion fails.
    fn to_standard_plan(&self, plan: Self::Plan) -> Result<SubscriptionPlan>;

    /// Converts merchant subscription to standard format.
    ///
    /// # Errors
    ///
    /// Returns error if conversion fails.
    fn to_standard_subscription(&self, sub: Self::Subscription) -> Result<SubscriptionResponse>;

    /// Converts merchant usage summary to standard format.
    ///
    /// # Errors
    ///
    /// Returns error if conversion fails.
    fn to_standard_usage(&self, usage: Self::UsageSummary) -> Result<UsageSummary>;

    /// Converts merchant proration preview to standard format.
    ///
    /// # Errors
    ///
    /// Returns error if conversion fails.
    fn to_standard_proration(&self, preview: Self::ProrationPreview) -> Result<ProrationPreview>;
}

/// Resolves subscription-specific API endpoints.
pub trait SubscriptionEndpointResolver: Send + Sync {
    /// Subscription plans list endpoint.
    fn plans_endpoint(&self, params: &PlanQueryParams) -> String;

    /// Single plan endpoint.
    fn plan_endpoint(&self, plan_id: &str) -> String;

    /// Subscriptions list endpoint.
    fn subscriptions_endpoint(&self) -> String;

    /// Single subscription endpoint.
    fn subscription_endpoint(&self, subscription_id: &str) -> String;

    /// Subscription cancel endpoint.
    fn cancel_endpoint(&self, subscription_id: &str) -> String;

    /// Subscription pause endpoint.
    fn pause_endpoint(&self, subscription_id: &str) -> String;

    /// Subscription resume endpoint.
    fn resume_endpoint(&self, subscription_id: &str) -> String;

    /// Usage reporting endpoint.
    fn usage_endpoint(&self, subscription_id: &str) -> String;

    /// Usage summary endpoint.
    fn usage_summary_endpoint(&self, subscription_id: &str) -> String;

    /// Payment method update endpoint.
    fn payment_method_endpoint(&self, subscription_id: &str) -> String;

    /// Proration preview endpoint.
    fn proration_preview_endpoint(&self, subscription_id: &str) -> String;
}

/// Query parameters for plan listing.
#[derive(Debug, Clone, Default)]
pub struct PlanQueryParams {
    /// Consumer identifier.
    pub consumer_id: String,
    /// Filter by billing cycle type.
    pub billing_cycle: Option<String>,
    /// Filter by pricing model type.
    pub pricing_type: Option<String>,
    /// Include inactive plans.
    pub include_inactive: bool,
    /// Page number.
    pub page: Option<u32>,
    /// Items per page.
    pub per_page: Option<u32>,
}

// Sealed trait pattern to prevent external implementations
mod private {
    pub trait Sealed {}
}

/// Default implementation for standard TAP subscription merchants.
#[derive(Debug)]
pub struct DefaultSubscriptionMerchant {
    base: crate::merchant::DefaultMerchant,
}

impl private::Sealed for DefaultSubscriptionMerchant {}

impl DefaultSubscriptionMerchant {
    /// Creates a new default subscription merchant.
    #[must_use]
    pub fn new(base: crate::merchant::DefaultMerchant) -> Self {
        Self { base }
    }
}

impl MerchantApi for DefaultSubscriptionMerchant {
    type CartState = crate::mcp::models::CartState;
    type Order = crate::mcp::models::Order;
    type PaymentResult = crate::mcp::models::PaymentResult;
    type Product = crate::mcp::models::Product;
    type ProductCatalog = crate::mcp::models::ProductCatalog;

    fn endpoint_resolver(&self) -> &dyn crate::merchant::EndpointResolver {
        self.base.endpoint_resolver()
    }

    fn field_mapper(&self) -> &dyn crate::merchant::FieldMapper {
        self.base.field_mapper()
    }

    fn to_standard_catalog(
        &self,
        catalog: Self::ProductCatalog,
    ) -> Result<crate::mcp::models::ProductCatalog> {
        Ok(catalog)
    }

    fn to_standard_product(&self, product: Self::Product) -> Result<crate::mcp::models::Product> {
        Ok(product)
    }

    fn to_standard_cart(&self, cart: Self::CartState) -> Result<crate::mcp::models::CartState> {
        Ok(cart)
    }

    fn to_standard_order(&self, order: Self::Order) -> Result<crate::mcp::models::Order> {
        Ok(order)
    }

    fn to_standard_payment(
        &self,
        result: Self::PaymentResult,
    ) -> Result<crate::mcp::models::PaymentResult> {
        Ok(result)
    }
}

/// Default subscription endpoint resolver.
#[derive(Debug)]
pub struct DefaultSubscriptionEndpointResolver;

impl SubscriptionEndpointResolver for DefaultSubscriptionEndpointResolver {
    fn plans_endpoint(&self, params: &PlanQueryParams) -> String {
        use std::fmt::Write;

        let mut url = String::from("/subscriptions/plans?");
        url.push_str("consumer_id=");
        url.push_str(&url_encode(&params.consumer_id));
        if let Some(ref cycle) = params.billing_cycle {
            url.push_str("&billing_cycle=");
            url.push_str(&url_encode(cycle));
        }
        if let Some(ref pricing) = params.pricing_type {
            url.push_str("&pricing_type=");
            url.push_str(&url_encode(pricing));
        }
        if params.include_inactive {
            url.push_str("&include_inactive=true");
        }
        if let Some(page) = params.page {
            write!(url, "&page={page}").expect("write to String cannot fail");
        }
        if let Some(per_page) = params.per_page {
            write!(url, "&per_page={per_page}").expect("write to String cannot fail");
        }
        url
    }

    fn plan_endpoint(&self, plan_id: &str) -> String {
        format!("/subscriptions/plans/{plan_id}")
    }

    fn subscriptions_endpoint(&self) -> String {
        "/subscriptions".to_owned()
    }

    fn subscription_endpoint(&self, subscription_id: &str) -> String {
        format!("/subscriptions/{subscription_id}")
    }

    fn cancel_endpoint(&self, subscription_id: &str) -> String {
        format!("/subscriptions/{subscription_id}/cancel")
    }

    fn pause_endpoint(&self, subscription_id: &str) -> String {
        format!("/subscriptions/{subscription_id}/pause")
    }

    fn resume_endpoint(&self, subscription_id: &str) -> String {
        format!("/subscriptions/{subscription_id}/resume")
    }

    fn usage_endpoint(&self, subscription_id: &str) -> String {
        format!("/subscriptions/{subscription_id}/usage")
    }

    fn usage_summary_endpoint(&self, subscription_id: &str) -> String {
        format!("/subscriptions/{subscription_id}/usage/summary")
    }

    fn payment_method_endpoint(&self, subscription_id: &str) -> String {
        format!("/subscriptions/{subscription_id}/payment-method")
    }

    fn proration_preview_endpoint(&self, subscription_id: &str) -> String {
        format!("/subscriptions/{subscription_id}/proration-preview")
    }
}

impl SubscriptionMerchantApi for DefaultSubscriptionMerchant {
    type Plan = SubscriptionPlan;
    type PlanCatalog = PlanCatalog;
    type ProrationPreview = ProrationPreview;
    type Subscription = SubscriptionResponse;
    type UsageSummary = UsageSummary;

    fn subscription_endpoints(&self) -> &dyn SubscriptionEndpointResolver {
        &DefaultSubscriptionEndpointResolver
    }

    fn to_standard_plan_catalog(&self, catalog: Self::PlanCatalog) -> Result<PlanCatalog> {
        Ok(catalog)
    }

    fn to_standard_plan(&self, plan: Self::Plan) -> Result<SubscriptionPlan> {
        Ok(plan)
    }

    fn to_standard_subscription(&self, sub: Self::Subscription) -> Result<SubscriptionResponse> {
        Ok(sub)
    }

    fn to_standard_usage(&self, usage: Self::UsageSummary) -> Result<UsageSummary> {
        Ok(usage)
    }

    fn to_standard_proration(&self, preview: Self::ProrationPreview) -> Result<ProrationPreview> {
        Ok(preview)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merchant::DefaultMerchant;

    // ========================================================================
    // PlanQueryParams Tests
    // ========================================================================

    #[test]
    fn test_plan_query_params_default() {
        let params = PlanQueryParams::default();
        assert!(params.consumer_id.is_empty());
        assert!(params.billing_cycle.is_none());
        assert!(params.pricing_type.is_none());
        assert!(!params.include_inactive);
        assert!(params.page.is_none());
        assert!(params.per_page.is_none());
    }

    #[test]
    fn test_plan_query_params_custom() {
        let params = PlanQueryParams {
            consumer_id: "consumer-123".to_owned(),
            billing_cycle: Some("monthly".to_owned()),
            pricing_type: Some("flat_rate".to_owned()),
            include_inactive: true,
            page: Some(2),
            per_page: Some(50),
        };
        assert_eq!(params.consumer_id, "consumer-123");
        assert_eq!(params.billing_cycle.as_deref(), Some("monthly"));
        assert_eq!(params.pricing_type.as_deref(), Some("flat_rate"));
        assert!(params.include_inactive);
        assert_eq!(params.page, Some(2));
        assert_eq!(params.per_page, Some(50));
    }

    // ========================================================================
    // DefaultSubscriptionEndpointResolver Tests
    // ========================================================================

    #[test]
    fn test_default_subscription_endpoint_resolver_plans() {
        let resolver = DefaultSubscriptionEndpointResolver;
        let params = PlanQueryParams {
            consumer_id: "consumer-456".to_owned(),
            billing_cycle: None,
            pricing_type: None,
            include_inactive: false,
            page: None,
            per_page: None,
        };

        let endpoint = resolver.plans_endpoint(&params);
        assert!(endpoint.starts_with("/subscriptions/plans?"));
        assert!(endpoint.contains("consumer_id=consumer-456"));
    }

    #[test]
    fn test_default_subscription_endpoint_resolver_plans_with_filters() {
        let resolver = DefaultSubscriptionEndpointResolver;
        let params = PlanQueryParams {
            consumer_id: "consumer-789".to_owned(),
            billing_cycle: Some("monthly".to_owned()),
            pricing_type: Some("tiered".to_owned()),
            include_inactive: true,
            page: Some(2),
            per_page: Some(25),
        };

        let endpoint = resolver.plans_endpoint(&params);
        assert!(endpoint.contains("consumer_id=consumer-789"));
        assert!(endpoint.contains("&billing_cycle=monthly"));
        assert!(endpoint.contains("&pricing_type=tiered"));
        assert!(endpoint.contains("&include_inactive=true"));
        assert!(endpoint.contains("&page=2"));
        assert!(endpoint.contains("&per_page=25"));
    }

    #[test]
    fn test_default_subscription_endpoint_resolver_plan() {
        let resolver = DefaultSubscriptionEndpointResolver;
        let endpoint = resolver.plan_endpoint("plan-basic");
        assert_eq!(endpoint, "/subscriptions/plans/plan-basic");
    }

    #[test]
    fn test_default_subscription_endpoint_resolver_subscriptions() {
        let resolver = DefaultSubscriptionEndpointResolver;
        let endpoint = resolver.subscriptions_endpoint();
        assert_eq!(endpoint, "/subscriptions");
    }

    #[test]
    fn test_default_subscription_endpoint_resolver_subscription() {
        let resolver = DefaultSubscriptionEndpointResolver;
        let endpoint = resolver.subscription_endpoint("sub-123");
        assert_eq!(endpoint, "/subscriptions/sub-123");
    }

    #[test]
    fn test_default_subscription_endpoint_resolver_cancel() {
        let resolver = DefaultSubscriptionEndpointResolver;
        let endpoint = resolver.cancel_endpoint("sub-456");
        assert_eq!(endpoint, "/subscriptions/sub-456/cancel");
    }

    #[test]
    fn test_default_subscription_endpoint_resolver_pause() {
        let resolver = DefaultSubscriptionEndpointResolver;
        let endpoint = resolver.pause_endpoint("sub-789");
        assert_eq!(endpoint, "/subscriptions/sub-789/pause");
    }

    #[test]
    fn test_default_subscription_endpoint_resolver_resume() {
        let resolver = DefaultSubscriptionEndpointResolver;
        let endpoint = resolver.resume_endpoint("sub-101");
        assert_eq!(endpoint, "/subscriptions/sub-101/resume");
    }

    #[test]
    fn test_default_subscription_endpoint_resolver_usage() {
        let resolver = DefaultSubscriptionEndpointResolver;
        let endpoint = resolver.usage_endpoint("sub-202");
        assert_eq!(endpoint, "/subscriptions/sub-202/usage");
    }

    #[test]
    fn test_default_subscription_endpoint_resolver_usage_summary() {
        let resolver = DefaultSubscriptionEndpointResolver;
        let endpoint = resolver.usage_summary_endpoint("sub-303");
        assert_eq!(endpoint, "/subscriptions/sub-303/usage/summary");
    }

    #[test]
    fn test_default_subscription_endpoint_resolver_payment_method() {
        let resolver = DefaultSubscriptionEndpointResolver;
        let endpoint = resolver.payment_method_endpoint("sub-404");
        assert_eq!(endpoint, "/subscriptions/sub-404/payment-method");
    }

    #[test]
    fn test_default_subscription_endpoint_resolver_proration_preview() {
        let resolver = DefaultSubscriptionEndpointResolver;
        let endpoint = resolver.proration_preview_endpoint("sub-505");
        assert_eq!(endpoint, "/subscriptions/sub-505/proration-preview");
    }

    // ========================================================================
    // DefaultSubscriptionMerchant Tests
    // ========================================================================

    #[test]
    fn test_default_subscription_merchant_creation() {
        let base = DefaultMerchant::new();
        let merchant = DefaultSubscriptionMerchant::new(base);

        let resolver = merchant.subscription_endpoints();
        assert_eq!(resolver.subscriptions_endpoint(), "/subscriptions");
    }

    #[test]
    fn test_default_subscription_merchant_plan_catalog_passthrough() {
        use crate::mcp::subscriptions::models::PlanCatalog;

        let base = DefaultMerchant::new();
        let merchant = DefaultSubscriptionMerchant::new(base);

        let catalog = PlanCatalog { plans: vec![], total: 0, page: 1, per_page: 10 };

        let result = merchant.to_standard_plan_catalog(catalog.clone());
        assert!(result.is_ok());
        let converted = result.unwrap();
        assert_eq!(converted.total, catalog.total);
        assert_eq!(converted.page, catalog.page);
    }

    #[test]
    fn test_default_subscription_merchant_subscription_passthrough() {
        use crate::mcp::subscriptions::{
            lifecycle::{SubscriptionResponse, SubscriptionStatus},
            models::{PlanId, SubscriptionId},
        };

        let base = DefaultMerchant::new();
        let merchant = DefaultSubscriptionMerchant::new(base);

        let sub_response = SubscriptionResponse {
            data: crate::mcp::subscriptions::lifecycle::SubscriptionData {
                id: SubscriptionId::new("sub-test").unwrap(),
                plan_id: PlanId::new("plan-test").unwrap(),
                consumer_id: "consumer-test".to_owned(),
                quantity: 1,
                created_at: chrono::Utc::now(),
                current_period_start: chrono::Utc::now(),
                current_period_end: chrono::Utc::now() + chrono::Duration::days(30),
                billing_address: None,
                billing_cycle: crate::mcp::subscriptions::models::BillingCycle::Monthly {
                    anchor_day: 1,
                },
                currency: "USD".to_owned(),
                current_period_amount: rust_decimal::Decimal::new(999, 2),
                payment_method_id: None,
                metadata: serde_json::Value::Null,
                state_data: crate::mcp::subscriptions::lifecycle::StateData::Active {
                    activated_at: chrono::Utc::now(),
                    last_payment_at: None,
                },
            },
            status: SubscriptionStatus::Active,
        };

        let result = merchant.to_standard_subscription(sub_response.clone());
        assert!(result.is_ok());
        let converted = result.unwrap();
        assert_eq!(converted.status, sub_response.status);
        assert_eq!(converted.data.id, sub_response.data.id);
    }
}
