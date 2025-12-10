//! Subscription management for TAP-MCP bridge.
//!
//! This module provides comprehensive subscription functionality including
//! plan management, subscription lifecycle, usage tracking, and proration.

pub mod lifecycle;
pub mod models;
pub mod pricing;
pub mod proration;
pub mod tools;

pub use lifecycle::{
    Active, Canceled, Expired, PastDue, Paused, StateData, Subscription, SubscriptionData,
    SubscriptionResponse, SubscriptionStatus, Trial,
};
pub use models::{
    BillingCycle, MetricUsage, PlanCatalog, PlanFeature, PlanId, SubscriptionId, SubscriptionPlan,
    TrialConfig, UsageAction, UsageRecord, UsageSummary,
};
pub use pricing::{
    FlatRatePrice, HybridPrice, IncludedUsage, OveragePricing, PerSeatPrice, PriceTier,
    PricingModel, TierMode, TieredPrice, UsageAggregation, UsageBasedPrice, UsageMetric, UsageTier,
    VolumeDiscount,
};
pub use proration::{calculate_charge, calculate_credit, calculate_next_billing_date};
pub use tools::{
    CancelSubscriptionParams, CreateSubscriptionParams, GetPlanParams, GetPlansParams,
    GetSubscriptionParams, GetUsageParams, PauseSubscriptionParams, PreviewProrationParams,
    ProrationBehavior, ProrationLineItem, ProrationPreview, ReportUsageParams,
    ResumeSubscriptionParams, UpdatePaymentMethodParams, UpdateSubscriptionParams,
    cancel_subscription, create_subscription, get_subscription, get_subscription_plan,
    get_subscription_plans, get_usage, pause_subscription, preview_proration, report_usage,
    resume_subscription, update_payment_method, update_subscription,
};
