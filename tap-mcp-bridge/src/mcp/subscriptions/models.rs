//! Subscription data models for TAP-MCP bridge.
//!
//! This module defines the data structures for subscription management
//! including plans, subscriptions, and billing cycles.

use chrono::{DateTime, Utc};
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};

use crate::error::{BridgeError, Result};

/// Maximum allowed usage quantity to prevent overflow and abuse.
/// Set to 1 trillion units (10^12).
const MAX_USAGE_QUANTITY: u64 = 1_000_000_000_000;

/// Unique identifier for a subscription plan.
///
/// Wraps merchant-provided plan ID with type safety.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PlanId(String);

impl PlanId {
    /// Creates a new plan ID after validation.
    ///
    /// # Errors
    ///
    /// Returns error if ID is empty, exceeds 64 characters, or contains invalid characters.
    /// Only alphanumeric characters, hyphens, and underscores are allowed.
    pub fn new<S: Into<String>>(id: S) -> Result<Self> {
        let id = id.into();
        if id.is_empty() {
            return Err(BridgeError::InvalidPlanId("plan_id cannot be empty".into()));
        }
        if id.len() > 64 {
            return Err(BridgeError::InvalidPlanId("plan_id must be 64 characters or less".into()));
        }
        if !id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
            return Err(BridgeError::InvalidPlanId(
                "plan_id can only contain alphanumeric characters, hyphens, and underscores".into(),
            ));
        }
        Ok(Self(id))
    }

    /// Returns the inner string reference.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Unique identifier for a subscription instance.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SubscriptionId(String);

impl SubscriptionId {
    /// Creates a new subscription ID after validation.
    ///
    /// # Errors
    ///
    /// Returns error if ID is empty, exceeds 64 characters, or contains invalid characters.
    /// Only alphanumeric characters, hyphens, and underscores are allowed.
    pub fn new<S: Into<String>>(id: S) -> Result<Self> {
        let id = id.into();
        if id.is_empty() {
            return Err(BridgeError::InvalidSubscriptionId(
                "subscription_id cannot be empty".into(),
            ));
        }
        if id.len() > 64 {
            return Err(BridgeError::InvalidSubscriptionId(
                "subscription_id must be 64 characters or less".into(),
            ));
        }
        if !id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
            return Err(BridgeError::InvalidSubscriptionId(
                "subscription_id can only contain alphanumeric characters, hyphens, and \
                 underscores"
                    .into(),
            ));
        }
        Ok(Self(id))
    }

    /// Returns the inner string reference.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Subscription plan defining pricing and terms.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubscriptionPlan {
    /// Unique plan identifier.
    pub id: PlanId,
    /// Display name.
    pub name: String,
    /// Plan description.
    pub description: String,
    /// Pricing model for this plan.
    pub pricing: crate::mcp::subscriptions::pricing::PricingModel,
    /// Billing cycle configuration.
    pub billing_cycle: BillingCycle,
    /// Trial configuration (optional).
    pub trial: Option<TrialConfig>,
    /// Features included in this plan.
    pub features: Vec<PlanFeature>,
    /// Whether plan is currently available for new subscriptions.
    pub active: bool,
    /// Currency code (ISO 4217).
    pub currency: String,
    /// Metadata for merchant-specific extensions.
    #[serde(default)]
    pub metadata: serde_json::Value,
}

/// Feature included in a subscription plan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlanFeature {
    /// Feature identifier.
    pub id: String,
    /// Display name.
    pub name: String,
    /// Feature description.
    pub description: Option<String>,
    /// Included quantity (None = unlimited).
    pub included_quantity: Option<u64>,
    /// Unit for quantity measurement.
    pub unit: Option<String>,
}

/// Trial period configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrialConfig {
    /// Duration of trial in days.
    pub duration_days: u32,
    /// Whether payment method required at trial start.
    pub requires_payment_method: bool,
    /// Whether trial auto-converts to paid subscription.
    pub auto_convert: bool,
}

/// Billing cycle configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum BillingCycle {
    /// Monthly billing (day of month).
    Monthly {
        /// Day of month for billing (1-28 recommended).
        anchor_day: u8,
    },
    /// Annual billing.
    Annual {
        /// Month for billing anniversary (1-12).
        anchor_month: u8,
        /// Day of month for billing anniversary (1-28 recommended).
        anchor_day: u8,
    },
    /// Weekly billing.
    Weekly {
        /// Day of week (0 = Sunday, 6 = Saturday).
        anchor_day: u8,
    },
    /// Custom interval in days.
    Custom {
        /// Number of days between billing cycles.
        interval_days: u32,
    },
    /// One-time charge with optional validity period.
    OneTime {
        /// Validity period in days (None = perpetual).
        validity_days: Option<u32>,
    },
}

impl BillingCycle {
    /// Returns human-readable interval description.
    #[must_use]
    pub fn interval_display(&self) -> &'static str {
        match self {
            Self::Monthly { .. } => "month",
            Self::Annual { .. } => "year",
            Self::Weekly { .. } => "week",
            Self::Custom { interval_days } if *interval_days == 1 => "day",
            Self::Custom { .. } => "custom period",
            Self::OneTime { .. } => "one-time",
        }
    }
}

/// Subscription plan catalog with pagination.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlanCatalog {
    /// Plans in current page.
    pub plans: Vec<SubscriptionPlan>,
    /// Total plan count.
    pub total: u32,
    /// Current page number.
    pub page: u32,
    /// Items per page.
    pub per_page: u32,
}

/// Usage record for usage-based billing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsageRecord {
    /// Subscription ID.
    pub subscription_id: SubscriptionId,
    /// Metric identifier.
    pub metric_id: String,
    /// Usage quantity.
    pub quantity: u64,
    /// Timestamp of usage (defaults to now).
    pub timestamp: DateTime<Utc>,
    /// Idempotency key to prevent duplicate reporting.
    pub idempotency_key: Option<String>,
    /// Action: set absolute value or increment.
    pub action: UsageAction,
}

impl UsageRecord {
    /// Validates the usage record.
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - quantity exceeds maximum allowed value
    /// - timestamp is in the future
    /// - timestamp is more than 24 hours in the past
    pub fn validate(&self) -> Result<()> {
        // Validate quantity
        if self.quantity > MAX_USAGE_QUANTITY {
            return Err(BridgeError::UsageError(format!(
                "Usage quantity {} exceeds maximum allowed value of {MAX_USAGE_QUANTITY}",
                self.quantity
            )));
        }

        // Validate timestamp is not in the future
        let now = Utc::now();
        if self.timestamp > now {
            return Err(BridgeError::UsageError("Usage timestamp cannot be in the future".into()));
        }

        // Validate timestamp is not too far in the past (24 hours)
        let twenty_four_hours_ago = now - chrono::Duration::hours(24);
        if self.timestamp < twenty_four_hours_ago {
            return Err(BridgeError::UsageError(
                "Usage timestamp cannot be more than 24 hours in the past".into(),
            ));
        }

        Ok(())
    }
}

/// Usage reporting action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UsageAction {
    /// Set absolute value (replaces current).
    Set,
    /// Increment current value.
    Increment,
}

/// Current usage summary for a subscription.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsageSummary {
    /// Subscription ID.
    pub subscription_id: SubscriptionId,
    /// Billing period start.
    pub period_start: DateTime<Utc>,
    /// Billing period end.
    pub period_end: DateTime<Utc>,
    /// Usage by metric.
    pub metrics: Vec<MetricUsage>,
    /// Estimated charges for current usage.
    pub estimated_charges: Decimal,
    /// Currency code.
    pub currency: String,
}

/// Usage for a single metric.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricUsage {
    /// Metric identifier.
    pub metric_id: String,
    /// Metric display name.
    pub metric_name: String,
    /// Current usage quantity.
    pub current_usage: u64,
    /// Included quantity (from plan).
    pub included: Option<u64>,
    /// Overage quantity (usage - included).
    pub overage: Option<u64>,
    /// Charges for this metric.
    pub charges: Decimal,
}

impl MetricUsage {
    /// Validates the metric usage.
    ///
    /// # Errors
    ///
    /// Returns error if `current_usage` exceeds maximum allowed value.
    pub fn validate(&self) -> Result<()> {
        if self.current_usage > MAX_USAGE_QUANTITY {
            return Err(BridgeError::UsageError(format!(
                "Current usage {} exceeds maximum allowed value of {MAX_USAGE_QUANTITY}",
                self.current_usage
            )));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ========================================================================
    // PlanId Tests
    // ========================================================================

    #[test]
    fn test_plan_id_valid() {
        let id = PlanId::new("plan-123").unwrap();
        assert_eq!(id.as_str(), "plan-123");
    }

    #[test]
    fn test_plan_id_empty_rejected() {
        let result = PlanId::new("");
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), BridgeError::InvalidPlanId(_)));
    }

    #[test]
    fn test_plan_id_too_long_rejected() {
        let long_id = "a".repeat(65);
        let result = PlanId::new(long_id);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), BridgeError::InvalidPlanId(_)));
    }

    #[test]
    fn test_plan_id_exactly_64_chars_accepted() {
        let exactly_64 = "a".repeat(64);
        let result = PlanId::new(exactly_64.clone());
        assert!(result.is_ok());
        assert_eq!(result.unwrap().as_str(), exactly_64);
    }

    #[test]
    fn test_plan_id_single_char_accepted() {
        let id = PlanId::new("a").unwrap();
        assert_eq!(id.as_str(), "a");
    }

    #[test]
    fn test_plan_id_rejects_path_traversal() {
        let result = PlanId::new("../etc/passwd");
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), BridgeError::InvalidPlanId(_)));
    }

    #[test]
    fn test_plan_id_rejects_slash() {
        let result = PlanId::new("plan/123");
        assert!(result.is_err());
    }

    #[test]
    fn test_plan_id_accepts_valid_chars() {
        let result = PlanId::new("plan-123_ABC");
        assert!(result.is_ok());
    }

    // ========================================================================
    // SubscriptionId Tests
    // ========================================================================

    #[test]
    fn test_subscription_id_valid() {
        let id = SubscriptionId::new("sub-456").unwrap();
        assert_eq!(id.as_str(), "sub-456");
    }

    #[test]
    fn test_subscription_id_empty_rejected() {
        let result = SubscriptionId::new("");
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), BridgeError::InvalidSubscriptionId(_)));
    }

    #[test]
    fn test_subscription_id_too_long_rejected() {
        let long_id = "b".repeat(65);
        let result = SubscriptionId::new(long_id);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), BridgeError::InvalidSubscriptionId(_)));
    }

    #[test]
    fn test_subscription_id_exactly_64_chars_accepted() {
        let exactly_64 = "b".repeat(64);
        let result = SubscriptionId::new(exactly_64.clone());
        assert!(result.is_ok());
        assert_eq!(result.unwrap().as_str(), exactly_64);
    }

    #[test]
    fn test_subscription_id_rejects_special_chars() {
        let result = SubscriptionId::new("sub@123");
        assert!(result.is_err());
    }

    #[test]
    fn test_subscription_id_rejects_whitespace() {
        let result = SubscriptionId::new("sub 123");
        assert!(result.is_err());
    }

    // ========================================================================
    // BillingCycle Tests
    // ========================================================================

    #[test]
    fn test_billing_cycle_monthly_display() {
        let cycle = BillingCycle::Monthly { anchor_day: 1 };
        assert_eq!(cycle.interval_display(), "month");
    }

    #[test]
    fn test_billing_cycle_annual_display() {
        let cycle = BillingCycle::Annual { anchor_month: 1, anchor_day: 1 };
        assert_eq!(cycle.interval_display(), "year");
    }

    #[test]
    fn test_billing_cycle_weekly_display() {
        let cycle = BillingCycle::Weekly { anchor_day: 1 };
        assert_eq!(cycle.interval_display(), "week");
    }

    #[test]
    fn test_billing_cycle_custom_single_day_display() {
        let cycle = BillingCycle::Custom { interval_days: 1 };
        assert_eq!(cycle.interval_display(), "day");
    }

    #[test]
    fn test_billing_cycle_custom_multi_day_display() {
        let cycle = BillingCycle::Custom { interval_days: 30 };
        assert_eq!(cycle.interval_display(), "custom period");
    }

    #[test]
    fn test_billing_cycle_onetime_display() {
        let cycle = BillingCycle::OneTime { validity_days: None };
        assert_eq!(cycle.interval_display(), "one-time");
    }

    #[test]
    fn test_billing_cycle_serialization() {
        let monthly = BillingCycle::Monthly { anchor_day: 15 };
        let json = serde_json::to_string(&monthly).unwrap();
        assert!(json.contains("\"type\":\"monthly\""));
        assert!(json.contains("\"anchor_day\":15"));

        let parsed: BillingCycle = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, monthly);
    }

    #[test]
    fn test_billing_cycle_deserialization() {
        let json = r#"{"type":"annual","anchor_month":6,"anchor_day":15}"#;
        let cycle: BillingCycle = serde_json::from_str(json).unwrap();
        assert_eq!(cycle, BillingCycle::Annual { anchor_month: 6, anchor_day: 15 });
    }

    // ========================================================================
    // UsageAction Tests
    // ========================================================================

    #[test]
    fn test_usage_action_set_serialization() {
        let action = UsageAction::Set;
        let json = serde_json::to_string(&action).unwrap();
        assert_eq!(json, "\"set\"");
    }

    #[test]
    fn test_usage_action_increment_serialization() {
        let action = UsageAction::Increment;
        let json = serde_json::to_string(&action).unwrap();
        assert_eq!(json, "\"increment\"");
    }

    #[test]
    fn test_usage_action_deserialization() {
        let set: UsageAction = serde_json::from_str("\"set\"").unwrap();
        assert_eq!(set, UsageAction::Set);

        let increment: UsageAction = serde_json::from_str("\"increment\"").unwrap();
        assert_eq!(increment, UsageAction::Increment);
    }
}
