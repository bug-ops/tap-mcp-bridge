//! Subscription configuration types.
//!
//! TOML-deserializable configuration for subscription endpoints and field mappings.

use std::collections::HashMap;

use serde::Deserialize;

use crate::{
    error::Result,
    merchant::config::{validate_endpoint_path, validate_field_name},
};

/// Subscription endpoint configuration.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct SubscriptionEndpointConfig {
    /// Plans list endpoint (default: "/subscriptions/plans").
    pub plans: Option<String>,

    /// Single plan endpoint template (default: "/subscriptions/plans/{id}").
    pub plan: Option<String>,

    /// Subscriptions list endpoint (default: "/subscriptions").
    pub subscriptions: Option<String>,

    /// Single subscription endpoint template (default: "/subscriptions/{id}").
    pub subscription: Option<String>,

    /// Cancel subscription endpoint (default: "/subscriptions/{id}/cancel").
    pub cancel: Option<String>,

    /// Pause subscription endpoint (default: "/subscriptions/{id}/pause").
    pub pause: Option<String>,

    /// Resume subscription endpoint (default: "/subscriptions/{id}/resume").
    pub resume: Option<String>,

    /// Report usage endpoint (default: "/subscriptions/{id}/usage").
    pub usage: Option<String>,

    /// Usage summary endpoint (default: "/subscriptions/{id}/usage/summary").
    pub usage_summary: Option<String>,

    /// Payment method update endpoint (default: "/subscriptions/{id}/payment-method").
    pub payment_method: Option<String>,

    /// Proration preview endpoint (default: "/subscriptions/{id}/proration-preview").
    pub proration_preview: Option<String>,
}

impl SubscriptionEndpointConfig {
    /// Validates endpoint templates for security issues.
    ///
    /// # Errors
    ///
    /// Returns error if any endpoint contains invalid patterns.
    pub fn validate(&self) -> Result<()> {
        let endpoints = [
            ("plans", &self.plans),
            ("plan", &self.plan),
            ("subscriptions", &self.subscriptions),
            ("subscription", &self.subscription),
            ("cancel", &self.cancel),
            ("pause", &self.pause),
            ("resume", &self.resume),
            ("usage", &self.usage),
            ("usage_summary", &self.usage_summary),
            ("payment_method", &self.payment_method),
            ("proration_preview", &self.proration_preview),
        ];

        for (name, endpoint) in endpoints {
            if let Some(path) = endpoint {
                validate_endpoint_path(name, path)?;
            }
        }

        Ok(())
    }
}

/// Subscription field mapping configuration.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct SubscriptionFieldMappingConfig {
    /// Plan field mappings.
    #[serde(default)]
    pub plan: HashMap<String, String>,

    /// Subscription field mappings.
    #[serde(default)]
    pub subscription: HashMap<String, String>,

    /// Usage field mappings.
    #[serde(default)]
    pub usage: HashMap<String, String>,

    /// Proration field mappings.
    #[serde(default)]
    pub proration: HashMap<String, String>,
}

impl SubscriptionFieldMappingConfig {
    /// Validates field mapping names for security issues.
    ///
    /// # Errors
    ///
    /// Returns error if any field name is invalid.
    pub fn validate(&self) -> Result<()> {
        for (context, mappings) in [
            ("plan", &self.plan),
            ("subscription", &self.subscription),
            ("usage", &self.usage),
            ("proration", &self.proration),
        ] {
            for (key, value) in mappings {
                validate_field_name(&format!("{context} key"), key)?;
                validate_field_name(&format!("{context} value"), value)?;
            }
        }
        Ok(())
    }
}

/// Extended merchant configuration with subscription support.
///
/// Extends base `MerchantConfig` with subscription-specific settings.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct SubscriptionMerchantConfig {
    /// Base merchant configuration.
    #[serde(flatten)]
    pub base: crate::merchant::MerchantConfig,

    /// Subscription endpoint configuration.
    #[serde(default)]
    pub subscription_endpoints: SubscriptionEndpointConfig,

    /// Subscription field mappings.
    #[serde(default)]
    pub subscription_field_mappings: SubscriptionFieldMappingConfig,

    /// Subscription-specific settings.
    #[serde(default)]
    pub subscription_settings: SubscriptionSettings,
}

/// Subscription-specific merchant settings.
#[derive(Debug, Clone, Deserialize)]
pub struct SubscriptionSettings {
    /// Grace period for past-due subscriptions (days).
    #[serde(default = "default_grace_period")]
    pub grace_period_days: u32,

    /// Maximum retry attempts for failed payments.
    #[serde(default = "default_max_retries")]
    pub max_payment_retries: u32,

    /// Whether pausing is supported by this merchant.
    #[serde(default = "default_true")]
    pub supports_pause: bool,

    /// Whether usage-based billing is supported.
    #[serde(default = "default_true")]
    pub supports_usage: bool,

    /// Whether proration preview is available.
    #[serde(default = "default_true")]
    pub supports_proration_preview: bool,
}

impl Default for SubscriptionSettings {
    fn default() -> Self {
        Self {
            grace_period_days: default_grace_period(),
            max_payment_retries: default_max_retries(),
            supports_pause: true,
            supports_usage: true,
            supports_proration_preview: true,
        }
    }
}

fn default_grace_period() -> u32 {
    7
}
fn default_max_retries() -> u32 {
    4
}
fn default_true() -> bool {
    true
}

impl SubscriptionSettings {
    /// Validates subscription settings.
    ///
    /// # Errors
    ///
    /// Returns error if `grace_period_days` is outside valid range (1-365 days).
    pub fn validate(&self) -> Result<()> {
        if self.grace_period_days == 0 || self.grace_period_days > 365 {
            return Err(crate::error::BridgeError::MerchantConfigError(
                "grace_period_days must be between 1 and 365".into(),
            ));
        }
        Ok(())
    }
}

impl SubscriptionMerchantConfig {
    /// Validates the complete subscription configuration.
    ///
    /// # Errors
    ///
    /// Returns error if any configuration value is invalid.
    pub fn validate(&self) -> Result<()> {
        self.base.validate()?;
        self.subscription_endpoints.validate()?;
        self.subscription_field_mappings.validate()?;
        self.subscription_settings.validate()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ========================================================================
    // SubscriptionEndpointConfig Tests
    // ========================================================================

    #[test]
    fn test_subscription_endpoint_config_default() {
        let config = SubscriptionEndpointConfig::default();
        assert!(config.plans.is_none());
        assert!(config.subscription.is_none());
        assert!(config.cancel.is_none());
        assert!(config.pause.is_none());
        assert!(config.usage.is_none());
    }

    #[test]
    fn test_subscription_endpoint_config_validate_valid() {
        let config = SubscriptionEndpointConfig {
            plans: Some("/subscriptions/plans".to_owned()),
            plan: Some("/subscriptions/plans/{id}".to_owned()),
            subscriptions: Some("/subscriptions".to_owned()),
            subscription: Some("/subscriptions/{id}".to_owned()),
            cancel: Some("/subscriptions/{id}/cancel".to_owned()),
            pause: Some("/subscriptions/{id}/pause".to_owned()),
            resume: Some("/subscriptions/{id}/resume".to_owned()),
            usage: Some("/subscriptions/{id}/usage".to_owned()),
            usage_summary: Some("/subscriptions/{id}/usage/summary".to_owned()),
            payment_method: Some("/subscriptions/{id}/payment-method".to_owned()),
            proration_preview: Some("/subscriptions/{id}/proration-preview".to_owned()),
        };

        let result = config.validate();
        assert!(result.is_ok());
    }

    #[test]
    fn test_subscription_endpoint_config_validate_path_traversal() {
        let config = SubscriptionEndpointConfig {
            plans: Some("/../etc/passwd".to_owned()),
            ..Default::default()
        };

        let result = config.validate();
        assert!(result.is_err());
    }

    #[test]
    fn test_subscription_endpoint_config_validate_double_slash() {
        let config = SubscriptionEndpointConfig {
            subscription: Some("/subscriptions//{id}".to_owned()),
            ..Default::default()
        };

        let result = config.validate();
        assert!(result.is_err());
    }

    // ========================================================================
    // SubscriptionFieldMappingConfig Tests
    // ========================================================================

    #[test]
    fn test_subscription_field_mapping_config_default() {
        let config = SubscriptionFieldMappingConfig::default();
        assert!(config.plan.is_empty());
        assert!(config.subscription.is_empty());
        assert!(config.usage.is_empty());
        assert!(config.proration.is_empty());
    }

    #[test]
    fn test_subscription_field_mapping_config_validate_valid() {
        let mut config = SubscriptionFieldMappingConfig::default();
        config.plan.insert("plan_id".to_owned(), "id".to_owned());
        config.subscription.insert("subscription_id".to_owned(), "sub_id".to_owned());

        let result = config.validate();
        assert!(result.is_ok());
    }

    #[test]
    fn test_subscription_field_mapping_config_validate_forbidden_field_name() {
        let mut config = SubscriptionFieldMappingConfig::default();
        config.plan.insert("__proto__".to_owned(), "id".to_owned());

        let result = config.validate();
        assert!(result.is_err());
    }

    #[test]
    fn test_subscription_field_mapping_config_validate_null_byte() {
        let mut config = SubscriptionFieldMappingConfig::default();
        config.subscription.insert("sub\0id".to_owned(), "value".to_owned());

        let result = config.validate();
        assert!(result.is_err());
    }

    // ========================================================================
    // SubscriptionSettings Tests
    // ========================================================================

    #[test]
    fn test_subscription_settings_default() {
        let settings = SubscriptionSettings::default();
        assert_eq!(settings.grace_period_days, 7);
        assert_eq!(settings.max_payment_retries, 4);
        assert!(settings.supports_pause);
        assert!(settings.supports_usage);
        assert!(settings.supports_proration_preview);
    }

    #[test]
    fn test_subscription_settings_custom() {
        let settings = SubscriptionSettings {
            grace_period_days: 14,
            max_payment_retries: 10,
            supports_pause: false,
            supports_usage: true,
            supports_proration_preview: false,
        };
        assert_eq!(settings.grace_period_days, 14);
        assert_eq!(settings.max_payment_retries, 10);
        assert!(!settings.supports_pause);
        assert!(settings.supports_usage);
        assert!(!settings.supports_proration_preview);
    }

    // ========================================================================
    // SubscriptionMerchantConfig Tests
    // ========================================================================

    #[test]
    fn test_subscription_merchant_config_default() {
        let config = SubscriptionMerchantConfig::default();
        assert_eq!(config.subscription_settings.grace_period_days, 7);
        assert!(config.subscription_endpoints.plans.is_none());
    }

    #[test]
    fn test_subscription_merchant_config_from_toml_basic() {
        let toml = r#"
            name = "Test Merchant"
            base_url = "https://api.test.com"

            [subscription_endpoints]
            plans = "/billing/plans"
            subscription = "/subscriptions/{id}"

            [subscription_settings]
            grace_period_days = 14
            max_payment_retries = 3
        "#;

        let config: SubscriptionMerchantConfig = toml::from_str(toml).unwrap();
        assert_eq!(config.base.name, "Test Merchant");
        assert_eq!(config.subscription_endpoints.plans.as_deref(), Some("/billing/plans"));
        assert_eq!(config.subscription_settings.grace_period_days, 14);
        assert_eq!(config.subscription_settings.max_payment_retries, 3);
    }

    #[test]
    fn test_subscription_merchant_config_from_toml_full() {
        let toml = r#"
            name = "Full Test Merchant"
            base_url = "https://api.test.com"

            [subscription_endpoints]
            plans = "/api/plans"
            plan = "/api/plans/{id}"
            subscriptions = "/api/subs"
            subscription = "/api/subs/{id}"
            cancel = "/api/subs/{id}/cancel"
            pause = "/api/subs/{id}/pause"
            resume = "/api/subs/{id}/resume"
            usage = "/api/subs/{id}/usage"
            usage_summary = "/api/subs/{id}/usage/summary"
            payment_method = "/api/subs/{id}/payment"
            proration_preview = "/api/subs/{id}/proration"

            [subscription_field_mappings.plan]
            plan_id = "id"
            plan_name = "name"

            [subscription_field_mappings.subscription]
            subscription_id = "sub_id"

            [subscription_settings]
            grace_period_days = 10
            max_payment_retries = 5
            supports_pause = true
            supports_usage = true
            supports_proration_preview = true
        "#;

        let config: SubscriptionMerchantConfig = toml::from_str(toml).unwrap();
        assert_eq!(config.base.name, "Full Test Merchant");
        assert_eq!(config.subscription_endpoints.plans.as_deref(), Some("/api/plans"));
        assert_eq!(config.subscription_endpoints.cancel.as_deref(), Some("/api/subs/{id}/cancel"));
        assert_eq!(config.subscription_field_mappings.plan.get("plan_id"), Some(&"id".to_owned()));
        assert_eq!(config.subscription_settings.grace_period_days, 10);
        assert_eq!(config.subscription_settings.max_payment_retries, 5);
    }

    #[test]
    fn test_subscription_merchant_config_validate_success() {
        let toml = r#"
            name = "Valid Merchant"
            base_url = "https://api.valid.com"

            [subscription_endpoints]
            plans = "/subscriptions/plans"

            [subscription_settings]
            grace_period_days = 7
        "#;

        let config: SubscriptionMerchantConfig = toml::from_str(toml).unwrap();
        let result = config.validate();
        assert!(result.is_ok());
    }

    #[test]
    fn test_subscription_merchant_config_validate_invalid_endpoint() {
        let toml = r#"
            name = "Invalid Merchant"
            base_url = "https://api.invalid.com"

            [subscription_endpoints]
            plans = "/../etc/passwd"
        "#;

        let config: SubscriptionMerchantConfig = toml::from_str(toml).unwrap();
        let result = config.validate();
        assert!(result.is_err());
    }

    #[test]
    fn test_subscription_merchant_config_validate_invalid_field_mapping() {
        let toml = r#"
            name = "Invalid Mapping"
            base_url = "https://api.test.com"

            [subscription_field_mappings.plan]
            __proto__ = "id"
        "#;

        let config: SubscriptionMerchantConfig = toml::from_str(toml).unwrap();
        let result = config.validate();
        assert!(result.is_err());
    }

    #[test]
    fn test_subscription_merchant_config_default_values() {
        let toml = r#"
            name = "Minimal Merchant"
            base_url = "https://api.minimal.com"
        "#;

        let config: SubscriptionMerchantConfig = toml::from_str(toml).unwrap();
        assert_eq!(config.subscription_settings.grace_period_days, 7);
        assert_eq!(config.subscription_settings.max_payment_retries, 4);
        assert!(config.subscription_settings.supports_pause);
        assert!(config.subscription_settings.supports_usage);
        assert!(config.subscription_settings.supports_proration_preview);
        assert!(config.subscription_endpoints.plans.is_none());
        assert!(config.subscription_field_mappings.plan.is_empty());
    }
}
