//! Pricing models for subscription plans.
//!
//! Supports flat-rate, tiered, per-seat, usage-based, and hybrid pricing.

use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};

/// Pricing model for a subscription plan.
///
/// Each variant represents a different pricing strategy.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum PricingModel {
    /// Fixed price per billing cycle.
    ///
    /// Example: $9.99/month, $99/year
    FlatRate(FlatRatePrice),

    /// Different price tiers based on plan level.
    ///
    /// Example: Basic $10, Pro $25, Enterprise $100
    Tiered(TieredPrice),

    /// Price per unit (seat, user, license).
    ///
    /// Example: $5/user/month
    PerSeat(PerSeatPrice),

    /// Price based on usage metrics.
    ///
    /// Example: $0.01/API call, $0.10/GB
    UsageBased(UsageBasedPrice),

    /// Combination of base price plus usage/overage.
    ///
    /// Example: Base $20 + $0.05/API call over 1000
    Hybrid(HybridPrice),
}

impl PricingModel {
    /// Returns the minimum price per billing cycle.
    ///
    /// For usage-based models, returns the base/minimum commitment.
    #[must_use]
    pub fn minimum_price(&self) -> Decimal {
        match self {
            Self::FlatRate(p) => p.amount,
            Self::Tiered(p) => p.tiers.first().map_or(Decimal::ZERO, |t| t.price),
            Self::PerSeat(p) => p.price_per_seat * Decimal::from(p.minimum_seats.unwrap_or(1)),
            Self::UsageBased(p) => p.minimum_commitment.unwrap_or(Decimal::ZERO),
            Self::Hybrid(p) => p.base_price,
        }
    }
}

/// Flat-rate pricing configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlatRatePrice {
    /// Price per billing cycle.
    pub amount: Decimal,
    /// Setup fee (charged once at subscription start).
    pub setup_fee: Option<Decimal>,
}

/// Tiered pricing configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TieredPrice {
    /// Available tiers (ordered by level).
    pub tiers: Vec<PriceTier>,
    /// Whether tiers are mutually exclusive or cumulative.
    pub tier_mode: TierMode,
}

/// Single price tier.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PriceTier {
    /// Tier identifier.
    pub id: String,
    /// Display name (e.g., "Basic", "Pro", "Enterprise").
    pub name: String,
    /// Price for this tier per billing cycle.
    pub price: Decimal,
    /// Maximum usage/seats included (None = unlimited).
    pub up_to: Option<u64>,
    /// Features specific to this tier.
    pub features: Vec<String>,
}

/// How tiers are calculated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TierMode {
    /// Each tier has fixed price (select one tier).
    Volume,
    /// Units are distributed across tiers (graduated pricing).
    Graduated,
}

/// Per-seat (per-user/license) pricing configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerSeatPrice {
    /// Price per seat per billing cycle.
    pub price_per_seat: Decimal,
    /// Minimum seats required.
    pub minimum_seats: Option<u32>,
    /// Maximum seats allowed (None = unlimited).
    pub maximum_seats: Option<u32>,
    /// Volume discount tiers.
    pub volume_discounts: Vec<VolumeDiscount>,
}

/// Volume discount for per-seat pricing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VolumeDiscount {
    /// Minimum seats to qualify for discount.
    pub min_seats: u32,
    /// Discount percentage (0-100).
    pub discount_percent: Decimal,
}

/// Usage-based pricing configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsageBasedPrice {
    /// Metric being measured.
    pub metric: UsageMetric,
    /// Price per unit of usage.
    pub price_per_unit: Decimal,
    /// Minimum commitment per billing cycle.
    pub minimum_commitment: Option<Decimal>,
    /// Tiered pricing for usage (graduated pricing).
    pub usage_tiers: Vec<UsageTier>,
}

/// Usage metric definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsageMetric {
    /// Metric identifier.
    pub id: String,
    /// Display name (e.g., "API Calls", "Storage").
    pub name: String,
    /// Unit of measurement (e.g., "calls", "GB", "requests").
    pub unit: String,
    /// How usage is aggregated within billing cycle.
    pub aggregation: UsageAggregation,
}

/// How usage is aggregated for billing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UsageAggregation {
    /// Sum of all usage in period.
    Sum,
    /// Maximum usage at any point in period.
    Max,
    /// Last recorded value in period.
    LastValue,
    /// Average across period.
    Average,
}

/// Usage tier for graduated pricing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsageTier {
    /// Start of tier (units).
    pub from: u64,
    /// End of tier (units, None = unlimited).
    pub up_to: Option<u64>,
    /// Price per unit in this tier.
    pub price_per_unit: Decimal,
}

/// Hybrid pricing configuration (base + usage/overage).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HybridPrice {
    /// Base price per billing cycle.
    pub base_price: Decimal,
    /// Included usage before overage charges.
    pub included_usage: IncludedUsage,
    /// Overage pricing when included usage exceeded.
    pub overage_pricing: OveragePricing,
}

/// Usage included in base price.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncludedUsage {
    /// Metric being measured.
    pub metric: UsageMetric,
    /// Quantity included in base price.
    pub quantity: u64,
}

/// Pricing for usage exceeding included amount.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OveragePricing {
    /// Price per unit of overage.
    pub price_per_unit: Decimal,
    /// Maximum overage allowed (hard cap).
    pub max_overage: Option<u64>,
    /// Whether overage is billed in arrears or immediately.
    pub bill_immediately: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    // ========================================================================
    // FlatRate Tests
    // ========================================================================

    #[test]
    fn test_flat_rate_minimum_price() {
        let pricing =
            PricingModel::FlatRate(FlatRatePrice { amount: Decimal::new(999, 2), setup_fee: None });
        assert_eq!(pricing.minimum_price(), Decimal::new(999, 2));
    }

    #[test]
    fn test_flat_rate_with_setup_fee() {
        let pricing = PricingModel::FlatRate(FlatRatePrice {
            amount: Decimal::new(1000, 2),
            setup_fee: Some(Decimal::new(500, 2)),
        });
        assert_eq!(pricing.minimum_price(), Decimal::new(1000, 2));
    }

    // ========================================================================
    // Tiered Tests
    // ========================================================================

    #[test]
    fn test_tiered_minimum_price_empty_tiers() {
        let pricing =
            PricingModel::Tiered(TieredPrice { tiers: vec![], tier_mode: TierMode::Volume });
        assert_eq!(pricing.minimum_price(), Decimal::ZERO);
    }

    #[test]
    fn test_tiered_minimum_price_single_tier() {
        let pricing = PricingModel::Tiered(TieredPrice {
            tiers: vec![PriceTier {
                id: "basic".to_owned(),
                name: "Basic".to_owned(),
                price: Decimal::new(1500, 2),
                up_to: Some(100),
                features: vec![],
            }],
            tier_mode: TierMode::Volume,
        });
        assert_eq!(pricing.minimum_price(), Decimal::new(1500, 2));
    }

    #[test]
    fn test_tiered_minimum_price_multiple_tiers() {
        let pricing = PricingModel::Tiered(TieredPrice {
            tiers: vec![
                PriceTier {
                    id: "basic".to_owned(),
                    name: "Basic".to_owned(),
                    price: Decimal::new(1000, 2),
                    up_to: Some(100),
                    features: vec![],
                },
                PriceTier {
                    id: "pro".to_owned(),
                    name: "Pro".to_owned(),
                    price: Decimal::new(2500, 2),
                    up_to: Some(500),
                    features: vec![],
                },
                PriceTier {
                    id: "enterprise".to_owned(),
                    name: "Enterprise".to_owned(),
                    price: Decimal::new(5000, 2),
                    up_to: None,
                    features: vec![],
                },
            ],
            tier_mode: TierMode::Graduated,
        });
        assert_eq!(pricing.minimum_price(), Decimal::new(1000, 2));
    }

    // ========================================================================
    // PerSeat Tests
    // ========================================================================

    #[test]
    fn test_per_seat_minimum_price_with_minimum() {
        let pricing = PricingModel::PerSeat(PerSeatPrice {
            price_per_seat: Decimal::new(500, 2),
            minimum_seats: Some(5),
            maximum_seats: None,
            volume_discounts: vec![],
        });
        assert_eq!(pricing.minimum_price(), Decimal::new(2500, 2));
    }

    #[test]
    fn test_per_seat_minimum_price_no_minimum() {
        let pricing = PricingModel::PerSeat(PerSeatPrice {
            price_per_seat: Decimal::new(500, 2),
            minimum_seats: None,
            maximum_seats: Some(100),
            volume_discounts: vec![],
        });
        assert_eq!(pricing.minimum_price(), Decimal::new(500, 2));
    }

    #[test]
    fn test_per_seat_minimum_price_zero_seats() {
        let pricing = PricingModel::PerSeat(PerSeatPrice {
            price_per_seat: Decimal::new(500, 2),
            minimum_seats: Some(0),
            maximum_seats: None,
            volume_discounts: vec![],
        });
        assert_eq!(pricing.minimum_price(), Decimal::ZERO);
    }

    // ========================================================================
    // UsageBased Tests
    // ========================================================================

    #[test]
    fn test_usage_based_minimum_price_with_commitment() {
        let pricing = PricingModel::UsageBased(UsageBasedPrice {
            metric: UsageMetric {
                id: "api_calls".to_owned(),
                name: "API Calls".to_owned(),
                unit: "calls".to_owned(),
                aggregation: UsageAggregation::Sum,
            },
            price_per_unit: Decimal::new(1, 2),
            minimum_commitment: Some(Decimal::new(10000, 2)),
            usage_tiers: vec![],
        });
        assert_eq!(pricing.minimum_price(), Decimal::new(10000, 2));
    }

    #[test]
    fn test_usage_based_minimum_price_no_commitment() {
        let pricing = PricingModel::UsageBased(UsageBasedPrice {
            metric: UsageMetric {
                id: "storage".to_owned(),
                name: "Storage".to_owned(),
                unit: "GB".to_owned(),
                aggregation: UsageAggregation::Max,
            },
            price_per_unit: Decimal::new(10, 2),
            minimum_commitment: None,
            usage_tiers: vec![],
        });
        assert_eq!(pricing.minimum_price(), Decimal::ZERO);
    }

    // ========================================================================
    // Hybrid Tests
    // ========================================================================

    #[test]
    fn test_hybrid_minimum_price() {
        let pricing = PricingModel::Hybrid(HybridPrice {
            base_price: Decimal::new(2000, 2),
            included_usage: IncludedUsage {
                metric: UsageMetric {
                    id: "api_calls".to_owned(),
                    name: "API Calls".to_owned(),
                    unit: "calls".to_owned(),
                    aggregation: UsageAggregation::Sum,
                },
                quantity: 1000,
            },
            overage_pricing: OveragePricing {
                price_per_unit: Decimal::new(5, 2),
                max_overage: None,
                bill_immediately: false,
            },
        });
        assert_eq!(pricing.minimum_price(), Decimal::new(2000, 2));
    }

    #[test]
    fn test_hybrid_zero_base_price() {
        let pricing = PricingModel::Hybrid(HybridPrice {
            base_price: Decimal::ZERO,
            included_usage: IncludedUsage {
                metric: UsageMetric {
                    id: "requests".to_owned(),
                    name: "Requests".to_owned(),
                    unit: "requests".to_owned(),
                    aggregation: UsageAggregation::Sum,
                },
                quantity: 0,
            },
            overage_pricing: OveragePricing {
                price_per_unit: Decimal::new(1, 2),
                max_overage: Some(10000),
                bill_immediately: true,
            },
        });
        assert_eq!(pricing.minimum_price(), Decimal::ZERO);
    }

    // ========================================================================
    // Serialization Tests
    // ========================================================================

    #[test]
    fn test_tier_mode_volume_serialization() {
        let mode = TierMode::Volume;
        let json = serde_json::to_string(&mode).unwrap();
        assert_eq!(json, "\"volume\"");
    }

    #[test]
    fn test_tier_mode_graduated_serialization() {
        let mode = TierMode::Graduated;
        let json = serde_json::to_string(&mode).unwrap();
        assert_eq!(json, "\"graduated\"");
    }

    #[test]
    fn test_usage_aggregation_sum_serialization() {
        let agg = UsageAggregation::Sum;
        let json = serde_json::to_string(&agg).unwrap();
        assert_eq!(json, "\"sum\"");
    }

    #[test]
    fn test_usage_aggregation_max_serialization() {
        let agg = UsageAggregation::Max;
        let json = serde_json::to_string(&agg).unwrap();
        assert_eq!(json, "\"max\"");
    }

    #[test]
    fn test_usage_aggregation_last_value_serialization() {
        let agg = UsageAggregation::LastValue;
        let json = serde_json::to_string(&agg).unwrap();
        assert_eq!(json, "\"last_value\"");
    }

    #[test]
    fn test_usage_aggregation_average_serialization() {
        let agg = UsageAggregation::Average;
        let json = serde_json::to_string(&agg).unwrap();
        assert_eq!(json, "\"average\"");
    }

    #[test]
    fn test_pricing_model_serialization_flat_rate() {
        let pricing = PricingModel::FlatRate(FlatRatePrice {
            amount: Decimal::new(999, 2),
            setup_fee: Some(Decimal::new(100, 2)),
        });
        let json = serde_json::to_string(&pricing).unwrap();
        assert!(json.contains("\"type\":\"flat_rate\""));
    }

    #[test]
    fn test_pricing_model_serialization_tiered() {
        let pricing =
            PricingModel::Tiered(TieredPrice { tiers: vec![], tier_mode: TierMode::Volume });
        let json = serde_json::to_string(&pricing).unwrap();
        assert!(json.contains("\"type\":\"tiered\""));
    }
}
