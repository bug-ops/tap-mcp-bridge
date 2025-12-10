//! Proration calculation utilities.
//!
//! Provides helpers for calculating prorated credits and charges
//! when subscriptions change mid-cycle.

use chrono::{DateTime, Datelike, Duration, Utc};
use rust_decimal::Decimal;

use super::models::BillingCycle;
use crate::error::{BridgeError, Result};

/// Calculates prorated credit for unused time in current period.
///
/// # Arguments
///
/// * `current_period_start` - Start of the current billing period
/// * `current_period_end` - End of the current billing period
/// * `change_date` - When the change takes effect
/// * `current_amount` - Amount paid for the current period
///
/// # Returns
///
/// Credit amount for unused time
///
/// # Errors
///
/// Returns error if dates are invalid (`change_date` before `period_start` or after `period_end`).
///
/// # Examples
///
/// ```
/// use chrono::Utc;
/// use rust_decimal::Decimal;
/// use tap_mcp_bridge::mcp::subscriptions::proration::calculate_credit;
///
/// # fn example() -> tap_mcp_bridge::error::Result<()> {
/// let period_start = Utc::now();
/// let period_end = period_start + chrono::Duration::days(30);
/// let change_date = period_start + chrono::Duration::days(15);
/// let current_amount = Decimal::new(3000, 2); // $30.00
///
/// let credit = calculate_credit(period_start, period_end, change_date, current_amount)?;
/// # Ok(())
/// # }
/// ```
pub fn calculate_credit(
    current_period_start: DateTime<Utc>,
    current_period_end: DateTime<Utc>,
    change_date: DateTime<Utc>,
    current_amount: Decimal,
) -> Result<Decimal> {
    if change_date < current_period_start || change_date > current_period_end {
        return Err(BridgeError::ProrationError(
            "change_date must be within current billing period".to_owned(),
        ));
    }

    let total_duration = (current_period_end - current_period_start).num_seconds();
    let unused_duration = (current_period_end - change_date).num_seconds();

    if total_duration == 0 {
        return Ok(Decimal::ZERO);
    }

    let proration_factor = Decimal::from(unused_duration) / Decimal::from(total_duration);

    current_amount
        .checked_mul(proration_factor)
        .ok_or_else(|| BridgeError::ProrationError("Overflow in credit calculation".into()))
}

/// Calculates prorated charge for new plan/quantity starting mid-cycle.
///
/// # Arguments
///
/// * `current_period_start` - Start of the current billing period
/// * `current_period_end` - End of the current billing period
/// * `change_date` - When the change takes effect
/// * `new_amount` - Amount for the new plan/quantity per period
///
/// # Returns
///
/// Prorated charge amount for the remaining period
///
/// # Errors
///
/// Returns error if dates are invalid.
pub fn calculate_charge(
    current_period_start: DateTime<Utc>,
    current_period_end: DateTime<Utc>,
    change_date: DateTime<Utc>,
    new_amount: Decimal,
) -> Result<Decimal> {
    if change_date < current_period_start || change_date > current_period_end {
        return Err(BridgeError::ProrationError(
            "change_date must be within current billing period".to_owned(),
        ));
    }

    let total_duration = (current_period_end - current_period_start).num_seconds();
    let remaining_duration = (current_period_end - change_date).num_seconds();

    if total_duration == 0 {
        return Ok(Decimal::ZERO);
    }

    let proration_factor = Decimal::from(remaining_duration) / Decimal::from(total_duration);

    new_amount
        .checked_mul(proration_factor)
        .ok_or_else(|| BridgeError::ProrationError("Overflow in charge calculation".into()))
}

/// Calculates the next billing date based on billing cycle.
///
/// # Arguments
///
/// * `current_date` - Current date/time
/// * `cycle` - Billing cycle configuration
///
/// # Returns
///
/// Next billing date
#[must_use]
pub fn calculate_next_billing_date(
    current_date: DateTime<Utc>,
    cycle: &BillingCycle,
) -> DateTime<Utc> {
    match cycle {
        BillingCycle::Monthly { anchor_day } => {
            let mut next_date = current_date;
            let target_day = u32::from((*anchor_day).min(28));

            if current_date.day() >= target_day {
                next_date += Duration::days(32);
            }

            next_date.with_day(target_day).unwrap_or(next_date)
        }
        BillingCycle::Annual { anchor_month, anchor_day } => {
            let mut next_date = current_date;
            let target_month = u32::from((*anchor_month).min(12));
            let target_day = u32::from((*anchor_day).min(28));

            if current_date.month() > target_month
                || (current_date.month() == target_month && current_date.day() >= target_day)
            {
                next_date += Duration::days(366);
            }

            next_date
                .with_month(target_month)
                .and_then(|d| d.with_day(target_day))
                .unwrap_or(next_date)
        }
        BillingCycle::Weekly { anchor_day } => {
            let current_weekday = current_date.weekday().num_days_from_sunday();
            let target_weekday = u32::from(*anchor_day).min(6);

            let days_until_target = if current_weekday < target_weekday {
                target_weekday - current_weekday
            } else {
                7 - (current_weekday - target_weekday)
            };

            current_date + Duration::days(i64::from(days_until_target))
        }
        BillingCycle::Custom { interval_days } => {
            current_date + Duration::days(i64::from(*interval_days))
        }
        BillingCycle::OneTime { .. } => current_date,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ========================================================================
    // Credit Calculation Tests
    // ========================================================================

    #[test]
    fn test_calculate_credit_half_period() {
        let start = Utc::now();
        let end = start + Duration::days(30);
        let change = start + Duration::days(15);
        let amount = Decimal::new(3000, 2);

        let credit = calculate_credit(start, end, change, amount).unwrap();
        assert!(credit > Decimal::new(1400, 2));
        assert!(credit < Decimal::new(1600, 2));
    }

    #[test]
    fn test_calculate_credit_end_of_period() {
        let start = Utc::now();
        let end = start + Duration::days(30);
        let change = end;
        let amount = Decimal::new(3000, 2);

        let credit = calculate_credit(start, end, change, amount).unwrap();
        assert_eq!(credit, Decimal::ZERO);
    }

    #[test]
    fn test_calculate_credit_start_of_period() {
        let start = Utc::now();
        let end = start + Duration::days(30);
        let change = start;
        let amount = Decimal::new(3000, 2);

        let credit = calculate_credit(start, end, change, amount).unwrap();
        assert_eq!(credit, amount);
    }

    #[test]
    fn test_calculate_credit_invalid_date_before_start() {
        let start = Utc::now();
        let end = start + Duration::days(30);
        let change = start - Duration::days(1);
        let amount = Decimal::new(3000, 2);

        let result = calculate_credit(start, end, change, amount);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), BridgeError::ProrationError(_)));
    }

    #[test]
    fn test_calculate_credit_invalid_date_after_end() {
        let start = Utc::now();
        let end = start + Duration::days(30);
        let change = end + Duration::days(1);
        let amount = Decimal::new(3000, 2);

        let result = calculate_credit(start, end, change, amount);
        assert!(result.is_err());
    }

    #[test]
    fn test_calculate_credit_zero_duration_period() {
        let now = Utc::now();
        let amount = Decimal::new(3000, 2);

        let credit = calculate_credit(now, now, now, amount).unwrap();
        assert_eq!(credit, Decimal::ZERO);
    }

    // ========================================================================
    // Charge Calculation Tests
    // ========================================================================

    #[test]
    fn test_calculate_charge_half_period() {
        let start = Utc::now();
        let end = start + Duration::days(30);
        let change = start + Duration::days(15);
        let amount = Decimal::new(5000, 2);

        let charge = calculate_charge(start, end, change, amount).unwrap();
        assert!(charge > Decimal::new(2400, 2));
        assert!(charge < Decimal::new(2600, 2));
    }

    #[test]
    fn test_calculate_charge_start_of_period() {
        let start = Utc::now();
        let end = start + Duration::days(30);
        let change = start;
        let amount = Decimal::new(5000, 2);

        let charge = calculate_charge(start, end, change, amount).unwrap();
        assert_eq!(charge, amount);
    }

    #[test]
    fn test_calculate_charge_end_of_period() {
        let start = Utc::now();
        let end = start + Duration::days(30);
        let change = end;
        let amount = Decimal::new(5000, 2);

        let charge = calculate_charge(start, end, change, amount).unwrap();
        assert_eq!(charge, Decimal::ZERO);
    }

    #[test]
    fn test_calculate_charge_invalid_date_before_start() {
        let start = Utc::now();
        let end = start + Duration::days(30);
        let change = start - Duration::days(1);
        let amount = Decimal::new(5000, 2);

        let result = calculate_charge(start, end, change, amount);
        assert!(result.is_err());
    }

    #[test]
    fn test_calculate_charge_invalid_date_after_end() {
        let start = Utc::now();
        let end = start + Duration::days(30);
        let change = end + Duration::days(1);
        let amount = Decimal::new(5000, 2);

        let result = calculate_charge(start, end, change, amount);
        assert!(result.is_err());
    }

    #[test]
    fn test_calculate_charge_zero_duration_period() {
        let now = Utc::now();
        let amount = Decimal::new(5000, 2);

        let charge = calculate_charge(now, now, now, amount).unwrap();
        assert_eq!(charge, Decimal::ZERO);
    }

    // ========================================================================
    // Next Billing Date Tests - Monthly
    // ========================================================================

    #[test]
    fn test_calculate_next_billing_date_monthly() {
        let current = Utc::now();
        let cycle = BillingCycle::Monthly { anchor_day: 15 };

        let next = calculate_next_billing_date(current, &cycle);
        assert!(next >= current);
        assert!(next.day() <= 15);
    }

    #[test]
    fn test_calculate_next_billing_date_monthly_anchor_day_28() {
        let current = Utc::now();
        let cycle = BillingCycle::Monthly { anchor_day: 28 };

        let next = calculate_next_billing_date(current, &cycle);
        assert!(next >= current);
        assert!(next.day() <= 28);
    }

    #[test]
    fn test_calculate_next_billing_date_monthly_anchor_day_clamped() {
        let current = Utc::now();
        let cycle = BillingCycle::Monthly { anchor_day: 31 };

        let next = calculate_next_billing_date(current, &cycle);
        assert!(next >= current);
        assert!(next.day() <= 28);
    }

    // ========================================================================
    // Next Billing Date Tests - Annual
    // ========================================================================

    #[test]
    fn test_calculate_next_billing_date_annual() {
        let current = Utc::now();
        let cycle = BillingCycle::Annual { anchor_month: 6, anchor_day: 15 };

        let next = calculate_next_billing_date(current, &cycle);
        assert!(next >= current);
    }

    #[test]
    fn test_calculate_next_billing_date_annual_month_clamped() {
        let current = Utc::now();
        let cycle = BillingCycle::Annual { anchor_month: 13, anchor_day: 15 };

        let next = calculate_next_billing_date(current, &cycle);
        assert!(next >= current);
        assert!(next.month() <= 12);
    }

    #[test]
    fn test_calculate_next_billing_date_annual_day_clamped() {
        let current = Utc::now();
        let cycle = BillingCycle::Annual { anchor_month: 6, anchor_day: 31 };

        let next = calculate_next_billing_date(current, &cycle);
        assert!(next >= current);
        assert!(next.day() <= 28);
    }

    // ========================================================================
    // Next Billing Date Tests - Weekly
    // ========================================================================

    #[test]
    fn test_calculate_next_billing_date_weekly_monday() {
        let current = Utc::now();
        let cycle = BillingCycle::Weekly { anchor_day: 1 };

        let next = calculate_next_billing_date(current, &cycle);
        assert!(next >= current);
        let days_diff = (next - current).num_days();
        assert!(days_diff <= 7);
    }

    #[test]
    fn test_calculate_next_billing_date_weekly_sunday() {
        let current = Utc::now();
        let cycle = BillingCycle::Weekly { anchor_day: 0 };

        let next = calculate_next_billing_date(current, &cycle);
        assert!(next >= current);
        let days_diff = (next - current).num_days();
        assert!(days_diff <= 7);
    }

    #[test]
    fn test_calculate_next_billing_date_weekly_saturday() {
        let current = Utc::now();
        let cycle = BillingCycle::Weekly { anchor_day: 6 };

        let next = calculate_next_billing_date(current, &cycle);
        assert!(next >= current);
        let days_diff = (next - current).num_days();
        assert!(days_diff <= 7);
    }

    #[test]
    fn test_calculate_next_billing_date_weekly_anchor_clamped() {
        let current = Utc::now();
        let cycle = BillingCycle::Weekly { anchor_day: 10 };

        let next = calculate_next_billing_date(current, &cycle);
        assert!(next >= current);
    }

    // ========================================================================
    // Next Billing Date Tests - Custom
    // ========================================================================

    #[test]
    fn test_calculate_next_billing_date_custom_interval() {
        let current = Utc::now();
        let cycle = BillingCycle::Custom { interval_days: 14 };

        let next = calculate_next_billing_date(current, &cycle);
        assert_eq!((next - current).num_days(), 14);
    }

    #[test]
    fn test_calculate_next_billing_date_custom_single_day() {
        let current = Utc::now();
        let cycle = BillingCycle::Custom { interval_days: 1 };

        let next = calculate_next_billing_date(current, &cycle);
        assert_eq!((next - current).num_days(), 1);
    }

    #[test]
    fn test_calculate_next_billing_date_custom_large_interval() {
        let current = Utc::now();
        let cycle = BillingCycle::Custom { interval_days: 365 };

        let next = calculate_next_billing_date(current, &cycle);
        assert_eq!((next - current).num_days(), 365);
    }

    // ========================================================================
    // Next Billing Date Tests - OneTime
    // ========================================================================

    #[test]
    fn test_calculate_next_billing_date_onetime_no_validity() {
        let current = Utc::now();
        let cycle = BillingCycle::OneTime { validity_days: None };

        let next = calculate_next_billing_date(current, &cycle);
        assert_eq!(next, current);
    }

    #[test]
    fn test_calculate_next_billing_date_onetime_with_validity() {
        let current = Utc::now();
        let cycle = BillingCycle::OneTime { validity_days: Some(30) };

        let next = calculate_next_billing_date(current, &cycle);
        assert_eq!(next, current);
    }
}
