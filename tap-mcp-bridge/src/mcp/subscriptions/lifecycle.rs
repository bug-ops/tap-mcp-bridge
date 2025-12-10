//! Subscription lifecycle management using typestate pattern.
//!
//! Makes invalid state transitions compile-time errors.

use std::marker::PhantomData;

use chrono::{DateTime, Utc};
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};

use super::models::{BillingCycle, PlanId, SubscriptionId};
use crate::mcp::models::Address;

// ============================================================================
// State Marker Types (Zero-Sized)
// ============================================================================

/// Trial state - subscription is in trial period.
#[derive(Debug, Clone, Copy)]
pub struct Trial;

/// Active state - subscription is paid and active.
#[derive(Debug, Clone, Copy)]
pub struct Active;

/// Paused state - subscription billing is suspended.
#[derive(Debug, Clone, Copy)]
pub struct Paused;

/// `PastDue` state - payment failed, in grace period.
#[derive(Debug, Clone, Copy)]
pub struct PastDue;

/// Canceled state - subscription terminated.
#[derive(Debug, Clone, Copy)]
pub struct Canceled;

/// Expired state - subscription validity period ended.
#[derive(Debug, Clone, Copy)]
pub struct Expired;

// ============================================================================
// Subscription with Typestate
// ============================================================================

/// Subscription instance with compile-time state tracking.
///
/// Uses typestate pattern to ensure only valid state transitions compile.
/// For example, you cannot call `cancel()` on an already `Canceled` subscription.
///
/// # State Machine
///
/// ```text
/// Trial ──────┬─► Active ◄─────┬─► Paused ──► Active
///             │      │         │
///             │      ▼         │
///             │   PastDue ─────┤
///             │      │         │
///             ▼      ▼         ▼
///          Canceled/Expired
/// ```
#[derive(Debug, Clone)]
pub struct Subscription<State> {
    /// Core subscription data (state-independent).
    pub(crate) data: SubscriptionData,
    /// Phantom marker for state.
    _state: PhantomData<State>,
}

/// State-independent subscription data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubscriptionData {
    /// Unique subscription identifier.
    pub id: SubscriptionId,
    /// Associated plan identifier.
    pub plan_id: PlanId,
    /// Consumer identifier.
    pub consumer_id: String,
    /// Current quantity (seats, licenses).
    pub quantity: u32,
    /// Creation timestamp.
    pub created_at: DateTime<Utc>,
    /// Current period start.
    pub current_period_start: DateTime<Utc>,
    /// Current period end.
    pub current_period_end: DateTime<Utc>,
    /// Billing address.
    pub billing_address: Option<Address>,
    /// Billing cycle.
    pub billing_cycle: BillingCycle,
    /// Currency code (ISO 4217).
    pub currency: String,
    /// Current period amount.
    pub current_period_amount: Decimal,
    /// Payment method reference (encrypted in APC).
    pub payment_method_id: Option<String>,
    /// Merchant-specific metadata.
    #[serde(default)]
    pub metadata: serde_json::Value,
    /// State-specific data.
    pub state_data: StateData,
}

/// State-specific data stored alongside subscription.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum StateData {
    /// Trial state data.
    Trial {
        /// Trial start timestamp.
        trial_start: DateTime<Utc>,
        /// Trial end timestamp.
        trial_end: DateTime<Utc>,
    },
    /// Active state data.
    Active {
        /// Activation timestamp.
        activated_at: DateTime<Utc>,
        /// Last successful payment timestamp.
        last_payment_at: Option<DateTime<Utc>>,
    },
    /// Paused state data.
    Paused {
        /// Pause timestamp.
        paused_at: DateTime<Utc>,
        /// Scheduled resume timestamp (optional).
        resume_at: Option<DateTime<Utc>>,
        /// Pause reason.
        pause_reason: Option<String>,
    },
    /// Past-due state data.
    PastDue {
        /// When subscription became past-due.
        became_past_due_at: DateTime<Utc>,
        /// Grace period expiration.
        grace_period_ends: DateTime<Utc>,
        /// Number of payment failure attempts.
        failure_count: u32,
        /// Last failure reason.
        last_failure_reason: Option<String>,
    },
    /// Canceled state data.
    Canceled {
        /// Cancellation timestamp.
        canceled_at: DateTime<Utc>,
        /// Effective end date.
        effective_end: DateTime<Utc>,
        /// Cancellation reason.
        cancellation_reason: Option<String>,
        /// Refund amount.
        refund_amount: Option<Decimal>,
    },
    /// Expired state data.
    Expired {
        /// Expiration timestamp.
        expired_at: DateTime<Utc>,
    },
}

// ============================================================================
// State-Specific Implementations
// ============================================================================

// --- Trial State Methods ---

impl Subscription<Trial> {
    /// Activates trial subscription to active paid state.
    ///
    /// Called when trial converts to paid subscription.
    #[must_use]
    pub fn activate(self) -> Subscription<Active> {
        let mut data = self.data;
        data.state_data = StateData::Active { activated_at: Utc::now(), last_payment_at: None };
        Subscription { data, _state: PhantomData }
    }

    /// Cancels trial without converting to paid.
    #[must_use]
    pub fn cancel(self, reason: Option<String>) -> Subscription<Canceled> {
        let now = Utc::now();
        let mut data = self.data;
        data.state_data = StateData::Canceled {
            canceled_at: now,
            effective_end: now,
            cancellation_reason: reason,
            refund_amount: None,
        };
        Subscription { data, _state: PhantomData }
    }

    /// Returns trial end date.
    #[must_use]
    pub fn trial_ends_at(&self) -> Option<DateTime<Utc>> {
        match &self.data.state_data {
            StateData::Trial { trial_end, .. } => Some(*trial_end),
            _ => None,
        }
    }

    /// Checks if trial has expired.
    #[must_use]
    pub fn is_trial_expired(&self) -> bool {
        self.trial_ends_at().is_some_and(|end| end < Utc::now())
    }
}

// --- Active State Methods ---

impl Subscription<Active> {
    /// Pauses active subscription.
    ///
    /// Billing is suspended until resumed.
    #[must_use]
    pub fn pause(
        self,
        reason: Option<String>,
        resume_at: Option<DateTime<Utc>>,
    ) -> Subscription<Paused> {
        let mut data = self.data;
        data.state_data =
            StateData::Paused { paused_at: Utc::now(), resume_at, pause_reason: reason };
        Subscription { data, _state: PhantomData }
    }

    /// Cancels active subscription.
    ///
    /// # Arguments
    ///
    /// * `reason` - Cancellation reason for records
    /// * `immediate` - If true, cancel immediately; if false, cancel at period end
    /// * `refund_amount` - Optional prorated refund amount
    ///
    /// # Errors
    ///
    /// Returns error if `refund_amount` is negative.
    pub fn cancel(
        self,
        reason: Option<String>,
        immediate: bool,
        refund_amount: Option<Decimal>,
    ) -> crate::error::Result<Subscription<Canceled>> {
        // Validate refund amount is non-negative
        if let Some(ref amount) = refund_amount
            && amount.is_sign_negative()
        {
            return Err(crate::error::BridgeError::SubscriptionError(
                "Refund amount cannot be negative".into(),
            ));
        }

        let now = Utc::now();
        let effective_end = if immediate {
            now
        } else {
            self.data.current_period_end
        };

        let mut data = self.data;
        data.state_data = StateData::Canceled {
            canceled_at: now,
            effective_end,
            cancellation_reason: reason,
            refund_amount,
        };
        Ok(Subscription { data, _state: PhantomData })
    }

    /// Transitions to past-due when payment fails.
    #[must_use]
    pub fn mark_past_due(
        self,
        grace_period_days: u32,
        failure_reason: Option<String>,
    ) -> Subscription<PastDue> {
        let now = Utc::now();
        let mut data = self.data;
        data.state_data = StateData::PastDue {
            became_past_due_at: now,
            grace_period_ends: now + chrono::Duration::days(i64::from(grace_period_days)),
            failure_count: 1,
            last_failure_reason: failure_reason,
        };
        Subscription { data, _state: PhantomData }
    }

    /// Updates quantity (seats/licenses) with proration.
    #[must_use]
    pub fn update_quantity(mut self, new_quantity: u32) -> Self {
        self.data.quantity = new_quantity;
        self
    }
}

// --- Paused State Methods ---

impl Subscription<Paused> {
    /// Resumes paused subscription.
    #[must_use]
    pub fn resume(self) -> Subscription<Active> {
        let mut data = self.data;
        data.state_data = StateData::Active { activated_at: Utc::now(), last_payment_at: None };
        Subscription { data, _state: PhantomData }
    }

    /// Cancels paused subscription.
    #[must_use]
    pub fn cancel(self, reason: Option<String>) -> Subscription<Canceled> {
        let now = Utc::now();
        let mut data = self.data;
        data.state_data = StateData::Canceled {
            canceled_at: now,
            effective_end: now,
            cancellation_reason: reason,
            refund_amount: None,
        };
        Subscription { data, _state: PhantomData }
    }

    /// Returns scheduled resume date if set.
    #[must_use]
    pub fn resume_at(&self) -> Option<DateTime<Utc>> {
        match &self.data.state_data {
            StateData::Paused { resume_at, .. } => *resume_at,
            _ => None,
        }
    }
}

// --- PastDue State Methods ---

impl Subscription<PastDue> {
    /// Recovers to active when payment succeeds.
    #[must_use]
    pub fn recover(self) -> Subscription<Active> {
        let mut data = self.data;
        data.state_data =
            StateData::Active { activated_at: Utc::now(), last_payment_at: Some(Utc::now()) };
        Subscription { data, _state: PhantomData }
    }

    /// Cancels after grace period exhausted.
    #[must_use]
    pub fn expire_grace_period(self) -> Subscription<Canceled> {
        let now = Utc::now();
        let mut data = self.data;
        data.state_data = StateData::Canceled {
            canceled_at: now,
            effective_end: now,
            cancellation_reason: Some("Payment failed - grace period expired".into()),
            refund_amount: None,
        };
        Subscription { data, _state: PhantomData }
    }

    /// Increments failure count on retry failure.
    #[must_use]
    pub fn record_failure(mut self, reason: Option<String>) -> Self {
        if let StateData::PastDue { failure_count, last_failure_reason, .. } =
            &mut self.data.state_data
        {
            *failure_count += 1;
            *last_failure_reason = reason;
        }
        self
    }

    /// Returns failure count.
    #[must_use]
    pub fn failure_count(&self) -> u32 {
        match &self.data.state_data {
            StateData::PastDue { failure_count, .. } => *failure_count,
            _ => 0,
        }
    }
}

// --- Common Methods (All States) ---

impl<S> Subscription<S> {
    /// Returns the subscription ID.
    #[must_use]
    pub fn id(&self) -> &SubscriptionId {
        &self.data.id
    }

    /// Returns the plan ID.
    #[must_use]
    pub fn plan_id(&self) -> &PlanId {
        &self.data.plan_id
    }

    /// Returns the consumer ID.
    #[must_use]
    pub fn consumer_id(&self) -> &str {
        &self.data.consumer_id
    }

    /// Returns current quantity.
    #[must_use]
    pub fn quantity(&self) -> u32 {
        self.data.quantity
    }

    /// Returns current period end date.
    #[must_use]
    pub fn current_period_end(&self) -> DateTime<Utc> {
        self.data.current_period_end
    }

    /// Returns the underlying data (for serialization).
    #[must_use]
    pub fn into_data(self) -> SubscriptionData {
        self.data
    }

    /// Returns reference to underlying data.
    #[must_use]
    pub fn data(&self) -> &SubscriptionData {
        &self.data
    }
}

// ============================================================================
// Runtime State (for API responses)
// ============================================================================

/// Runtime subscription status for API responses.
///
/// Unlike the typestate `Subscription<S>`, this is used for serialization
/// and when the state must be determined at runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SubscriptionStatus {
    /// Trial state.
    Trial,
    /// Active state.
    Active,
    /// Paused state.
    Paused,
    /// Past-due state.
    PastDue,
    /// Canceled state.
    Canceled,
    /// Expired state.
    Expired,
}

/// Dynamic subscription representation for API responses.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubscriptionResponse {
    /// Subscription data.
    #[serde(flatten)]
    pub data: SubscriptionData,
    /// Current status.
    pub status: SubscriptionStatus,
}

impl SubscriptionResponse {
    /// Creates response from typed subscription.
    #[must_use]
    pub fn from_trial(sub: Subscription<Trial>) -> Self {
        Self { data: sub.data, status: SubscriptionStatus::Trial }
    }

    /// Creates response from active subscription.
    #[must_use]
    pub fn from_active(sub: Subscription<Active>) -> Self {
        Self { data: sub.data, status: SubscriptionStatus::Active }
    }

    /// Creates response from paused subscription.
    #[must_use]
    pub fn from_paused(sub: Subscription<Paused>) -> Self {
        Self { data: sub.data, status: SubscriptionStatus::Paused }
    }

    /// Creates response from past-due subscription.
    #[must_use]
    pub fn from_past_due(sub: Subscription<PastDue>) -> Self {
        Self { data: sub.data, status: SubscriptionStatus::PastDue }
    }

    /// Creates response from canceled subscription.
    #[must_use]
    pub fn from_canceled(sub: Subscription<Canceled>) -> Self {
        Self { data: sub.data, status: SubscriptionStatus::Canceled }
    }

    /// Creates response from expired subscription.
    #[must_use]
    pub fn from_expired(sub: Subscription<Expired>) -> Self {
        Self { data: sub.data, status: SubscriptionStatus::Expired }
    }
}

#[cfg(test)]
#[allow(
    clippy::unreachable,
    reason = "Test code uses unreachable! for invalid state assertions"
)]
mod tests {
    use super::*;

    // ========================================================================
    // Test Helpers
    // ========================================================================

    fn create_test_subscription_data() -> SubscriptionData {
        let now = Utc::now();
        SubscriptionData {
            id: SubscriptionId::new("sub-test-123").unwrap(),
            plan_id: PlanId::new("plan-basic").unwrap(),
            consumer_id: "consumer-456".to_owned(),
            quantity: 1,
            created_at: now,
            current_period_start: now,
            current_period_end: now + chrono::Duration::days(30),
            billing_address: None,
            billing_cycle: BillingCycle::Monthly { anchor_day: 1 },
            currency: "USD".to_owned(),
            current_period_amount: Decimal::new(999, 2),
            payment_method_id: None,
            metadata: serde_json::Value::Null,
            state_data: StateData::Trial {
                trial_start: now,
                trial_end: now + chrono::Duration::days(14),
            },
        }
    }

    // ========================================================================
    // Trial State Tests
    // ========================================================================

    #[test]
    fn test_trial_to_active_transition() {
        let data = create_test_subscription_data();
        let trial_sub = Subscription::<Trial> { data, _state: PhantomData };

        let active_sub = trial_sub.activate();

        match active_sub.data.state_data {
            StateData::Active { activated_at, last_payment_at } => {
                assert!(activated_at <= Utc::now());
                assert!(last_payment_at.is_none());
            }
            _ => unreachable!("Expected Active state"),
        }
    }

    #[test]
    fn test_trial_to_canceled_transition() {
        let data = create_test_subscription_data();
        let trial_sub = Subscription::<Trial> { data, _state: PhantomData };

        let canceled_sub = trial_sub.cancel(Some("User requested".to_owned()));

        match canceled_sub.data.state_data {
            StateData::Canceled {
                canceled_at,
                effective_end,
                cancellation_reason,
                refund_amount,
            } => {
                assert!(canceled_at <= Utc::now());
                assert_eq!(canceled_at, effective_end);
                assert_eq!(cancellation_reason.as_deref(), Some("User requested"));
                assert!(refund_amount.is_none());
            }
            _ => unreachable!("Expected Canceled state"),
        }
    }

    #[test]
    fn test_trial_ends_at() {
        let data = create_test_subscription_data();
        let trial_sub = Subscription::<Trial> { data, _state: PhantomData };

        let trial_end = trial_sub.trial_ends_at();
        assert!(trial_end.is_some());
    }

    #[test]
    fn test_trial_is_expired() {
        let now = Utc::now();
        let mut data = create_test_subscription_data();
        data.state_data = StateData::Trial {
            trial_start: now - chrono::Duration::days(20),
            trial_end: now - chrono::Duration::days(5),
        };
        let trial_sub = Subscription::<Trial> { data, _state: PhantomData };

        assert!(trial_sub.is_trial_expired());
    }

    #[test]
    fn test_trial_not_expired() {
        let now = Utc::now();
        let mut data = create_test_subscription_data();
        data.state_data =
            StateData::Trial { trial_start: now, trial_end: now + chrono::Duration::days(14) };
        let trial_sub = Subscription::<Trial> { data, _state: PhantomData };

        assert!(!trial_sub.is_trial_expired());
    }

    // ========================================================================
    // Active State Tests
    // ========================================================================

    #[test]
    fn test_active_to_paused_transition() {
        let mut data = create_test_subscription_data();
        data.state_data = StateData::Active { activated_at: Utc::now(), last_payment_at: None };
        let active_sub = Subscription::<Active> { data, _state: PhantomData };

        let resume_at = Utc::now() + chrono::Duration::days(30);
        let paused_sub = active_sub.pause(Some("Vacation".to_owned()), Some(resume_at));

        match paused_sub.data.state_data {
            StateData::Paused { paused_at, resume_at: r, pause_reason } => {
                assert!(paused_at <= Utc::now());
                assert_eq!(r, Some(resume_at));
                assert_eq!(pause_reason.as_deref(), Some("Vacation"));
            }
            _ => unreachable!("Expected Paused state"),
        }
    }

    #[test]
    fn test_active_to_canceled_immediate() {
        let mut data = create_test_subscription_data();
        data.state_data = StateData::Active { activated_at: Utc::now(), last_payment_at: None };
        let active_sub = Subscription::<Active> { data, _state: PhantomData };

        let refund = Decimal::new(500, 2);
        let canceled_sub =
            active_sub.cancel(Some("Not satisfied".to_owned()), true, Some(refund)).unwrap();

        match canceled_sub.data.state_data {
            StateData::Canceled { canceled_at, effective_end, refund_amount, .. } => {
                assert_eq!(canceled_at, effective_end);
                assert_eq!(refund_amount, Some(refund));
            }
            _ => unreachable!("Expected Canceled state"),
        }
    }

    #[test]
    fn test_active_to_canceled_at_period_end() {
        let mut data = create_test_subscription_data();
        let period_end = data.current_period_end;
        data.state_data = StateData::Active { activated_at: Utc::now(), last_payment_at: None };
        let active_sub = Subscription::<Active> { data, _state: PhantomData };

        let canceled_sub =
            active_sub.cancel(Some("Switching provider".to_owned()), false, None).unwrap();

        match canceled_sub.data.state_data {
            StateData::Canceled { canceled_at, effective_end, .. } => {
                assert!(canceled_at < effective_end);
                assert_eq!(effective_end, period_end);
            }
            _ => unreachable!("Expected Canceled state"),
        }
    }

    #[test]
    fn test_active_to_past_due_transition() {
        let mut data = create_test_subscription_data();
        data.state_data = StateData::Active {
            activated_at: Utc::now(),
            last_payment_at: Some(Utc::now() - chrono::Duration::days(30)),
        };
        let active_sub = Subscription::<Active> { data, _state: PhantomData };

        let grace_period = 7;
        let past_due_sub =
            active_sub.mark_past_due(grace_period, Some("Insufficient funds".to_owned()));

        match past_due_sub.data.state_data {
            StateData::PastDue {
                became_past_due_at,
                grace_period_ends,
                failure_count,
                last_failure_reason,
            } => {
                assert!(became_past_due_at <= Utc::now());
                assert!(grace_period_ends > became_past_due_at);
                assert_eq!(failure_count, 1);
                assert_eq!(last_failure_reason.as_deref(), Some("Insufficient funds"));
            }
            _ => unreachable!("Expected PastDue state"),
        }
    }

    #[test]
    fn test_active_update_quantity() {
        let mut data = create_test_subscription_data();
        data.state_data = StateData::Active { activated_at: Utc::now(), last_payment_at: None };
        let active_sub = Subscription::<Active> { data, _state: PhantomData };

        let updated_sub = active_sub.update_quantity(5);
        assert_eq!(updated_sub.quantity(), 5);
    }

    // ========================================================================
    // Paused State Tests
    // ========================================================================

    #[test]
    fn test_paused_to_active_transition() {
        let mut data = create_test_subscription_data();
        data.state_data =
            StateData::Paused { paused_at: Utc::now(), resume_at: None, pause_reason: None };
        let paused_sub = Subscription::<Paused> { data, _state: PhantomData };

        let active_sub = paused_sub.resume();

        match active_sub.data.state_data {
            StateData::Active { activated_at, .. } => {
                assert!(activated_at <= Utc::now());
            }
            _ => unreachable!("Expected Active state"),
        }
    }

    #[test]
    fn test_paused_to_canceled_transition() {
        let mut data = create_test_subscription_data();
        data.state_data = StateData::Paused {
            paused_at: Utc::now(),
            resume_at: None,
            pause_reason: Some("Testing".to_owned()),
        };
        let paused_sub = Subscription::<Paused> { data, _state: PhantomData };

        let canceled_sub = paused_sub.cancel(Some("No longer needed".to_owned()));

        match canceled_sub.data.state_data {
            StateData::Canceled { cancellation_reason, .. } => {
                assert_eq!(cancellation_reason.as_deref(), Some("No longer needed"));
            }
            _ => unreachable!("Expected Canceled state"),
        }
    }

    #[test]
    fn test_paused_resume_at() {
        let resume_time = Utc::now() + chrono::Duration::days(15);
        let mut data = create_test_subscription_data();
        data.state_data = StateData::Paused {
            paused_at: Utc::now(),
            resume_at: Some(resume_time),
            pause_reason: None,
        };
        let paused_sub = Subscription::<Paused> { data, _state: PhantomData };

        assert_eq!(paused_sub.resume_at(), Some(resume_time));
    }

    // ========================================================================
    // PastDue State Tests
    // ========================================================================

    #[test]
    fn test_past_due_to_active_recovery() {
        let mut data = create_test_subscription_data();
        data.state_data = StateData::PastDue {
            became_past_due_at: Utc::now() - chrono::Duration::days(3),
            grace_period_ends: Utc::now() + chrono::Duration::days(4),
            failure_count: 2,
            last_failure_reason: Some("Card declined".to_owned()),
        };
        let past_due_sub = Subscription::<PastDue> { data, _state: PhantomData };

        let active_sub = past_due_sub.recover();

        match active_sub.data.state_data {
            StateData::Active { activated_at, last_payment_at } => {
                assert!(activated_at <= Utc::now());
                assert!(last_payment_at.is_some());
            }
            _ => unreachable!("Expected Active state"),
        }
    }

    #[test]
    fn test_past_due_grace_period_expiration() {
        let mut data = create_test_subscription_data();
        data.state_data = StateData::PastDue {
            became_past_due_at: Utc::now() - chrono::Duration::days(10),
            grace_period_ends: Utc::now() - chrono::Duration::days(1),
            failure_count: 5,
            last_failure_reason: Some("Card expired".to_owned()),
        };
        let past_due_sub = Subscription::<PastDue> { data, _state: PhantomData };

        let canceled_sub = past_due_sub.expire_grace_period();

        match canceled_sub.data.state_data {
            StateData::Canceled { cancellation_reason, .. } => {
                assert!(cancellation_reason.unwrap().contains("grace period expired"));
            }
            _ => unreachable!("Expected Canceled state"),
        }
    }

    #[test]
    fn test_past_due_record_failure() {
        let mut data = create_test_subscription_data();
        data.state_data = StateData::PastDue {
            became_past_due_at: Utc::now(),
            grace_period_ends: Utc::now() + chrono::Duration::days(7),
            failure_count: 1,
            last_failure_reason: Some("First failure".to_owned()),
        };
        let past_due_sub = Subscription::<PastDue> { data, _state: PhantomData };

        let updated_sub = past_due_sub.record_failure(Some("Second failure".to_owned()));

        assert_eq!(updated_sub.failure_count(), 2);
        match updated_sub.data.state_data {
            StateData::PastDue { last_failure_reason, .. } => {
                assert_eq!(last_failure_reason.as_deref(), Some("Second failure"));
            }
            _ => unreachable!("Expected PastDue state"),
        }
    }

    #[test]
    fn test_past_due_failure_count() {
        let mut data = create_test_subscription_data();
        data.state_data = StateData::PastDue {
            became_past_due_at: Utc::now(),
            grace_period_ends: Utc::now() + chrono::Duration::days(7),
            failure_count: 3,
            last_failure_reason: None,
        };
        let past_due_sub = Subscription::<PastDue> { data, _state: PhantomData };

        assert_eq!(past_due_sub.failure_count(), 3);
    }

    // ========================================================================
    // SubscriptionStatus Serialization Tests
    // ========================================================================

    #[test]
    fn test_subscription_status_trial_serialization() {
        let status = SubscriptionStatus::Trial;
        let json = serde_json::to_string(&status).unwrap();
        assert_eq!(json, "\"trial\"");
    }

    #[test]
    fn test_subscription_status_active_serialization() {
        let status = SubscriptionStatus::Active;
        let json = serde_json::to_string(&status).unwrap();
        assert_eq!(json, "\"active\"");
    }

    #[test]
    fn test_subscription_status_paused_serialization() {
        let status = SubscriptionStatus::Paused;
        let json = serde_json::to_string(&status).unwrap();
        assert_eq!(json, "\"paused\"");
    }

    #[test]
    fn test_subscription_status_past_due_serialization() {
        let status = SubscriptionStatus::PastDue;
        let json = serde_json::to_string(&status).unwrap();
        assert_eq!(json, "\"past_due\"");
    }

    #[test]
    fn test_subscription_status_canceled_serialization() {
        let status = SubscriptionStatus::Canceled;
        let json = serde_json::to_string(&status).unwrap();
        assert_eq!(json, "\"canceled\"");
    }

    #[test]
    fn test_subscription_status_expired_serialization() {
        let status = SubscriptionStatus::Expired;
        let json = serde_json::to_string(&status).unwrap();
        assert_eq!(json, "\"expired\"");
    }

    // ========================================================================
    // StateData Serialization Tests
    // ========================================================================

    #[test]
    fn test_state_data_trial_serialization() {
        let now = Utc::now();
        let state =
            StateData::Trial { trial_start: now, trial_end: now + chrono::Duration::days(14) };
        let json = serde_json::to_string(&state).unwrap();
        assert!(json.contains("\"state\":\"trial\""));
    }

    #[test]
    fn test_state_data_active_serialization() {
        let state = StateData::Active { activated_at: Utc::now(), last_payment_at: None };
        let json = serde_json::to_string(&state).unwrap();
        assert!(json.contains("\"state\":\"active\""));
    }

    #[test]
    fn test_state_data_paused_serialization() {
        let state = StateData::Paused {
            paused_at: Utc::now(),
            resume_at: None,
            pause_reason: Some("Testing".to_owned()),
        };
        let json = serde_json::to_string(&state).unwrap();
        assert!(json.contains("\"state\":\"paused\""));
    }

    #[test]
    fn test_state_data_canceled_serialization() {
        let state = StateData::Canceled {
            canceled_at: Utc::now(),
            effective_end: Utc::now(),
            cancellation_reason: Some("Test".to_owned()),
            refund_amount: Some(Decimal::new(1000, 2)),
        };
        let json = serde_json::to_string(&state).unwrap();
        assert!(json.contains("\"state\":\"canceled\""));
    }

    // ========================================================================
    // SubscriptionResponse Tests
    // ========================================================================

    #[test]
    fn test_subscription_response_from_trial() {
        let data = create_test_subscription_data();
        let trial_sub = Subscription::<Trial> { data, _state: PhantomData };
        let response = SubscriptionResponse::from_trial(trial_sub);

        assert_eq!(response.status, SubscriptionStatus::Trial);
    }

    #[test]
    fn test_subscription_response_from_active() {
        let mut data = create_test_subscription_data();
        data.state_data = StateData::Active { activated_at: Utc::now(), last_payment_at: None };
        let active_sub = Subscription::<Active> { data, _state: PhantomData };
        let response = SubscriptionResponse::from_active(active_sub);

        assert_eq!(response.status, SubscriptionStatus::Active);
    }

    #[test]
    fn test_subscription_response_roundtrip() {
        let data = create_test_subscription_data();
        let trial_sub = Subscription::<Trial> { data, _state: PhantomData };
        let response = SubscriptionResponse::from_trial(trial_sub);

        let json = serde_json::to_string(&response).unwrap();
        let parsed: SubscriptionResponse = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.status, SubscriptionStatus::Trial);
        assert_eq!(parsed.data.id, response.data.id);
    }
}
