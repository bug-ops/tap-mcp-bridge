//! Audit logging for security-relevant events.
//!
//! Provides structured audit logging with sensitive data redaction
//! and unique correlation IDs for tracking requests across operations.

use std::time::{Duration, SystemTime};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Types of auditable events.
///
/// Each variant represents a security-relevant operation that should be
/// tracked for compliance and incident response purposes.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AuditEventType {
    /// Signature was generated for a TAP request.
    SignatureGenerated,
    /// Checkout operation was attempted.
    CheckoutAttempted,
    /// Checkout operation succeeded.
    CheckoutSucceeded,
    /// Checkout operation failed.
    CheckoutFailed,
    /// Browse operation was attempted.
    BrowseAttempted,
    /// Browse operation succeeded.
    BrowseSucceeded,
    /// Authentication failed (invalid signature, expired token, etc).
    AuthenticationFailed,
    /// Rate limit exceeded for an agent.
    RateLimitExceeded,
    /// Circuit breaker state changed.
    CircuitBreakerStateChanged,
}

/// Details for audit log entry.
///
/// Contains contextual information about the audited event.
/// Sensitive fields are marked with `skip_serializing_if` to avoid
/// logging when not applicable.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AuditDetails {
    /// Merchant URL (may be redacted if sensitive).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub merchant_url: Option<String>,
    /// Consumer ID (may be partially redacted).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub consumer_id: Option<String>,
    /// Request nonce for replay attack prevention.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    /// Error message (sensitive data automatically redacted).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Duration of the operation in milliseconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<u64>,
}

/// Audit log entry.
///
/// Represents a single auditable event with timestamp, type,
/// agent identity, and contextual details.
///
/// # Examples
///
/// ```
/// use tap_mcp_bridge::security::audit::{AuditEvent, AuditEventType};
/// use uuid::Uuid;
///
/// let event = AuditEvent::new(AuditEventType::SignatureGenerated, "agent-123", Uuid::new_v4())
///     .with_merchant_url("https://merchant.example.com")
///     .with_nonce("550e8400-e29b-41d4-a716-446655440000");
///
/// // Log the event
/// tap_mcp_bridge::security::audit::audit_log(&event);
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    /// Event timestamp (when the event occurred).
    pub timestamp: SystemTime,
    /// Event type (what happened).
    pub event_type: AuditEventType,
    /// Agent ID (who performed the action).
    pub agent_id: String,
    /// Request correlation ID (for tracking across operations).
    pub request_id: Uuid,
    /// Event details (contextual information).
    pub details: AuditDetails,
}

impl AuditEvent {
    /// Creates a new audit event.
    ///
    /// # Examples
    ///
    /// ```
    /// use tap_mcp_bridge::security::audit::{AuditEvent, AuditEventType};
    /// use uuid::Uuid;
    ///
    /// let event = AuditEvent::new(AuditEventType::CheckoutAttempted, "agent-456", Uuid::new_v4());
    /// ```
    #[must_use]
    #[allow(
        clippy::impl_trait_in_params,
        reason = "impl Into<String> is idiomatic for builder methods"
    )]
    pub fn new(event_type: AuditEventType, agent_id: impl Into<String>, request_id: Uuid) -> Self {
        Self {
            timestamp: SystemTime::now(),
            event_type,
            agent_id: agent_id.into(),
            request_id,
            details: AuditDetails::default(),
        }
    }

    /// Adds merchant URL to details.
    ///
    /// # Examples
    ///
    /// ```
    /// use tap_mcp_bridge::security::audit::{AuditEvent, AuditEventType};
    /// use uuid::Uuid;
    ///
    /// let event = AuditEvent::new(AuditEventType::CheckoutAttempted, "agent-789", Uuid::new_v4())
    ///     .with_merchant_url("https://merchant.example.com/checkout");
    /// ```
    #[must_use]
    #[allow(
        clippy::impl_trait_in_params,
        reason = "impl Into<String> is idiomatic for builder methods"
    )]
    pub fn with_merchant_url(mut self, url: impl Into<String>) -> Self {
        self.details.merchant_url = Some(url.into());
        self
    }

    /// Adds consumer ID to details.
    ///
    /// Consumer IDs should be partially redacted before logging
    /// to protect user privacy. Use `redact_consumer_id` helper.
    ///
    /// # Examples
    ///
    /// ```
    /// use tap_mcp_bridge::security::audit::{AuditEvent, AuditEventType, redact_consumer_id};
    /// use uuid::Uuid;
    ///
    /// let consumer_id = "user-1234567890";
    /// let event = AuditEvent::new(AuditEventType::CheckoutAttempted, "agent-123", Uuid::new_v4())
    ///     .with_consumer_id(redact_consumer_id(consumer_id));
    /// ```
    #[must_use]
    #[allow(
        clippy::impl_trait_in_params,
        reason = "impl Into<String> is idiomatic for builder methods"
    )]
    pub fn with_consumer_id(mut self, id: impl Into<String>) -> Self {
        self.details.consumer_id = Some(id.into());
        self
    }

    /// Adds nonce to details.
    ///
    /// # Examples
    ///
    /// ```
    /// use tap_mcp_bridge::security::audit::{AuditEvent, AuditEventType};
    /// use uuid::Uuid;
    ///
    /// let event = AuditEvent::new(AuditEventType::SignatureGenerated, "agent-456", Uuid::new_v4())
    ///     .with_nonce("550e8400-e29b-41d4-a716-446655440000");
    /// ```
    #[must_use]
    #[allow(
        clippy::impl_trait_in_params,
        reason = "impl Into<String> is idiomatic for builder methods"
    )]
    pub fn with_nonce(mut self, nonce: impl Into<String>) -> Self {
        self.details.nonce = Some(nonce.into());
        self
    }

    /// Adds error message to details.
    ///
    /// Automatically redacts sensitive data from the error message.
    ///
    /// # Examples
    ///
    /// ```
    /// use tap_mcp_bridge::security::audit::{AuditEvent, AuditEventType};
    /// use uuid::Uuid;
    ///
    /// let event = AuditEvent::new(AuditEventType::CheckoutFailed, "agent-789", Uuid::new_v4())
    ///     .with_error("Network timeout after 30s");
    /// ```
    #[must_use]
    #[allow(
        clippy::impl_trait_in_params,
        reason = "impl Into<String> is idiomatic for builder methods"
    )]
    pub fn with_error(mut self, error: impl Into<String>) -> Self {
        let error_msg = error.into();
        self.details.error = Some(redact_sensitive(&error_msg));
        self
    }

    /// Adds duration to details.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::time::Duration;
    ///
    /// use tap_mcp_bridge::security::audit::{AuditEvent, AuditEventType};
    /// use uuid::Uuid;
    ///
    /// let event = AuditEvent::new(AuditEventType::CheckoutSucceeded, "agent-123", Uuid::new_v4())
    ///     .with_duration(Duration::from_millis(1250));
    /// ```
    #[must_use]
    #[allow(
        clippy::cast_possible_truncation,
        reason = "duration in ms fits u64 for practical values"
    )]
    pub fn with_duration(mut self, duration: Duration) -> Self {
        self.details.duration_ms = Some(duration.as_millis() as u64);
        self
    }
}

/// Logs audit event to tracing with target "audit".
///
/// Audit logs use a special target for easy filtering and routing
/// to separate log files or SIEM systems.
///
/// # Examples
///
/// ```
/// use tap_mcp_bridge::security::audit::{AuditEvent, AuditEventType, audit_log};
/// use uuid::Uuid;
///
/// let event = AuditEvent::new(AuditEventType::SignatureGenerated, "agent-123", Uuid::new_v4())
///     .with_merchant_url("https://merchant.example.com")
///     .with_nonce("550e8400-e29b-41d4-a716-446655440000");
///
/// audit_log(&event);
/// ```
pub fn audit_log(event: &AuditEvent) {
    tracing::info!(
        target: "audit",
        timestamp = ?event.timestamp,
        event_type = ?event.event_type,
        agent_id = %event.agent_id,
        request_id = %event.request_id,
        details = ?event.details,
        "AUDIT"
    );
}

/// Redacts sensitive data from error messages.
///
/// Removes potential credit card numbers, CVV codes, and other
/// sensitive payment information from error messages before logging.
///
/// # Pattern Matching
///
/// - Credit card numbers (4 groups of 4 digits): `1234-5678-9012-3456` → `XXXX-XXXX-XXXX-XXXX`
/// - CVV codes (3-4 digits after CVV keyword): `CVV: 123` → `CVV: XXX`
/// - SSNs (3-2-4 digit pattern): `123-45-6789` → `XXX-XX-XXXX`
///
/// # Examples
///
/// ```
/// use tap_mcp_bridge::security::audit::redact_sensitive;
///
/// let msg = "Payment failed for card 1234-5678-9012-3456";
/// let redacted = redact_sensitive(msg);
/// assert!(redacted.contains("XXXX-XXXX-XXXX-XXXX"));
/// assert!(!redacted.contains("1234-5678-9012-3456"));
/// ```
#[must_use]
#[allow(
    clippy::string_slice,
    reason = "slicing is safe because we only operate on ASCII character boundaries"
)]
pub fn redact_sensitive(input: &str) -> String {
    let mut result = input.to_owned();
    let chars: Vec<char> = input.chars().collect();

    // Redact credit card numbers (16 digits with optional separators)
    // Pattern: DDDD-DDDD-DDDD-DDDD or DDDD DDDD DDDD DDDD or DDDDDDDDDDDDDDDD
    for i in 0..chars.len() {
        if i + 18 < chars.len() {
            // Check for pattern: DDDD-DDDD-DDDD-DDDD
            if is_digit_sequence(&chars, i, 4)
                && (chars[i + 4] == '-' || chars[i + 4] == ' ')
                && is_digit_sequence(&chars, i + 5, 4)
                && (chars[i + 9] == '-' || chars[i + 9] == ' ')
                && is_digit_sequence(&chars, i + 10, 4)
                && (chars[i + 14] == '-' || chars[i + 14] == ' ')
                && is_digit_sequence(&chars, i + 15, 4)
            {
                result = result.replace(&input[i..i + 19], "XXXX-XXXX-XXXX-XXXX");
            }
        }
        if i + 15 < chars.len() {
            // Check for 16 consecutive digits
            if is_digit_sequence(&chars, i, 16) {
                result = result.replace(&input[i..i + 16], "XXXX-XXXX-XXXX-XXXX");
            }
        }
    }

    // Redact CVV/CVC codes (3-4 digits after keywords)
    let cvv_keywords = ["cvv:", "cvc:", "cvv2:", "cid:", "cvv=", "cvc=", "cvv ", "cvc "];
    let mut i = 0;
    while i < result.len() {
        let result_lower = result[i..].to_lowercase();
        let mut found_keyword = None;

        for keyword in &cvv_keywords {
            if result_lower.starts_with(keyword) {
                found_keyword = Some(keyword.len());
                break;
            }
        }

        if let Some(keyword_len) = found_keyword {
            let after_keyword = i + keyword_len;
            if after_keyword < result.len() {
                let remaining = &result[after_keyword..];
                let (spaces, digits_start) = {
                    let mut spaces = 0;
                    for ch in remaining.chars() {
                        if ch.is_whitespace() {
                            spaces += 1;
                        } else {
                            break;
                        }
                    }
                    (spaces, after_keyword + spaces)
                };

                if digits_start < result.len() {
                    let remaining_after_spaces = &result[digits_start..];
                    let digits: String =
                        remaining_after_spaces.chars().take_while(char::is_ascii_digit).collect();

                    if digits.len() >= 3 && digits.len() <= 4 {
                        let original_section = &result[i..digits_start + digits.len()];
                        let redacted =
                            format!("{}{}XXX", &result[i..i + keyword_len], " ".repeat(spaces));
                        result = result.replace(original_section, &redacted);
                    }
                }
            }
            i += keyword_len;
        } else {
            i += 1;
        }
    }

    // Redact SSN patterns (XXX-XX-XXXX)
    for i in 0..chars.len() {
        if i + 10 < chars.len()
            && is_digit_sequence(&chars, i, 3)
            && chars[i + 3] == '-'
            && is_digit_sequence(&chars, i + 4, 2)
            && chars[i + 6] == '-'
            && is_digit_sequence(&chars, i + 7, 4)
        {
            result = result.replace(&input[i..i + 11], "XXX-XX-XXXX");
        }
    }

    result
}

/// Helper to check if a character sequence contains only digits.
fn is_digit_sequence(chars: &[char], start: usize, length: usize) -> bool {
    if start + length > chars.len() {
        return false;
    }
    chars[start..start + length].iter().all(char::is_ascii_digit)
}

/// Redacts consumer ID to show only last 4 characters.
///
/// Provides enough information for correlation while protecting
/// user privacy.
///
/// # Examples
///
/// ```
/// use tap_mcp_bridge::security::audit::redact_consumer_id;
///
/// assert_eq!(redact_consumer_id("user-1234567890"), "user-******7890");
/// assert_eq!(redact_consumer_id("abc"), "abc");
/// assert_eq!(redact_consumer_id(""), "");
/// ```
#[must_use]
#[allow(
    clippy::string_slice,
    reason = "slicing is safe because we validate lengths and only use ASCII"
)]
pub fn redact_consumer_id(consumer_id: &str) -> String {
    if consumer_id.len() <= 4 {
        return consumer_id.to_owned();
    }

    let len = consumer_id.len();
    let prefix_len = if consumer_id.contains('-') {
        // Keep prefix like "user-" intact
        consumer_id.find('-').map_or(0, |pos| pos + 1)
    } else {
        0
    };

    let visible_end = &consumer_id[len - 4..];
    let redacted_middle = "*".repeat(len - prefix_len - 4);

    if prefix_len > 0 {
        format!("{}{redacted_middle}{visible_end}", &consumer_id[..prefix_len])
    } else {
        format!("{redacted_middle}{visible_end}")
    }
}

/// Convenience macro for audit logging.
///
/// Simplifies creating and logging audit events in a single expression.
///
/// # Examples
///
/// ```
/// use tap_mcp_bridge::{audit, security::audit::AuditEventType};
/// use uuid::Uuid;
///
/// // Simple event without details
/// audit!(AuditEventType::SignatureGenerated, "agent-123", Uuid::new_v4());
///
/// // Event with details
/// audit!(
///     AuditEventType::CheckoutAttempted,
///     "agent-456",
///     Uuid::new_v4(),
///     with_merchant_url("https://merchant.example.com"),
///     with_consumer_id("user-123")
/// );
/// ```
#[macro_export]
macro_rules! audit {
    ($event_type:expr, $agent_id:expr, $request_id:expr) => {
        $crate::security::audit::audit_log(
            &$crate::security::audit::AuditEvent::new($event_type, $agent_id, $request_id)
        )
    };
    ($event_type:expr, $agent_id:expr, $request_id:expr, $($method:ident($arg:expr)),+ $(,)?) => {
        $crate::security::audit::audit_log(
            &$crate::security::audit::AuditEvent::new($event_type, $agent_id, $request_id)
                $(.$method($arg))+
        )
    };
}

#[cfg(test)]
#[allow(
    clippy::str_to_string,
    reason = "test code uses this pattern for readability"
)]
mod tests {
    use super::*;

    #[test]
    fn test_redact_credit_card() {
        let inputs = [
            ("Card: 1234-5678-9012-3456", "Card: XXXX-XXXX-XXXX-XXXX"),
            ("Card: 1234 5678 9012 3456", "Card: XXXX-XXXX-XXXX-XXXX"),
            ("Card: 1234567890123456", "Card: XXXX-XXXX-XXXX-XXXX"),
        ];

        for (input, expected) in &inputs {
            let result = redact_sensitive(input);
            assert_eq!(&result, expected, "Failed to redact: {input}");
        }
    }

    #[test]
    fn test_redact_cvv() {
        let inputs = [("CVV: 123", "CVV: XXX"), ("cvv: 1234", "cvv: XXX"), ("CVC=456", "CVC: XXX")];

        for (input, _expected) in &inputs {
            let result = redact_sensitive(input);
            assert!(!result.contains("123"), "CVV not redacted in: {result}");
            assert!(!result.contains("1234"), "CVV not redacted in: {result}");
            assert!(!result.contains("456"), "CVV not redacted in: {result}");
        }
    }

    #[test]
    fn test_redact_ssn() {
        let input = "SSN: 123-45-6789";
        let result = redact_sensitive(input);
        assert!(result.contains("XXX-XX-XXXX"), "SSN not redacted");
        assert!(!result.contains("123-45-6789"), "Original SSN still present");
    }

    #[test]
    fn test_redact_consumer_id() {
        assert_eq!(redact_consumer_id("user-1234567890"), "user-******7890");
        assert_eq!(redact_consumer_id("1234567890"), "******7890");
        assert_eq!(redact_consumer_id("abc"), "abc");
        assert_eq!(redact_consumer_id(""), "");
        assert_eq!(redact_consumer_id("a"), "a");
    }

    #[test]
    fn test_audit_event_builder() {
        let request_id = Uuid::new_v4();
        let event = AuditEvent::new(AuditEventType::CheckoutSucceeded, "test-agent", request_id)
            .with_merchant_url("https://example.com")
            .with_consumer_id("user-123")
            .with_nonce("test-nonce")
            .with_duration(Duration::from_millis(1500));

        assert_eq!(event.agent_id, "test-agent");
        assert_eq!(event.request_id, request_id);
        assert_eq!(event.details.merchant_url, Some("https://example.com".to_string()));
        assert_eq!(event.details.consumer_id, Some("user-123".to_string()));
        assert_eq!(event.details.nonce, Some("test-nonce".to_string()));
        assert_eq!(event.details.duration_ms, Some(1500));
    }

    #[test]
    fn test_audit_event_with_error() {
        let request_id = Uuid::new_v4();
        let event = AuditEvent::new(AuditEventType::CheckoutFailed, "test-agent", request_id)
            .with_error("Payment failed for card 1234-5678-9012-3456");

        let error = event.details.error.expect("Error should be set");
        assert!(!error.contains("1234-5678-9012-3456"), "Card number should be redacted");
        assert!(error.contains("XXXX-XXXX-XXXX-XXXX"), "Redacted placeholder should be present");
    }

    #[test]
    fn test_audit_event_serialization() {
        let request_id = Uuid::new_v4();
        let event = AuditEvent::new(AuditEventType::SignatureGenerated, "agent-123", request_id)
            .with_merchant_url("https://merchant.example.com")
            .with_nonce("test-nonce");

        let json = serde_json::to_string(&event).expect("Should serialize");
        assert!(json.contains("signature_generated"));
        assert!(json.contains("agent-123"));
        assert!(json.contains("merchant.example.com"));
    }

    #[test]
    fn test_redact_multiple_credit_cards() {
        let input = "Cards: 1234-5678-9012-3456 and 9876-5432-1098-7654";
        let result = redact_sensitive(input);

        assert!(result.contains("XXXX-XXXX-XXXX-XXXX"));
        assert!(!result.contains("1234-5678-9012-3456"));
        assert!(!result.contains("9876-5432-1098-7654"));
    }

    #[test]
    fn test_redact_cvv_no_space() {
        let inputs = [("cvv:123", "cvv: XXX"), ("CVV:456", "CVV: XXX"), ("cvc=789", "cvc: XXX")];

        for (input, _expected) in &inputs {
            let result = redact_sensitive(input);
            assert!(!result.contains("123"), "CVV not redacted in: {result}");
            assert!(!result.contains("456"), "CVV not redacted in: {result}");
            assert!(!result.contains("789"), "CVV not redacted in: {result}");
        }
    }

    #[test]
    fn test_redact_sensitive_preserves_safe_data() {
        let input = "Order ID: 12345, Amount: $67.89, Date: 2024-01-15";
        let result = redact_sensitive(input);

        // Safe data should be unchanged
        assert!(result.contains("Order ID: 12345"));
        assert!(result.contains("Amount: $67.89"));
        assert!(result.contains("Date: 2024-01-15"));
    }

    #[test]
    fn test_redact_credit_card_without_separators() {
        let input = "Card number: 1234567890123456";
        let result = redact_sensitive(input);

        assert!(result.contains("XXXX-XXXX-XXXX-XXXX"));
        assert!(!result.contains("1234567890123456"));
    }

    #[test]
    fn test_redact_credit_card_with_spaces() {
        let input = "Card: 1234 5678 9012 3456";
        let result = redact_sensitive(input);

        assert!(result.contains("XXXX-XXXX-XXXX-XXXX"));
        assert!(!result.contains("1234 5678 9012 3456"));
    }

    #[test]
    fn test_redact_consumer_id_edge_cases() {
        // Very short IDs (length <=4, returned unchanged)
        assert_eq!(redact_consumer_id(""), "");
        assert_eq!(redact_consumer_id("a"), "a");
        assert_eq!(redact_consumer_id("ab"), "ab");
        assert_eq!(redact_consumer_id("abc"), "abc");
        assert_eq!(redact_consumer_id("abcd"), "abcd");

        // ID longer than 4 characters (no dash)
        // For "abcde" (5 chars): show last 4, redact 1 => "*bcde"
        assert_eq!(redact_consumer_id("abcde"), "*bcde");

        // Longer ID with no dash
        // For "1234567890" (10 chars): show last 4, redact 6 => "******7890"
        assert_eq!(redact_consumer_id("1234567890"), "******7890");

        // ID with dash - keeps prefix
        // For "user-1234567890": keeps "user-", redacts middle, shows last 4
        assert_eq!(redact_consumer_id("user-1234567890"), "user-******7890");

        // ID with multiple dashes - only keeps first prefix
        // For "user-org-12345" (14 chars): keeps "user-" (5 chars), redacts 5 chars, shows last 4
        assert_eq!(redact_consumer_id("user-org-12345"), "user-*****2345");
    }

    #[test]
    fn test_redact_sensitive_empty_string() {
        let result = redact_sensitive("");
        assert_eq!(result, "");
    }

    #[test]
    fn test_redact_sensitive_with_multiple_patterns() {
        let input = "Payment failed: card 1234-5678-9012-3456, CVV: 123, SSN: 987-65-4321";
        let result = redact_sensitive(input);

        // All sensitive data should be redacted
        assert!(result.contains("XXXX-XXXX-XXXX-XXXX"));
        assert!(result.contains("XXX-XX-XXXX"));
        assert!(!result.contains("1234-5678-9012-3456"));
        assert!(!result.contains("123"));
        assert!(!result.contains("987-65-4321"));
    }

    #[test]
    fn test_audit_event_with_very_long_error() {
        let request_id = Uuid::new_v4();
        let long_error = format!(
            "Error: Transaction failed with card {} and CVV {} due to {}",
            "1234-5678-9012-3456", "456", "network timeout after 30 seconds"
        );

        let event = AuditEvent::new(AuditEventType::CheckoutFailed, "agent-test", request_id)
            .with_error(&long_error);

        let error = event.details.error.expect("Error should be set");
        assert!(error.contains("XXXX-XXXX-XXXX-XXXX"), "Card should be redacted");
        assert!(!error.contains("1234-5678-9012-3456"), "Original card should be gone");
        assert!(error.contains("network timeout"), "Safe parts should remain");
    }
}
