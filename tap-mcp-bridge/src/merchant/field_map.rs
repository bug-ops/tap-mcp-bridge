//! Field mapping implementations.
//!
//! This module provides field mappers for translating between standard and merchant-specific
//! field names.

use std::{borrow::Cow, collections::HashMap};

use crate::merchant::{FieldMapper, FieldMappingConfig};

/// Identity field mapper (no transformation).
#[derive(Debug, Clone)]
pub struct IdentityFieldMapper;

impl Default for IdentityFieldMapper {
    fn default() -> Self {
        Self::new()
    }
}

impl IdentityFieldMapper {
    /// Creates a new identity field mapper.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl FieldMapper for IdentityFieldMapper {
    fn map_request_field<'a>(&self, standard_name: &'a str) -> Cow<'a, str> {
        Cow::Borrowed(standard_name)
    }

    fn map_response_field<'a>(&self, merchant_name: &'a str) -> Cow<'a, str> {
        Cow::Borrowed(merchant_name)
    }

    fn has_custom_mappings(&self) -> bool {
        false
    }
}

/// Configurable field mapper using merchant configuration.
#[derive(Debug, Clone, Default)]
pub struct ConfigurableFieldMapper {
    request_mappings: HashMap<String, String>,
    response_mappings: HashMap<String, String>,
}

impl ConfigurableFieldMapper {
    /// Creates a new configurable field mapper.
    #[must_use]
    pub fn new(config: &FieldMappingConfig) -> Self {
        Self {
            request_mappings: config.request.clone(),
            response_mappings: config.response.clone(),
        }
    }

    /// Returns true if this mapper has any custom mappings.
    #[must_use]
    pub fn has_mappings(&self) -> bool {
        !self.request_mappings.is_empty() || !self.response_mappings.is_empty()
    }
}

impl FieldMapper for ConfigurableFieldMapper {
    fn map_request_field<'a>(&self, standard_name: &'a str) -> Cow<'a, str> {
        self.request_mappings
            .get(standard_name)
            .map_or_else(|| Cow::Borrowed(standard_name), |s| Cow::Owned(s.clone()))
    }

    fn map_response_field<'a>(&self, merchant_name: &'a str) -> Cow<'a, str> {
        self.response_mappings
            .get(merchant_name)
            .map_or_else(|| Cow::Borrowed(merchant_name), |s| Cow::Owned(s.clone()))
    }

    fn has_custom_mappings(&self) -> bool {
        self.has_mappings()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identity_field_mapper() {
        let mapper = IdentityFieldMapper::new();
        assert_eq!(mapper.map_request_field("consumer_id"), "consumer_id");
        assert_eq!(mapper.map_request_field("product_id"), "product_id");
        assert_eq!(mapper.map_response_field("consumer_id"), "consumer_id");
        assert!(!mapper.has_custom_mappings());
    }

    #[test]
    fn test_identity_field_mapper_default() {
        let mapper = <IdentityFieldMapper as Default>::default();
        assert_eq!(mapper.map_request_field("test"), "test");
    }

    #[test]
    fn test_configurable_field_mapper_empty() {
        let config = FieldMappingConfig::default();
        let mapper = ConfigurableFieldMapper::new(&config);

        assert_eq!(mapper.map_request_field("consumer_id"), "consumer_id");
        assert_eq!(mapper.map_response_field("product_id"), "product_id");
        assert!(!mapper.has_custom_mappings());
    }

    #[test]
    fn test_configurable_field_mapper_request_mapping() {
        let mut request_mappings = HashMap::new();
        request_mappings.insert("consumer_id".to_owned(), "customerId".to_owned());
        request_mappings.insert("product_id".to_owned(), "sku".to_owned());

        let config = FieldMappingConfig { request: request_mappings, response: HashMap::new() };

        let mapper = ConfigurableFieldMapper::new(&config);

        assert_eq!(mapper.map_request_field("consumer_id"), "customerId");
        assert_eq!(mapper.map_request_field("product_id"), "sku");
        assert_eq!(mapper.map_request_field("unmapped_field"), "unmapped_field");
        assert!(mapper.has_custom_mappings());
    }

    #[test]
    fn test_configurable_field_mapper_response_mapping() {
        let mut response_mappings = HashMap::new();
        response_mappings.insert("customerId".to_owned(), "consumer_id".to_owned());
        response_mappings.insert("sku".to_owned(), "product_id".to_owned());

        let config = FieldMappingConfig { request: HashMap::new(), response: response_mappings };

        let mapper = ConfigurableFieldMapper::new(&config);

        assert_eq!(mapper.map_response_field("customerId"), "consumer_id");
        assert_eq!(mapper.map_response_field("sku"), "product_id");
        assert_eq!(mapper.map_response_field("unmapped"), "unmapped");
        assert!(mapper.has_custom_mappings());
    }

    #[test]
    fn test_configurable_field_mapper_bidirectional() {
        let mut request_mappings = HashMap::new();
        request_mappings.insert("consumer_id".to_owned(), "customerId".to_owned());

        let mut response_mappings = HashMap::new();
        response_mappings.insert("customerId".to_owned(), "consumer_id".to_owned());

        let config = FieldMappingConfig { request: request_mappings, response: response_mappings };

        let mapper = ConfigurableFieldMapper::new(&config);

        // Request mapping: standard -> merchant
        assert_eq!(mapper.map_request_field("consumer_id"), "customerId");

        // Response mapping: merchant -> standard
        assert_eq!(mapper.map_response_field("customerId"), "consumer_id");
    }

    #[test]
    fn test_configurable_field_mapper_multiple_mappings() {
        let mut request_mappings = HashMap::new();
        request_mappings.insert("consumer_id".to_owned(), "customer_id".to_owned());
        request_mappings.insert("product_id".to_owned(), "item_id".to_owned());
        request_mappings.insert("cart_id".to_owned(), "basket_id".to_owned());

        let config = FieldMappingConfig { request: request_mappings, response: HashMap::new() };

        let mapper = ConfigurableFieldMapper::new(&config);

        assert_eq!(mapper.map_request_field("consumer_id"), "customer_id");
        assert_eq!(mapper.map_request_field("product_id"), "item_id");
        assert_eq!(mapper.map_request_field("cart_id"), "basket_id");
    }

    #[test]
    fn test_configurable_field_mapper_default() {
        let mapper = ConfigurableFieldMapper::default();
        assert!(!mapper.has_custom_mappings());
        assert_eq!(mapper.map_request_field("test"), "test");
    }

    #[test]
    fn test_has_mappings() {
        let mut request_mappings = HashMap::new();
        request_mappings.insert("test".to_owned(), "test_mapped".to_owned());

        let config = FieldMappingConfig { request: request_mappings, response: HashMap::new() };

        let mapper = ConfigurableFieldMapper::new(&config);
        assert!(mapper.has_mappings());
    }

    #[test]
    fn test_identity_mapper_with_empty_string() {
        let mapper = IdentityFieldMapper::new();
        assert_eq!(mapper.map_request_field(""), "");
        assert_eq!(mapper.map_response_field(""), "");
    }

    #[test]
    fn test_identity_mapper_with_unicode() {
        let mapper = IdentityFieldMapper::new();
        assert_eq!(mapper.map_request_field("用户_id"), "用户_id");
        assert_eq!(mapper.map_response_field("消费者_名称"), "消费者_名称");
    }

    #[test]
    fn test_configurable_mapper_with_empty_string_key() {
        let mut request_mappings = HashMap::new();
        request_mappings.insert(String::new(), "empty_key".to_owned());

        let config = FieldMappingConfig { request: request_mappings, response: HashMap::new() };

        let mapper = ConfigurableFieldMapper::new(&config);
        assert_eq!(mapper.map_request_field(""), "empty_key");
    }

    #[test]
    fn test_configurable_mapper_with_empty_string_value() {
        let mut request_mappings = HashMap::new();
        request_mappings.insert("field".to_owned(), String::new());

        let config = FieldMappingConfig { request: request_mappings, response: HashMap::new() };

        let mapper = ConfigurableFieldMapper::new(&config);
        assert_eq!(mapper.map_request_field("field"), "");
    }

    #[test]
    fn test_configurable_mapper_unicode_field_names() {
        let mut request_mappings = HashMap::new();
        request_mappings.insert("用户_id".to_owned(), "userId".to_owned());

        let mut response_mappings = HashMap::new();
        response_mappings.insert("userId".to_owned(), "用户_id".to_owned());

        let config = FieldMappingConfig { request: request_mappings, response: response_mappings };

        let mapper = ConfigurableFieldMapper::new(&config);
        assert_eq!(mapper.map_request_field("用户_id"), "userId");
        assert_eq!(mapper.map_response_field("userId"), "用户_id");
    }

    #[test]
    fn test_configurable_mapper_case_sensitivity() {
        let mut request_mappings = HashMap::new();
        request_mappings.insert("consumer_id".to_owned(), "customerId".to_owned());
        request_mappings.insert("Consumer_ID".to_owned(), "CUSTOMER_ID".to_owned());

        let config = FieldMappingConfig { request: request_mappings, response: HashMap::new() };

        let mapper = ConfigurableFieldMapper::new(&config);
        assert_eq!(mapper.map_request_field("consumer_id"), "customerId");
        assert_eq!(mapper.map_request_field("Consumer_ID"), "CUSTOMER_ID");
        assert_eq!(mapper.map_request_field("CONSUMER_ID"), "CONSUMER_ID");
    }

    #[test]
    fn test_configurable_mapper_special_characters() {
        let mut request_mappings = HashMap::new();
        request_mappings.insert("field-name".to_owned(), "field_name".to_owned());
        request_mappings.insert("field.name".to_owned(), "fieldName".to_owned());

        let config = FieldMappingConfig { request: request_mappings, response: HashMap::new() };

        let mapper = ConfigurableFieldMapper::new(&config);
        assert_eq!(mapper.map_request_field("field-name"), "field_name");
        assert_eq!(mapper.map_request_field("field.name"), "fieldName");
    }

    #[test]
    fn test_configurable_mapper_very_long_field_names() {
        let long_field = "a".repeat(1000);
        let long_mapped = "b".repeat(1000);

        let mut request_mappings = HashMap::new();
        request_mappings.insert(long_field.clone(), long_mapped.clone());

        let config = FieldMappingConfig { request: request_mappings, response: HashMap::new() };

        let mapper = ConfigurableFieldMapper::new(&config);
        assert_eq!(mapper.map_request_field(&long_field), long_mapped);
    }

    #[test]
    fn test_configurable_mapper_response_only_mappings() {
        let mut response_mappings = HashMap::new();
        response_mappings.insert("merchantField".to_owned(), "standard_field".to_owned());

        let config = FieldMappingConfig { request: HashMap::new(), response: response_mappings };

        let mapper = ConfigurableFieldMapper::new(&config);
        assert!(mapper.has_custom_mappings());
        assert_eq!(mapper.map_response_field("merchantField"), "standard_field");
        assert_eq!(mapper.map_request_field("any_field"), "any_field");
    }

    #[test]
    fn test_configurable_mapper_clone() {
        let mut request_mappings = HashMap::new();
        request_mappings.insert("test".to_owned(), "mapped".to_owned());

        let config = FieldMappingConfig { request: request_mappings, response: HashMap::new() };

        let mapper = ConfigurableFieldMapper::new(&config);
        let cloned = mapper.clone();

        assert_eq!(mapper.map_request_field("test"), cloned.map_request_field("test"));
    }

    #[test]
    fn test_identity_mapper_cow_borrowed() {
        use std::borrow::Cow;

        let mapper = IdentityFieldMapper::new();
        let result = mapper.map_request_field("test");

        // Verify it's actually borrowed
        assert!(matches!(result, Cow::Borrowed(_)), "expected Borrowed, got Owned");
    }

    #[test]
    fn test_configurable_mapper_cow_owned_when_mapped() {
        use std::borrow::Cow;

        let mut request_mappings = HashMap::new();
        request_mappings.insert("test".to_owned(), "mapped".to_owned());

        let config = FieldMappingConfig { request: request_mappings, response: HashMap::new() };

        let mapper = ConfigurableFieldMapper::new(&config);
        let result = mapper.map_request_field("test");

        // Verify it's actually owned when mapped
        assert!(matches!(result, Cow::Owned(_)), "expected Owned, got Borrowed");
    }

    #[test]
    fn test_configurable_mapper_cow_borrowed_when_not_mapped() {
        use std::borrow::Cow;

        let config = FieldMappingConfig::default();
        let mapper = ConfigurableFieldMapper::new(&config);
        let result = mapper.map_request_field("unmapped");

        // Verify it's borrowed when not mapped
        assert!(matches!(result, Cow::Borrowed(_)), "expected Borrowed, got Owned");
    }
}
