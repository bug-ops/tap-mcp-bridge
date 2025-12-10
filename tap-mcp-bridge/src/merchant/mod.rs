//! Merchant API abstraction layer.
//!
//! This module provides flexible integration with different merchant APIs through
//! a trait-based abstraction system.

pub mod config;
pub mod default;
pub mod endpoint;
pub mod field_map;
pub mod traits;
pub mod transform;

pub use config::{AuthConfig, EndpointConfig, FieldMappingConfig, MerchantConfig, PaginationStyle};
pub use default::DefaultMerchant;
pub use endpoint::{ConfigurableEndpointResolver, DefaultEndpointResolver};
pub use field_map::{ConfigurableFieldMapper, IdentityFieldMapper};
pub use traits::{
    EndpointResolver, FieldMapper, MerchantApi, RequestTransformer, ResponseTransformer,
};
pub use transform::Operation;
