# Spec 015 — `merchant` Subsystem: Merchant API Abstraction and TOML Configuration

**Status**: Documented (as-built)
**Priority**: N/A (subsystem documentation, not a fix)
**Type**: Subsystem specification — documents existing behavior
**Owner**: N/A
**Discovered**: Authored during specs migration cycle, 2026-08-08, closing the
subsystem-coverage gap against `.claude/rules/continuous-improvement.md` §
Project Subsystems
**Source**: `tap-mcp-bridge/src/merchant/{mod,traits,default,config,endpoint,field_map,transform,subscription_config,subscription_traits}.rs`,
`tap-mcp-bridge/examples/merchants/*.toml`

> [!note]
> Describes existing, tested code — including the extensive input-validation
> surface added in response to prior findings (issues #150, #143).

## 1. Overview

### Problem Statement

Merchants expose different REST conventions — endpoint paths, field names,
pagination styles, auth schemes. The bridge cannot hardcode one merchant's
shape. The `merchant` module provides a trait-based abstraction
(`MerchantApi` + `EndpointResolver` + `FieldMapper` + optional
`RequestTransformer`/`ResponseTransformer`) so a merchant integration is
expressed as data (a TOML file) rather than new Rust code, with
`DefaultMerchant` as the out-of-box implementation for standard-TAP-shaped
merchants.

### Goal

A merchant integrator can describe their API surface entirely in a TOML file
(base URL, endpoint templates, field-name mappings, pagination style, auth)
and have `DefaultMerchant::from_toml` (or `::from_file`) produce a working
`MerchantApi` implementation, validated against injection and SSRF-adjacent
attack patterns before use.

### Out of Scope

- The subscription-specific mirror types (`SubscriptionMerchantConfig`, etc.)
  are documented at the type level here but their business logic
  (proration, pricing) is covered in [[014-mcp-tool-surface]]
- Actual HTTP transport — that's [[016-transport-layer]]

## 2. Data Model

| Entity | Description | Key Attributes |
|--------|-------------|-----------------|
| `MerchantApi` (trait) | Central abstraction every merchant integration implements | associated types `ProductCatalog`, `Product`, `CartState`, `Order`, `PaymentResult`; methods `endpoint_resolver()`, `field_mapper()`, optional `request_transformer()`/`response_transformer()`, `to_standard_*` conversions |
| `EndpointResolver` (trait) | Maps logical operations to concrete paths | `products_endpoint`, `product_endpoint`, `cart_endpoint`, `add_to_cart_endpoint`, `update_cart_item_endpoint`, `remove_cart_item_endpoint`, `create_order_endpoint`, `order_endpoint`, `checkout_endpoint` |
| `FieldMapper` (trait) | Maps standard field names to merchant-specific ones | `map_request_field`, `map_response_field`, `has_custom_mappings` |
| `MerchantConfig` | Deserialized TOML root | `name, base_url, api_prefix, endpoints, field_mappings, auth: Option<AuthConfig>, pagination` |
| `AuthConfig` | Tagged enum for auth scheme | `ApiKey{header,env_var} \| Bearer{env_var} \| OAuth2{token_url,client_id_env,client_secret_env}` |
| `PaginationStyle` | Tagged enum | `PageBased (default) \| OffsetBased \| CursorBased` |
| `DefaultMerchant` | Standard-TAP `MerchantApi` implementation | `config: MerchantConfig`, `endpoint_resolver: ConfigurableEndpointResolver`, `field_mapper: ConfigurableFieldMapper` |

## 3. Functional Requirements

| ID | Requirement | Priority |
|----|------------|----------|
| FR-1 | WHEN `DefaultMerchant::from_toml` or `::from_file` loads a config THE SYSTEM SHALL call `MerchantConfig::validate()` before returning a usable instance | must |
| FR-2 | WHEN `base_url` or an OAuth2 `token_url` is validated THE SYSTEM SHALL require HTTPS and SHALL reject loopback hosts (`localhost`, `127.0.0.0/8`, `::1`, IPv4-mapped IPv6 loopback), unspecified addresses (`0.0.0.0`, `::`), userinfo in the URL, and port `0` | must |
| FR-3 | WHEN an endpoint template is validated THE SYSTEM SHALL reject templates containing `..`, `//`, not starting with `/`, or containing NUL/`?`/`#`/whitespace | must |
| FR-4 | WHEN a field-mapping name is validated THE SYSTEM SHALL reject empty names, prototype-pollution-shaped names (`__proto__`, `constructor`, `prototype`, `__defineGetter__`, case-insensitively), NUL bytes, and SQL-injection-shaped patterns (`'; drop`, `-- `, `/*`, `*/`) | must |
| FR-5 | WHEN an auth config env-var name is validated THE SYSTEM SHALL require it start with a letter or underscore and contain only alphanumerics/underscores thereafter; header names SHALL be restricted to the RFC 7230 token subset (alphanumeric, `-`, `_`) | must |
| FR-6 | WHEN a `MerchantApi` implementor's methods run THE SYSTEM SHALL convert between the merchant's native response shape and the standard wire types defined in [[014-mcp-tool-surface]] via `to_standard_*` methods | must |

## 4. Non-Functional Requirements

| ID | Category | Requirement |
|----|----------|-------------|
| NFR-1 | Security | Validation is exhaustive enough to have a dedicated "Regression tests for issue #150" block in `config.rs` covering unspecified-address, IPv4-mapped-loopback, userinfo, port-0, and path-traversal edge cases together |
| NFR-2 | Extensibility | Adding a new merchant integration requires only a new TOML file (and, for non-standard field/pagination conventions, no Rust code at all) — `DefaultMerchant` is intended to cover the majority case |
| NFR-3 | Testability | `config.rs` alone carries roughly 50 inline tests; every other file in the module has its own `#[cfg(test)]` block |

## 5. Edge Cases and Error Handling

| Scenario | Expected Behavior |
|----------|--------------------|
| `base_url` points at `http://api.example.com` (no TLS) | Rejected by `validate_https_url` at load time — `MerchantConfigError` |
| `base_url` resolves to `0.0.0.0` or `::` | Rejected by `host_is_disallowed` (unspecified-address check) |
| Endpoint template is `/cart/../admin` | Rejected — traversal pattern |
| Field mapping maps `"total"` → `"__proto__"` | Rejected — prototype-pollution pattern, case-insensitive |
| Auth env-var name is `"9_TOKEN"` (starts with digit) | Rejected — must start with letter or underscore |
| A merchant's response omits a field the `FieldMapper` expects | Behavior is implementation-specific per `MerchantApi` impl; `DefaultMerchant`'s conversions are the reference behavior, not enforced generically by the trait |

## 6. Agent Boundaries

### Always (without asking)
- Run `MerchantConfig::validate()` (directly or via `from_toml`/`from_file`) before using any loaded config
- Keep new merchant TOML fixtures under `tap-mcp-bridge/examples/merchants/` in sync with schema changes (per `.claude/rules/branching.md`)

### Ask First
- Loosening any of the FR-2 through FR-5 validation rules — each corresponds to a specific historical finding (issue #150, #143)
- Adding a new `AuthConfig` variant or `PaginationStyle` variant — changes the TOML schema surface

### Never
- Skip `validate()` when loading merchant config from an untrusted or user-editable source
- Allow endpoint templates or field-mapping names sourced from config to be interpolated into requests without the FR-3/FR-4 checks

## 7. Open Questions

- `[NEEDS CLARIFICATION: is there a plan to support merchant config sources other than local TOML files (e.g. remote-fetched config), and if so, does the current validate()-on-load pattern need to move to validate-on-every-use?]`

## 8. See Also

- [[MOC-specs]] — all specifications
- [[004-id-fields-path-traversal]] — related path-traversal finding (in `mcp`, not `merchant`, but same defect class as FR-3)
- [[014-mcp-tool-surface]] — the standard wire types this module's `to_standard_*` conversions target
- `tap-mcp-bridge/examples/merchants/standard-tap.toml`, `acme-store.toml`, `shopify-style.toml` — reference configs
