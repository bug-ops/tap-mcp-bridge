# Development Guide for tap-mcp-bridge

This document outlines the development workflow, tooling, and quality standards for the tap-mcp-bridge project.

## Toolchain Requirements

This project uses the **nightly** Rust toolchain with the following components:

- `rustfmt` - Code formatting
- `clippy` - Linting
- `rust-src` - Source code for standard library
- `rust-analyzer` - IDE support
- `miri` - Unsafe code validation

The toolchain is automatically configured via `rust-toolchain.toml`.

## Required Tools

Install the following tools for complete development workflow:

```bash
# Core testing framework (faster than cargo test)
cargo install cargo-nextest

# Security audit tool
cargo install cargo-audit

# License and dependency checker
cargo install cargo-deny

# Unused dependency checker
cargo install cargo-udeps

# Feature combination validator
cargo install cargo-hack

# Task runner (optional but recommended)
cargo install cargo-make
```

## Code Quality Standards

This project follows the [Microsoft Rust Guidelines](https://microsoft.github.io/rust-guidelines/) with strict quality enforcement:

### Linting

All code must pass clippy with the following enabled:
- All standard lint categories (cargo, complexity, correctness, pedantic, perf, style, suspicious)
- Restriction lints for enhanced safety
- `-D warnings` (all warnings treated as errors)

### Formatting

Code must be formatted with `rustfmt` using the configuration in `rustfmt.toml`:
- Edition 2024 features
- 100 character line width
- Standardized import grouping
- Comment normalization

### Documentation

All public APIs must have documentation:
- Summary line describing purpose
- Examples showing usage
- Error conditions documented
- Panics documented (avoid panics!)

### Testing

Every public function requires tests:
- Happy path tests
- Error case coverage
- Edge case handling
- Use `#[cfg(test)]` modules in the same file

## Development Workflow

### Daily Commands

```bash
# Format code
cargo fmt

# Check compilation
cargo check

# Run clippy
cargo clippy --all-targets --all-features -- -D warnings

# Run tests (with nextest)
cargo nextest run --all-features

# Or standard test
cargo test --all-features

# Build documentation
cargo doc --all-features --no-deps --open
```

### Using cargo-make (Recommended)

```bash
# Format code
cargo make format

# Run full verification
cargo make verify

# Run complete verification (includes udeps, hack)
cargo make verify-all

# Pre-commit checks
cargo make pre-commit

# Simulate CI pipeline
cargo make ci
```

### Using Verification Script

```bash
# Basic verification
./scripts/verify.sh

# With unused dependency check
CHECK_UDEPS=1 ./scripts/verify.sh
```

### Cargo Aliases

The project provides convenient aliases in `.cargo/config.toml`:

```bash
# All checks with deny warnings
cargo check-all

# Format check without modifying
cargo fmt-check

# Run all tests
cargo test-all

# Audit dependencies
cargo audit

# Check unused dependencies
cargo udeps

# Feature powerset validation
cargo hack-check

# Run miri tests
cargo miri-test

# Full verification suite
cargo verify
```

## Pre-Commit Checklist

Before committing code, ensure:

- [ ] Code is formatted: `cargo fmt`
- [ ] Clippy passes: `cargo clippy --all-targets --all-features -- -D warnings`
- [ ] Tests pass: `cargo nextest run` or `cargo test`
- [ ] Documentation builds: `cargo doc --no-deps`
- [ ] No unused dependencies: `cargo udeps` (if changed deps)
- [ ] Security audit passes: `cargo audit`

Or simply run:
```bash
cargo make pre-commit
```

## Continuous Integration

The CI pipeline should run:

1. Format check: `cargo fmt --check`
2. Clippy: `cargo clippy -- -D warnings`
3. Tests: `cargo test --all-features`
4. Security audit: `cargo audit --deny warnings`
5. Documentation: `cargo doc --all-features --no-deps`
6. Unused deps: `cargo udeps`
7. Feature validation: `cargo hack check --feature-powerset`

## Error Handling Guidelines

### Use `thiserror` for library errors:

```rust
use thiserror::Error;

#[derive(Error, Debug)]
pub enum BridgeError {
    #[error("connection failed: {0}")]
    ConnectionFailed(String),

    #[error("invalid protocol version: {0}")]
    InvalidProtocol(u32),
}

pub type Result<T> = std::result::Result<T, BridgeError>;
```

### Never use `unwrap()` or `panic!()` in library code

Instead, return `Result<T, E>` and let callers handle errors.

## Ownership Patterns

Prefer this order:
1. Immutable borrow `&T` - for reading
2. Mutable borrow `&mut T` - for modification
3. Owned value `T` - for ownership transfer
4. Clone `.clone()` - last resort (document why)

## Documentation Standards

Every public item needs doc comments:

```rust
/// Creates a new bridge connection.
///
/// Establishes a bidirectional communication channel between TAP and MCP
/// using the provided configuration.
///
/// # Errors
///
/// Returns `BridgeError::ConnectionFailed` if the connection cannot be established.
///
/// # Examples
///
/// ```
/// use tap_mcp_bridge::{Bridge, Config};
///
/// let config = Config::default();
/// let bridge = Bridge::new(config)?;
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub fn new(config: Config) -> Result<Self> {
    // implementation
}
```

## Performance Considerations

- Pre-allocate collections with known capacity
- Use iterators over explicit loops
- Choose appropriate collection types
- Profile with `cargo bench` (profile.bench has debug=1 for symbols)

## Unsafe Code

If unsafe code is necessary:
- Document with `# Safety` section
- Use `unsafe_op_in_unsafe_fn` lint
- Validate with `cargo miri test`
- Every unsafe block must have a comment explaining why it's safe

## License Compliance

The project uses dual licensing: MIT OR Apache-2.0

Ensure all dependencies comply with allowed licenses (see `deny.toml`).

## Getting Help

- Check the [Microsoft Rust Guidelines](https://microsoft.github.io/rust-guidelines/)
- Review existing code for patterns
- Run verification tools for immediate feedback
- Documentation: `cargo doc --open`

## Summary

**Before every commit:**
```bash
cargo make pre-commit
```

**For complete verification:**
```bash
cargo make verify-all
```

The goal is to maintain high code quality, safety, and consistency throughout the project lifecycle.
