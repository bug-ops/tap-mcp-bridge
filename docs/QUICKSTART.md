# Quick Start Guide

This guide will get you up and running with tap-mcp-bridge development in under 5 minutes.

## Prerequisites

- Rust toolchain installed (rustup)
- Git (for version control)

## Initial Setup

### 1. Toolchain Auto-Configuration

The nightly toolchain will be automatically installed when you first run any cargo command:

```bash
cd tap-mcp-bridge
cargo check
```

This automatically:
- Installs Rust nightly toolchain
- Installs rustfmt, clippy, rust-src, rust-analyzer, and miri
- Configures your IDE (VS Code, IntelliJ) to use nightly

### 2. Install Development Tools (Recommended)

Install all quality assurance tools in one command:

```bash
cargo install cargo-nextest cargo-audit cargo-deny cargo-udeps cargo-hack cargo-make
```

This takes 5-10 minutes as tools compile from source.

**Optional:** Skip this step and use the verification script instead.

## Daily Development Workflow

### Option A: Using cargo-make (Recommended)

```bash
# Format your code
cargo make format

# Run pre-commit checks (fast)
cargo make pre-commit

# Full verification
cargo make verify
```

### Option B: Using the Verification Script

```bash
# Run standard verification
./scripts/verify.sh

# With unused dependency check
CHECK_UDEPS=1 ./scripts/verify.sh
```

### Option C: Manual Commands

```bash
# Format code
cargo fmt

# Check lints
cargo clippy --all-targets --all-features -- -D warnings

# Run tests
cargo test  # or: cargo nextest run (if installed)
```

## Before Every Commit

Run this single command:

```bash
cargo make pre-commit
```

This ensures:
- Code is properly formatted
- All clippy lints pass
- All tests pass

## Project Structure

```
tap-mcp-bridge/
├── src/               # Source code
│   └── lib.rs         # Main library file
├── Cargo.toml         # Package manifest with strict lints
├── rust-toolchain.toml  # Nightly toolchain config
├── rustfmt.toml       # Formatting rules
├── clippy.toml        # Linting thresholds
└── scripts/
    └── verify.sh      # Verification script
```

## Code Quality Requirements

Every public function must:
- Have documentation comments (///)
- Include usage examples
- Have tests
- Pass clippy lints
- Handle errors with Result<T, E>

Example:

```rust
/// Adds two numbers together.
///
/// # Examples
///
/// ```
/// use tap_mcp_bridge::add;
///
/// let result = add(2, 2);
/// assert_eq!(result, 4);
/// ```
#[must_use]
pub fn add(left: u64, right: u64) -> u64 {
    left + right
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add() {
        assert_eq!(add(2, 2), 4);
    }
}
```

## Common Commands

```bash
# Check code without building
cargo check

# Build the project
cargo build

# Build optimized release
cargo build --release

# Run tests
cargo test

# Build documentation
cargo doc --open

# Security audit
cargo audit  # (if installed)

# Check for unused dependencies
cargo udeps  # (if installed)
```

## IDE Setup

### VS Code
1. Install "rust-analyzer" extension
2. Restart VS Code
3. Format on save is automatic

### IntelliJ IDEA / CLion
1. Install Rust plugin
2. Settings → Rust → Enable rustfmt on save
3. Done!

## Troubleshooting

### Clippy or rustfmt not found

```bash
rustup component add rustfmt clippy --toolchain nightly
```

### Tests failing

```bash
# Clean build and retry
cargo clean
cargo test
```

### Tools not in PATH

Add to ~/.bashrc or ~/.zshrc:

```bash
export PATH="$HOME/.cargo/bin:$PATH"
```

Then restart your terminal.

## What's Next?

1. Read `DEVELOPMENT.md` for detailed development practices
2. Review `TOOLS_SETUP.md` for tool documentation
3. Check `CONFIG_SUMMARY.md` to understand all configuration files
4. Start coding!

## Verification Checklist

Before pushing code:

- [ ] `cargo fmt` - Code formatted
- [ ] `cargo clippy -- -D warnings` - No lint warnings
- [ ] `cargo test` - All tests pass
- [ ] Documentation added for public APIs
- [ ] Tests added for new functions

Or simply:

```bash
cargo make pre-commit
```

## Getting Help

- Microsoft Rust Guidelines: https://microsoft.github.io/rust-guidelines/
- Project documentation: `cargo doc --open`
- Clippy lint list: https://rust-lang.github.io/rust-clippy/

## Summary

**Minimal workflow:**

1. `cargo check` (first time - installs toolchain)
2. Write code
3. `cargo make pre-commit` (before commit)
4. Commit and push

That's it! You're ready to develop high-quality Rust code following Microsoft guidelines.
