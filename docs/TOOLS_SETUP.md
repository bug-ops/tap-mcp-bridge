# Development Tools Setup

This document provides installation instructions for all quality assurance tools used in tap-mcp-bridge.

## Automatic Toolchain Setup

The project uses a nightly Rust toolchain, which is automatically configured via `rust-toolchain.toml`. When you first run any cargo command in this directory, rustup will automatically:

- Install the nightly toolchain
- Install required components (rustfmt, clippy, rust-src, rust-analyzer, miri)

No manual toolchain configuration is needed.

## Required Development Tools

Install these tools for complete development workflow:

### 1. cargo-nextest (Fast Test Runner)

```bash
cargo install cargo-nextest
```

**Why:** Significantly faster test execution with better output formatting.

**Usage:**
```bash
cargo nextest run
```

### 2. cargo-audit (Security Auditing)

```bash
cargo install cargo-audit
```

**Why:** Checks dependencies against the RustSec Advisory Database for known security vulnerabilities.

**Usage:**
```bash
cargo audit
cargo audit --deny warnings  # Fail on any vulnerability
```

### 3. cargo-deny (License and Dependency Checker)

```bash
cargo install cargo-deny
```

**Why:** Enforces license policies, detects duplicate dependencies, and validates dependency sources.

**Usage:**
```bash
cargo deny check
cargo deny check licenses  # Check license compliance only
cargo deny check advisories  # Check security advisories only
```

### 4. cargo-udeps (Unused Dependency Checker)

```bash
cargo install cargo-udeps
```

**Why:** Identifies dependencies declared in Cargo.toml but not actually used in the code.

**Usage:**
```bash
cargo +nightly udeps --all-targets
```

Note: Requires nightly toolchain (already configured).

### 5. cargo-hack (Feature Combination Validator)

```bash
cargo install cargo-hack
```

**Why:** Tests all possible feature flag combinations to ensure each combination compiles.

**Usage:**
```bash
cargo hack check --feature-powerset
cargo hack check --feature-powerset --no-dev-deps
```

### 6. cargo-make (Task Runner - Optional but Recommended)

```bash
cargo install cargo-make
```

**Why:** Provides convenient task definitions for common workflows.

**Usage:**
```bash
cargo make verify       # Run standard verification
cargo make verify-all   # Run complete verification
cargo make pre-commit   # Pre-commit checks
cargo make ci           # Simulate CI pipeline
```

See `Makefile.toml` for all available tasks.

## Verification Script

An alternative to cargo-make is the provided shell script:

```bash
./scripts/verify.sh
```

This runs the core verification suite without requiring cargo-make.

## Quick Setup

Install all recommended tools at once:

```bash
cargo install cargo-nextest cargo-audit cargo-deny cargo-udeps cargo-hack cargo-make
```

This may take several minutes as each tool compiles from source.

## Verification After Setup

Test that everything is working:

```bash
# Check toolchain
rustc --version  # Should show nightly

# Check tools
cargo nextest --version
cargo audit --version
cargo deny --version
cargo +nightly udeps --version
cargo hack --version
cargo make --version  # If installed

# Run verification
cargo make verify
# or
./scripts/verify.sh
```

## IDE Setup

### VS Code

Install the `rust-analyzer` extension. The project's `rust-toolchain.toml` will automatically configure it to use the nightly toolchain.

Recommended settings (`.vscode/settings.json`):

```json
{
  "rust-analyzer.check.command": "clippy",
  "rust-analyzer.check.extraArgs": ["--all-targets", "--all-features"],
  "editor.formatOnSave": true,
  "[rust]": {
    "editor.defaultFormatter": "rust-lang.rust-analyzer"
  }
}
```

### IntelliJ IDEA / CLion

1. Install the Rust plugin
2. The nightly toolchain will be detected automatically from `rust-toolchain.toml`
3. Enable rustfmt on save in Settings → Languages & Frameworks → Rust → Rustfmt

## CI/CD Integration

For GitHub Actions, use:

```yaml
- name: Install Rust toolchain
  uses: dtolnay/rust-toolchain@nightly
  with:
    components: rustfmt, clippy

- name: Install cargo tools
  run: |
    cargo install cargo-nextest cargo-audit cargo-deny cargo-udeps cargo-hack

- name: Run verification
  run: |
    cargo fmt --check
    cargo clippy --all-targets --all-features -- -D warnings
    cargo nextest run --all-features
    cargo audit --deny warnings
    cargo deny check
    cargo +nightly udeps --all-targets
    cargo hack check --feature-powerset
```

## Troubleshooting

### "rustfmt not found" or "clippy not found"

```bash
rustup component add rustfmt clippy --toolchain nightly
```

### "miri not found"

```bash
rustup component add miri --toolchain nightly
```

### cargo-udeps fails

Ensure you're using the nightly toolchain:
```bash
cargo +nightly udeps --all-targets
```

### Tools installed but not in PATH

Cargo installs binaries to `~/.cargo/bin`. Ensure this is in your PATH:

```bash
export PATH="$HOME/.cargo/bin:$PATH"
```

Add this to your shell profile (.bashrc, .zshrc, etc.).

## Tool Update

Keep tools up to date:

```bash
# Update Rust toolchain
rustup update nightly

# Update cargo tools
cargo install cargo-nextest cargo-audit cargo-deny cargo-udeps cargo-hack cargo-make --force
```

## Minimum Versions

These tools have been tested with:
- Rust nightly-2025-11-09 or later
- cargo-nextest 0.9+
- cargo-audit 0.20+
- cargo-deny 0.14+
- cargo-udeps 0.1+
- cargo-hack 0.6+
- cargo-make 0.37+ (optional)

## Summary

**Essential tools:**
```bash
cargo install cargo-nextest cargo-audit cargo-deny cargo-udeps cargo-hack
```

**Quick verification:**
```bash
./scripts/verify.sh
```

**Full verification:**
```bash
cargo make verify-all  # If cargo-make installed
```

All tools support the Microsoft Rust Guidelines for comprehensive code quality checking.
