# Contributing to TAP-MCP Bridge

Thank you for your interest in contributing to TAP-MCP Bridge! We welcome contributions from the community to help make this project better.

## Development Philosophy

This project follows the **[Microsoft Rust Guidelines](https://microsoft.github.io/rust-guidelines/)** for soundness and idiomatic design.

**Key Principles:**

- **Compact solutions**: Implement minimal functionality to validate hypotheses.
- **No convenience features**: Avoid syntactic sugar or "nice-to-have" additions without a clear use case.
- **Hypothesis-driven**: Every feature must directly test a core assumption.
- **Soundness**: Unsafe code is strictly regulated and must be justified.

## Prerequisites

- **Rust** 1.85+ (Edition 2024)
- **Cargo**
- **Optional**: `cargo-make`, `cargo-nextest`, `cargo-deny`

## Setup

1. **Clone the repository:**

    ```bash
    git clone https://github.com/bug-ops/tap-mcp-bridge.git
    cd tap-mcp-bridge
    ```

2. **Install development tools (recommended):**

    ```bash
    cargo install cargo-make cargo-nextest cargo-deny cargo-udeps
    ```

## Common Commands

We use `cargo-make` for common tasks. If you don't have it installed, you can use the direct cargo commands listed in `README.md`.

- **Pre-commit checks** (format, clippy, test, deny):

    ```bash
    cargo make pre-commit
    ```

- **Full verification**:

    ```bash
    cargo make verify
    ```

- **Run tests**:

    ```bash
    cargo make test
    ```

- **Format code**:

    ```bash
    cargo make format
    ```

## Pull Request Process

1. **Create a feature branch** from `master`.
2. **Implement your changes** with tests.
3. **Run pre-commit checks**: `cargo make pre-commit`.
4. **Open a Pull Request** with a clear description of your changes and the problem they solve.
5. **Ensure all CI checks pass**.

## Code Quality Standards

- **No unsafe code** unless absolutely necessary and justified.
- **Strong types** over primitives.
- **Comprehensive error handling** using `thiserror`.
- **Zero warnings**: We enforce strict clippy lints.
- **Documentation**: All public APIs must be documented with examples.

## License

By contributing, you agree that your contributions will be licensed under the project's [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE) license.
