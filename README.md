# TAP-MCP Bridge

[![Crates.io](https://img.shields.io/crates/v/tap-mcp-bridge)](https://crates.io/crates/tap-mcp-bridge)
[![docs.rs](https://img.shields.io/docsrs/tap-mcp-bridge)](https://docs.rs/tap-mcp-bridge)
[![CI](https://img.shields.io/github/actions/workflow/status/bug-ops/tap-mcp-bridge/ci.yml?branch=master)](https://github.com/bug-ops/tap-mcp-bridge/actions)
[![License](https://img.shields.io/crates/l/tap-mcp-bridge)](LICENSE)

Rust library and MCP server for Visa's Trusted Agent Protocol (TAP), enabling AI agents to securely authenticate with merchants and execute payment transactions.

## Workspace Structure

```text
tap-mcp-bridge/
├── tap-mcp-bridge/    # Library crate - TAP protocol implementation
└── tap-mcp-server/    # Binary crate - MCP server for AI agents
```

| Crate | Type | Description |
|-------|------|-------------|
| [`tap-mcp-bridge`](tap-mcp-bridge/) | Library | RFC 9421 signatures, JWE encryption, TAP protocol |
| [`tap-mcp-server`](tap-mcp-server/) | Binary | MCP server exposing TAP tools for Claude and other AI agents |

## Installation

### As a Library

```toml
[dependencies]
tap-mcp-bridge = "0.1"
```

### As MCP Server

```bash
cargo install --path tap-mcp-server
```

Configure your MCP client:

```json
{
  "mcpServers": {
    "tap": {
      "command": "tap-mcp-server",
      "env": {
        "TAP_AGENT_ID": "your-agent-id",
        "TAP_AGENT_DIRECTORY": "https://your-agent-directory.com",
        "TAP_SIGNING_KEY": "64-hex-characters-ed25519-key"
      }
    }
  }
}
```

> [!IMPORTANT]
> Requires Rust 1.85+ (Edition 2024).

## Quick Example

```rust
use ed25519_dalek::SigningKey;
use tap_mcp_bridge::tap::TapSigner;

let signing_key = SigningKey::from_bytes(&[0u8; 32]);
let signer = TapSigner::new(signing_key, "agent-123", "https://agent.example.com");

let signature = signer.sign_request(
    "POST",
    "merchant.example.com",
    "/checkout",
    b"request body",
    tap_mcp_bridge::tap::InteractionType::Checkout,
);
```

## MCP Tools

The server exposes three tools:

| Tool | Description |
|------|-------------|
| `checkout_with_tap` | Execute payment with TAP authentication |
| `browse_merchant` | Browse merchant catalog with verified identity |
| `verify_agent_identity` | Health check and agent verification |

## Features

- **RFC 9421** HTTP Message Signatures with Ed25519
- **RFC 7516** JWE encryption for payment data (A256GCM + RSA-OAEP-256)
- **RFC 7638** JWK Thumbprints for key identification
- **ID Tokens** (JWT) for consumer authentication
- **ACRO** - Agentic Consumer Recognition Object
- **APC** - Agentic Payment Container with JWE
- **Replay protection** via UUID v4 nonce and LRU cache

## Documentation

| Resource | Description |
|----------|-------------|
| [API Reference](https://docs.rs/tap-mcp-bridge) | Complete API documentation |
| [TAP Specification](docs/TAP_SPECIFICATION.md) | Protocol implementation details |
| [MCP Integration](docs/MCP_INTEGRATION.md) | MCP server configuration |
| [Observability](docs/OBSERVABILITY.md) | Logging and health checks |
| [Examples](tap-mcp-bridge/examples/) | Runnable code examples |

## Examples

```bash
cargo run --example basic_checkout
cargo run --example apc_generation
cargo run --example signature_generation
```

## Development

```bash
# Quick verification
cargo make pre-commit

# Full test suite
cargo nextest run --all-features

# Documentation
cargo doc --no-deps --open
```

## License

Licensed under MIT OR Apache-2.0 at your option.

## Resources

- [TAP Protocol](https://developer.visa.com/capabilities/trusted-agent-protocol/) - Official Visa documentation
- [MCP Protocol](https://modelcontextprotocol.io/) - Anthropic's Model Context Protocol
- [RFC 9421](https://www.rfc-editor.org/rfc/rfc9421.html) - HTTP Message Signatures
