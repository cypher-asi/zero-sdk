# zero-sdk

End-to-end encrypted messaging SDK built on post-quantum hybrid
cryptography. The workspace provides identity management, hybrid
HPKE (X25519 + ML-KEM-768), persistent storage, a relay network
layer with automatic retry, and high-level DM / group / inbox
services exposed through a single `ZeroSdk` facade.

## Minimum Supported Rust Version (MSRV)

**1.78** -- enforced by `rust-version` in the workspace `Cargo.toml`.

## Workspace Layout

```
crates/
  zero-identity/    Core identity primitives: NeuralKey, MachineKey,
                    deterministic key derivation via HKDF + BLAKE3.
  zero-crypto/      Hybrid HPKE-PQ encryption (X25519 + ML-KEM-768 +
                    ChaCha20-Poly1305), dual-signing (Ed25519 + ML-DSA-65),
                    deterministic CBOR AAD builder.
  zero-storage/     RocksDB wrapper (ZeroDb) with column-family management,
                    sector model, and batch writes.
  zero-network/     GridClient trait, real and mock implementations,
                    InMemoryGridBroker for testing, RetryPump with
                    exponential backoff (500ms x2, max 5, cap 30s, jitter).
  zero-messaging/   High-level messaging layer:
                      contacts/  -- ContactStore (CRUD over RocksDB)
                      dm/        -- DmService: send, receive, status tracking
                      group/     -- GroupService: create, join, permissions
                      inbox/     -- InboxService: conversation index, unread
                                    counts, 140-char previews
  zero-sdk/         Top-level facade. SdkBuilder wires all services into a
                    single ZeroSdk entry point for downstream consumers.
```

## Quick Start

```rust
use zero_sdk::builder::SdkBuilder;
use zero_sdk::InMemoryGridBroker;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let broker = InMemoryGridBroker::new();

    let sdk = SdkBuilder::new()
        .db_path("/tmp/zero-alice")
        .build_mock(broker.clone())?;

    // List the inbox (empty initially)
    let conversations = sdk.inbox.list_conversations(None)?;
    println!("Conversations: {}", conversations.len());

    Ok(())
}
```

Build the entire workspace:

```sh
cargo build --workspace
```

Run all tests:

```sh
cargo test --workspace
```

Run clippy with deny-warnings:

```sh
cargo clippy --workspace -- -D warnings
```

Compile criterion benchmarks (without running):

```sh
cargo bench --workspace --no-run
```

## Performance Budgets

The following latency and memory budgets are enforced by criterion
benchmarks in `crates/zero-sdk/benches/sdk_bench.rs`. CI compiles
the bench binaries on every push; local runs verify P99 values.

| Path | Budget |
|------|--------|
| Inbox list, 1 000 conversations, warm cache | P99 < 5 ms |
| Inbox list, 1 000 conversations, cold (RocksDB warm) | P99 < 50 ms |
| DM send (encrypt + persist + publish on loopback) | P99 < 100 ms |
| DM receive (verify + decrypt + index update) | P99 < 50 ms |
| Steady-state SDK memory (excl. RocksDB block cache) | < 64 MB |

## Code Quality Gates

The following gates are enforced on every commit:

- `cargo fmt --check` -- consistent formatting via rustfmt
- `cargo clippy --workspace -- -D warnings` -- zero clippy warnings
- `cargo test --workspace` -- full test suite must pass
- `cargo bench --workspace --no-run` -- bench binaries must compile
- No `unsafe` code in any library crate
- No `anyhow` dependency in any library crate
- No `panic!` on any public API path (panics are test-only)

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or
  <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT License ([LICENSE-MIT](LICENSE-MIT) or
  <http://opensource.org/licenses/MIT>)

at your option.
