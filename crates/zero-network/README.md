# zero-network

GRID network client trait, in-memory mock broker, and outbox retry pump for
the zero-sdk.

## API-Name Mapping Table

The SDK defines its own trait surface. The table below documents how each SDK
name maps to the upstream `the-grid` crate. Entries marked **N/A (identical)**
use the exact same name in both SDK and upstream.

| SDK name | GRID upstream name | Notes |
|---|---|---|
| `GridClient` (trait) | `GridClient` | N/A (identical) |
| `GridClient::publish` | `GridClient::publish` | N/A (identical) -- publishes raw sector bytes to a topic |
| `GridClient::subscribe` | `GridClient::subscribe` | N/A (identical) -- returns `Stream` of sector bytes |
| `GridClient::unsubscribe` | `GridClient::unsubscribe` | N/A (identical) |
| `RealGridClient` | `GridClient` (concrete) | SDK wraps upstream concrete client |
| `RealGridClient::connect` | `GridClient::connect` | N/A (identical) -- async, returns `Self` |
| `SectorBytes` (`Vec<u8>`) | raw bytes | SDK type alias; upstream uses raw `Vec<u8>` |
| `NetworkError` | `the_grid::Error` | SDK maps upstream errors via `NetworkError::Other` |

> **Note:** The upstream `the-grid` git dependency is not yet pinned
> (`Cargo.toml` has the line commented out). Once the exact commit SHA is
> confirmed, `RealGridClient` methods will delegate to the upstream instead of
> returning `NetworkError::Other`. Any new name mismatches discovered at pin
> time will be bridged with `type Alias = grid::RealName;` in `real.rs` and
> documented here.

## Usage

```rust
use zero_network::{RealGridClient, GridClient};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = RealGridClient::connect("/ip4/0.0.0.0/udp/3690/quic-v1").await?;
    // client.publish("my.topic", sector_bytes).await?;
    Ok(())
}
```

## License

MIT OR Apache-2.0
