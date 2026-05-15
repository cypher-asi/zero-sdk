# zero-identity

`zero-identity` is the foundational layer of the `zero-sdk` workspace. It
wraps the upstream [`zid`](https://github.com/cypher-asi/zid) library and
exposes a focused, high-level surface for:

- generating and managing `NeuralKey`s (root identity keys),
- deriving HKDF-SHA256 subkeys per domain,
- splitting and recovering NeuralKeys via Shamir secret sharing,
- creating and listing per-device `MachineKey`s.

This crate is deliberately network-unaware: every operation is a local
key-management primitive. Higher-level networking concerns live in
sibling crates introduced in later phases.

## MSRV and toolchain

- Rust edition: **2021**
- MSRV: **1.78**
- `#![deny(warnings)]`, `#![forbid(unsafe_code)]`, clippy `pedantic` and
  `nursery` enabled at warn level.

## Upstream pin

The `zid` dependency is pinned to a specific commit on
`github.com/cypher-asi/zid` (the `main` commit at spec time, locked in
`Cargo.lock`). All cryptographic primitives in this crate ultimately
delegate to that revision; bumping the pin requires re-running this
crate's KAT and proptest suites.

## ZID API mapping

The table below maps every upstream `zid` symbol referenced inside
`crates/zero-identity/src` to its `zero-identity` counterpart. Even
identical names appear so CI can grep this file to assert that no ZID
symbol is silently used without an entry. One symbol per row.

| ZID upstream symbol | `zero-identity` counterpart | Rationale |
|---|---|---|
| `zid::CryptoError` | `zero_identity::error::IdentityError::Zid` | Wrapped via `#[from]` so cryptographic failures surface as a single crate-level error type. |
| `zid::types::IdentityId` | `zero_identity::IdentityId` | N/A (identical) - re-exported unchanged so callers stay decoupled from the upstream module path. |
| `zid::types::MachineId` | `zero_identity::MachineId` | N/A (identical) - re-exported unchanged for the same reason as `IdentityId`. |
| `zid::keys::neural::NeuralKey` | `zero_identity::neural_key::NeuralKey` | Newtype wrapper that adds CSPRNG-based `generate`, deterministic `identity_id`, and HKDF `derive` while hiding the upstream module path. |
| `zid::keys::machine::MachineKeyCapabilities` | `zero_identity::MachineKeyCapabilities` | N/A (identical) - re-exported so capability flags can be constructed without naming the upstream module. |
| `zid::keys::machine::MachineKeyPair` | `zero_identity::machine_key::MachineKeyEntry` | Renamed to `MachineKeyEntry` because this crate stores additional metadata (label, epoch, persistence handle) alongside the keypair. |
| `zid::shamir_split` | `zero_identity::neural_key::split_neural_key` | Renamed to make the operand explicit (`split_neural_key`) and to validate `ShareConfig` bounds before delegating. |
| `zid::shamir_combine` | `zero_identity::neural_key::recover_neural_key` | Renamed to `recover_neural_key` to match the spec vocabulary and to map upstream errors onto `IdentityError::ShareRecoveryFailed`. |
| `zid::ShamirShare` | `zero_identity::neural_key::NeuralKeyShares` | `NeuralKeyShares` aggregates `Vec<ShamirShare>` plus the threshold so that a recovered bundle is self-describing on disk. |

If you add a new `zid::*` reference to the crate source, add a matching
row to the table above. The CI grep gate fails the build otherwise.

## Public API

See the rustdoc for the authoritative API surface. The headline items
are:

- `NeuralKey::generate`, `NeuralKey::derive`, `NeuralKey::identity_id`
- `split_neural_key`, `recover_neural_key`, `ShareConfig`,
  `NeuralKeyShares`
- `MachineKeyStore::open`, `MachineKeyStore::create_machine_key`,
  `MachineKeyStore::list_machine_keys`, `MachineKeyStore::get`
- `MachineKeyEntry` (with `ed25519_verifying_key`,
  `mldsa_verifying_key`, `x25519_public_key`, `mlkem_encap_key` fields)
- `IdentityError`

## License

See the workspace root for license terms.
