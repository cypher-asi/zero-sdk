//! `zero-network`: GRID integration layer for the zero-sdk.
//!
//! Provides a `GridClient` async trait, an in-memory mock broker for
//! testing, a stub for the real GRID-backed client, and an outbox-driven
//! retry pump.

#![deny(warnings)]
#![forbid(unsafe_code)]

pub mod client;
pub mod dedupe;
pub mod error;
pub mod mock;
pub mod real;
pub mod retry;

pub use client::GridClient;
pub use error::NetworkError;
pub use mock::{Fault, InMemoryGridBroker, MockGridClient};
pub use real::RealGridClient;

/// Canonical program identifier for the zero chat protocol.
pub const PROGRAM_ID: &str = "zero.chat.v1";
