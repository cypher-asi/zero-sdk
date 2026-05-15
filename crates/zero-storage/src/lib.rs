//! `zero-storage`: durable substrate for the zero-sdk.
//!
//! This crate owns the canonical sector wire format (postcard), a
//! RocksDB-backed multi-column-family store, a bounded LRU dedupe cache,
//! and an outbox queue for retryable outbound deliveries. It deliberately
//! has no network or crypto dependencies beyond shared type definitions.

#![deny(warnings)]
#![forbid(unsafe_code)]

pub mod db;
pub mod dedupe;
pub mod error;
pub mod outbox;
pub mod sector;

pub use db::{
    ZeroDb, CF_CHAINS, CF_CONTACTS, CF_GROUPS, CF_INBOX_INDEX, CF_META, CF_OUTBOX, CF_SECTORS,
};
pub use dedupe::{DedupeCache, DEFAULT_DEDUPE_CAPACITY};
pub use error::StorageError;
pub use outbox::{Outbox, OutboxEntry, DEFAULT_OUTBOX_CAPACITY};
pub use sector::{decode_sector, encode_sector, Sector, SectorId};
