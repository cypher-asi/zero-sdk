//! `zero-identity` --- foundational identity and machine-key primitives.
//!
//! This crate wraps the upstream [`zid`](https://github.com/cypher-asi/zid)
//! library and exposes the lowest layer of the zero-sdk: `NeuralKey`
//! generation, Shamir secret-share emission, and local machine-key
//! storage. Higher-level networking concerns live in sibling crates.
//!
//! At this stage of the build the public API surface is intentionally
//! empty; tasks 1.3 onward populate the [`error`], [`neural_key`], and
//! [`machine_key`] modules.

#![deny(warnings)]
#![warn(clippy::pedantic, clippy::nursery)]
#![forbid(unsafe_code)]

pub mod error;
pub mod machine_key;
pub mod neural_key;
