//! `zero-crypto`: cryptographic envelope for the zero-sdk.
//!
//! Provides HPKE-PQ-hybrid AEAD (X25519 + ML-KEM-768 with
//! ChaCha20-Poly1305), dual-signing (Ed25519 + ML-DSA-65), canonical
//! CBOR AAD, and MLS group-key helpers.

#![deny(warnings)]
#![forbid(unsafe_code)]

pub mod aad;
pub mod encrypt;
pub mod envelope;
pub mod error;
pub mod group_key;
pub mod sign;
