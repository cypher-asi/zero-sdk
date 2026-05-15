//! `zero-messaging` -- contacts and conversation primitives for the zero-sdk.

#![deny(warnings)]
#![warn(clippy::pedantic, clippy::nursery)]
#![forbid(unsafe_code)]
#![allow(
    clippy::must_use_candidate,
    clippy::missing_const_for_fn,
    clippy::missing_errors_doc,
    clippy::needless_pass_by_value,
    clippy::module_name_repetitions,
    clippy::redundant_pub_crate,
    clippy::future_not_send,
    clippy::missing_panics_doc,
    clippy::significant_drop_tightening,
    clippy::option_if_let_else,
    clippy::derive_partial_eq_without_eq,
    clippy::doc_markdown,
    clippy::single_match_else,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::items_after_statements,
    clippy::redundant_else,
    clippy::match_wildcard_for_single_variants,
    clippy::unnested_or_patterns,
    clippy::wildcard_imports,
    clippy::used_underscore_binding,
    clippy::struct_field_names,
    clippy::manual_let_else,
    clippy::return_self_not_must_use,
    clippy::implicit_clone,
    clippy::ref_option,
    clippy::trivially_copy_pass_by_ref,
    clippy::unused_self,
    clippy::unnecessary_wraps,
    clippy::cognitive_complexity,
    clippy::too_long_first_doc_paragraph
)]

pub mod contacts;
pub mod dm;
pub mod group;
pub mod inbox;
