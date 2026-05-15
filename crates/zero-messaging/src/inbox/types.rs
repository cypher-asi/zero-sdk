//! Inbox types: entry, conversation reference, and statistics.

use serde::{Deserialize, Serialize};
use zero_crypto::aad::IdentityId;

use crate::dm::ConversationId;

const MAX_PREVIEW_CHARS: usize = 140;

/// Distinguishes DM from group conversations in the inbox.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ConversationKind {
    Dm,
    Group,
}

/// Reference to a conversation: either a DM or group, identified by its ID.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ConversationRef {
    pub conversation_id: ConversationId,
    pub kind: ConversationKind,
}

impl ConversationRef {
    #[must_use]
    pub fn dm(conversation_id: ConversationId) -> Self {
        Self {
            conversation_id,
            kind: ConversationKind::Dm,
        }
    }

    #[must_use]
    pub fn group(conversation_id: ConversationId) -> Self {
        Self {
            conversation_id,
            kind: ConversationKind::Group,
        }
    }
}

/// A single inbox index entry persisted in `CF_INBOX_INDEX`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct InboxEntry {
    pub conversation_id: ConversationId,
    pub kind: ConversationKind,
    pub last_ts: u64,
    pub unread: u32,
    pub preview_sender: IdentityId,
    pub preview: String,
}

impl InboxEntry {
    /// Cap preview text at 140 Unicode characters (char boundary safe).
    #[must_use]
    pub fn cap_preview(text: &str) -> String {
        if text.chars().count() <= MAX_PREVIEW_CHARS {
            text.to_string()
        } else {
            text.chars().take(MAX_PREVIEW_CHARS).collect()
        }
    }
}

/// Aggregate inbox statistics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InboxStats {
    pub total_unread: u64,
    pub conversation_count: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cap_preview_short_text() {
        let text = "hello world";
        assert_eq!(InboxEntry::cap_preview(text), "hello world");
    }

    #[test]
    fn cap_preview_exactly_140() {
        let text: String = "a".repeat(140);
        assert_eq!(InboxEntry::cap_preview(&text).chars().count(), 140);
    }

    #[test]
    fn cap_preview_long_text_truncated() {
        let text: String = "b".repeat(200);
        let capped = InboxEntry::cap_preview(&text);
        assert_eq!(capped.chars().count(), 140);
    }

    #[test]
    fn cap_preview_multibyte_chars() {
        // 150 emoji characters - each is multi-byte
        let text: String = "\u{1F600}".repeat(150);
        let capped = InboxEntry::cap_preview(&text);
        assert_eq!(capped.chars().count(), 140);
    }

    #[test]
    fn conversation_ref_dm_kind() {
        let id = ConversationId([0u8; 32]);
        let r = ConversationRef::dm(id);
        assert_eq!(r.kind, ConversationKind::Dm);
    }

    #[test]
    fn conversation_ref_group_kind() {
        let id = ConversationId([1u8; 32]);
        let r = ConversationRef::group(id);
        assert_eq!(r.kind, ConversationKind::Group);
    }
}
