//! InboxService: manages the inbox index for conversation previews.

use std::sync::Arc;

use zero_crypto::aad::{IdentityId, MachineId};
use zero_storage::db::{ZeroDb, CF_INBOX_INDEX};

use super::index;
use super::types::{ConversationRef, InboxEntry, InboxStats};
use super::InboxError;

/// Service managing the per-user inbox index in `CF_INBOX_INDEX`.
pub struct InboxService {
    db: Arc<ZeroDb>,
    identity_id: IdentityId,
    machine_id: MachineId,
}

impl InboxService {
    /// Create a new `InboxService` bound to a specific identity and machine.
    #[must_use]
    pub fn new(db: Arc<ZeroDb>, identity_id: IdentityId, machine_id: MachineId) -> Self {
        Self {
            db,
            identity_id,
            machine_id,
        }
    }

    /// Insert or update an inbox entry for a conversation.
    ///
    /// If an entry already exists for the same conversation, the old key is
    /// deleted and the new one is written, keeping the index consistent.
    pub fn upsert(&self, entry: InboxEntry) -> Result<(), InboxError> {
        if let Some((old_key, _)) = self.find_raw_entry(entry.conversation_id)? {
            self.db
                .delete_raw(CF_INBOX_INDEX, &old_key)
                .map_err(InboxError::Storage)?;
        }
        let key = index::encode_key(
            &self.identity_id,
            &self.machine_id,
            entry.last_ts,
            &entry.conversation_id,
        );
        let value = postcard::to_allocvec(&entry).map_err(|e| InboxError::Codec(e.to_string()))?;
        self.db
            .put_raw(CF_INBOX_INDEX, &key, &value)
            .map_err(InboxError::Storage)?;
        Ok(())
    }

    /// Return conversations sorted by `last_ts` descending (newest first).
    ///
    /// Because keys encode an inverted timestamp, a forward prefix scan already
    /// yields entries in DESC order -- no in-memory sort required.
    /// Defaults to 50 when `limit` is `None`.
    pub fn list_conversations(&self, limit: Option<usize>) -> Result<Vec<InboxEntry>, InboxError> {
        self.list_inbox(limit)
    }

    /// Return inbox entries sorted by `last_ts` descending, capped at `limit`.
    ///
    /// Reads only from `CF_INBOX_INDEX` -- no full sector scan.
    /// Defaults to 50 when `limit` is `None`.
    pub fn list_inbox(&self, limit: Option<usize>) -> Result<Vec<InboxEntry>, InboxError> {
        let limit = limit.unwrap_or(50);
        let prefix = index::owner_prefix(&self.identity_id, &self.machine_id);
        let pairs = self
            .db
            .prefix_scan_raw(CF_INBOX_INDEX, &prefix)
            .map_err(InboxError::Storage)?;

        let mut entries = Vec::with_capacity(pairs.len().min(limit));
        for (_key, value) in pairs {
            if entries.len() >= limit {
                break;
            }
            let entry: InboxEntry =
                postcard::from_bytes(&value).map_err(|e| InboxError::Codec(e.to_string()))?;
            entries.push(entry);
        }
        Ok(entries)
    }

    /// Sum of `unread` across all conversations for this identity.
    ///
    /// Pure `CF_INBOX_INDEX` prefix scan -- no other column families touched.
    pub fn unread_total(&self) -> Result<u64, InboxError> {
        let prefix = index::owner_prefix(&self.identity_id, &self.machine_id);
        let pairs = self
            .db
            .prefix_scan_raw(CF_INBOX_INDEX, &prefix)
            .map_err(InboxError::Storage)?;
        let mut total: u64 = 0;
        for (_key, value) in pairs {
            let entry: InboxEntry =
                postcard::from_bytes(&value).map_err(|e| InboxError::Codec(e.to_string()))?;
            total += u64::from(entry.unread);
        }
        Ok(total)
    }

    /// Global stats: total unread count and number of conversations.
    pub fn stats(&self) -> Result<InboxStats, InboxError> {
        let prefix = index::owner_prefix(&self.identity_id, &self.machine_id);
        let pairs = self
            .db
            .prefix_scan_raw(CF_INBOX_INDEX, &prefix)
            .map_err(InboxError::Storage)?;
        let mut total_unread: u64 = 0;
        let mut conversation_count: usize = 0;
        for (_key, value) in pairs {
            let entry: InboxEntry =
                postcard::from_bytes(&value).map_err(|e| InboxError::Codec(e.to_string()))?;
            total_unread += u64::from(entry.unread);
            conversation_count += 1;
        }
        Ok(InboxStats {
            total_unread,
            conversation_count,
        })
    }

    /// Mark all messages in a conversation as read (set `unread` to 0).
    ///
    /// No-op if the conversation is not found.
    pub fn mark_read(&self, conversation_ref: &ConversationRef) -> Result<(), InboxError> {
        if let Some((old_key, mut entry)) = self.find_raw_entry(conversation_ref.conversation_id)? {
            if entry.unread > 0 {
                self.db
                    .delete_raw(CF_INBOX_INDEX, &old_key)
                    .map_err(InboxError::Storage)?;
                entry.unread = 0;
                let new_key = index::encode_key(
                    &self.identity_id,
                    &self.machine_id,
                    entry.last_ts,
                    &entry.conversation_id,
                );
                let value =
                    postcard::to_allocvec(&entry).map_err(|e| InboxError::Codec(e.to_string()))?;
                self.db
                    .put_raw(CF_INBOX_INDEX, &new_key, &value)
                    .map_err(InboxError::Storage)?;
            }
        }
        Ok(())
    }

    /// Scan for an entry matching `conv_id`, returning the raw key and decoded value.
    fn find_raw_entry(
        &self,
        conv_id: crate::dm::ConversationId,
    ) -> Result<Option<(Vec<u8>, InboxEntry)>, InboxError> {
        let prefix = index::owner_prefix(&self.identity_id, &self.machine_id);
        let pairs = self
            .db
            .prefix_scan_raw(CF_INBOX_INDEX, &prefix)
            .map_err(InboxError::Storage)?;
        for (key, value) in pairs {
            let entry: InboxEntry =
                postcard::from_bytes(&value).map_err(|e| InboxError::Codec(e.to_string()))?;
            if entry.conversation_id == conv_id {
                return Ok(Some((key, entry)));
            }
        }
        Ok(None)
    }
}
