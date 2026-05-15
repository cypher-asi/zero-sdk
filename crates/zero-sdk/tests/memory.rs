//! Memory budget test: drives a 1000-conversation inbox workload and asserts
//! that the process RSS stays under 64 MB (excluding OS overhead that exists
//! before the workload begins).

use std::sync::Arc;

use sysinfo::{ProcessRefreshKind, ProcessesToUpdate, System};
use tempfile::TempDir;

use zero_crypto::aad::{IdentityId, MachineId};
use zero_messaging::dm::ConversationId;
use zero_sdk::{ConversationKind, InboxEntry, InboxService, ZeroDb};

const NUM_CONVERSATIONS: usize = 1000;
const MAX_RSS_BYTES: u64 = 64 * 1024 * 1024; // 64 MB

fn current_rss_bytes() -> u64 {
    let pid = sysinfo::get_current_pid().expect("failed to get current pid");
    let mut sys = System::new();
    sys.refresh_processes_specifics(
        ProcessesToUpdate::Some(&[pid]),
        ProcessRefreshKind::new().with_memory(),
    );
    sys.process(pid).map_or(0, |p| p.memory())
}

fn make_conv_id(index: usize) -> ConversationId {
    let mut id = [0u8; 32];
    let bytes = index.to_le_bytes();
    id[..bytes.len()].copy_from_slice(&bytes);
    ConversationId(id)
}

fn make_preview_text(index: usize) -> String {
    // 140-char preview to exercise realistic payload sizes
    let base = format!("Preview message for conversation {index}: ");
    let padding_len = 140usize.saturating_sub(base.len());
    let mut text = base;
    for _ in 0..padding_len {
        text.push('x');
    }
    text.truncate(140);
    text
}

#[test]
fn inbox_1000_conversations_rss_under_64mb() {
    let tmp = TempDir::new().expect("failed to create temp dir");
    let db = Arc::new(ZeroDb::open(tmp.path()).expect("failed to open db"));

    let identity_id = IdentityId([0xAAu8; 16]);
    let machine_id = MachineId([0xBBu8; 16]);
    let sender_id = IdentityId([0xCCu8; 16]);

    let svc = InboxService::new(Arc::clone(&db), identity_id, machine_id);

    // Populate 1000 conversations
    for i in 0..NUM_CONVERSATIONS {
        let entry = InboxEntry {
            conversation_id: make_conv_id(i),
            kind: if i % 5 == 0 {
                ConversationKind::Group
            } else {
                ConversationKind::Dm
            },
            last_ts: (i as u64 + 1) * 1000,
            unread: (i % 10) as u32,
            preview_sender: sender_id,
            preview: make_preview_text(i),
        };
        svc.upsert(entry).expect("upsert failed");
    }

    // Exercise the read paths
    let conversations = svc
        .list_conversations(None)
        .expect("list_conversations failed");
    assert_eq!(conversations.len(), 50, "default limit is 50");

    let all = svc
        .list_conversations(Some(NUM_CONVERSATIONS))
        .expect("list all failed");
    assert_eq!(all.len(), NUM_CONVERSATIONS);

    let stats = svc.stats().expect("stats failed");
    assert_eq!(stats.conversation_count, NUM_CONVERSATIONS);

    // Sample RSS after workload
    let rss = current_rss_bytes();
    eprintln!(
        "Peak RSS after 1000-conversation workload: {:.2} MB",
        rss as f64 / (1024.0 * 1024.0)
    );

    assert!(
        rss < MAX_RSS_BYTES,
        "RSS {rss} bytes ({:.2} MB) exceeds 64 MB budget",
        rss as f64 / (1024.0 * 1024.0)
    );
}
