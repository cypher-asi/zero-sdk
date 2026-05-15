//! End-to-end DM test: A sends to B, B receives, receipts flow back.

use std::sync::Arc;
use std::time::Instant;
use tempfile::TempDir;

use zero_crypto::aad::{IdentityId, MachineId};
use zero_messaging::contacts::store::ContactStore;
use zero_messaging::contacts::types::Contact;
use zero_messaging::dm::service::DmService;
use zero_messaging::dm::types::{Message, MessageId, MessageStatus};
use zero_storage::db::ZeroDb;

struct TestNode {
    _dir: TempDir,
    _db: Arc<ZeroDb>,
    svc: DmService,
    identity: IdentityId,
    machine: MachineId,
}

fn make_identity(byte: u8) -> IdentityId {
    let mut arr = [0u8; 16];
    arr[0] = byte;
    IdentityId(arr)
}

fn make_machine(byte: u8) -> MachineId {
    let mut arr = [0u8; 16];
    arr[0] = byte;
    MachineId(arr)
}

fn make_contact(id: IdentityId) -> Contact {
    Contact {
        identity_id: id,
        label: format!("peer-{}", id.0[0]),
        machine_keys: vec![],
        last_seen_epoch: None,
        added_at_ms: now_ms(),
    }
}

fn setup_node(identity_byte: u8, machine_byte: u8, peer_byte: u8) -> TestNode {
    let dir = TempDir::new().expect("tempdir");
    let db = Arc::new(ZeroDb::open(dir.path()).expect("open db"));
    let identity = make_identity(identity_byte);
    let machine = make_machine(machine_byte);
    let contacts = Arc::new(ContactStore::new(db.clone(), identity));
    let peer_id = make_identity(peer_byte);
    contacts
        .add_contact(make_contact(peer_id))
        .expect("add peer");
    let svc = DmService::new(db.clone(), identity, machine, contacts);
    TestNode {
        _dir: dir,
        _db: db,
        svc,
        identity,
        machine,
    }
}

#[test]
fn e2e_send_receive_delivered_read() {
    let node_a = setup_node(1, 0xAA, 2);
    let node_b = setup_node(2, 0xBB, 1);

    // A opens conversation with B and sends a message
    let conv_a = node_a
        .svc
        .open_conversation(node_b.identity)
        .expect("open conv A");
    let msg_id = node_a
        .svc
        .send_text(conv_a.conversation_id, "hi".to_string())
        .expect("send_text");

    // Status should be Queued immediately after send
    let msg = node_a
        .svc
        .get_message(conv_a.conversation_id, msg_id)
        .expect("get_message")
        .expect("message exists");
    assert_eq!(msg.status, MessageStatus::Queued);

    // A acknowledges the message was sent (simulating successful publish)
    node_a
        .svc
        .acknowledge_sent(conv_a.conversation_id, msg_id)
        .expect("acknowledge_sent");

    let msg = node_a
        .svc
        .get_message(conv_a.conversation_id, msg_id)
        .expect("get_message")
        .expect("message exists");
    assert_eq!(msg.status, MessageStatus::Sent);

    // B opens conversation with A and receives the message
    let conv_b = node_b
        .svc
        .open_conversation(node_a.identity)
        .expect("open conv B");
    assert_eq!(conv_a.conversation_id, conv_b.conversation_id);

    // Build a Message to store on B's side (simulating receipt of A's message)
    let received = Message {
        id: msg_id,
        conversation_id: conv_b.conversation_id,
        sender_identity: node_a.identity,
        sender_machine: node_a.machine,
        text: "hi".to_string(),
        status: MessageStatus::Delivered,
        created_at_ms: msg.created_at_ms,
        status_updated_at_ms: now_ms(),
    };
    node_b.svc.store_message(&received).expect("store_message");

    // B emits a Delivered receipt and A processes it
    let delivered_receipt = zero_messaging::dm::build_delivered_receipt(
        msg_id,
        conv_b.conversation_id,
        node_b.identity,
        node_b.machine,
    );

    node_a
        .svc
        .process_receipt(&delivered_receipt)
        .expect("process delivered receipt");

    let msg = node_a
        .svc
        .get_message(conv_a.conversation_id, msg_id)
        .expect("get_message")
        .expect("message exists");
    assert_eq!(msg.status, MessageStatus::Delivered);

    // B marks the message as read
    let read_receipt = node_b
        .svc
        .mark_read(conv_b.conversation_id, msg_id)
        .expect("mark_read");

    // A processes the Read receipt
    node_a
        .svc
        .process_receipt(&read_receipt)
        .expect("process read receipt");

    let msg = node_a
        .svc
        .get_message(conv_a.conversation_id, msg_id)
        .expect("get_message")
        .expect("message exists");
    assert_eq!(msg.status, MessageStatus::Read);
}

#[test]
fn status_cannot_go_backwards() {
    let node = setup_node(3, 0xCC, 4);
    let peer = make_identity(4);
    // peer is NOT in contacts for this node — add it
    let _ = node._db.clone(); // just to keep _db alive
    let contacts2 = Arc::new(ContactStore::new(node._db.clone(), node.identity));
    contacts2.add_contact(make_contact(peer)).ok();

    let conv = node.svc.open_conversation(peer).expect("open conv");
    let msg_id = node
        .svc
        .send_text(conv.conversation_id, "hello".to_string())
        .expect("send");
    node.svc
        .acknowledge_sent(conv.conversation_id, msg_id)
        .expect("ack sent");

    // Manually advance to Delivered
    let delivered = Message {
        id: msg_id,
        conversation_id: conv.conversation_id,
        sender_identity: node.identity,
        sender_machine: node.machine,
        text: "hello".to_string(),
        status: MessageStatus::Delivered,
        created_at_ms: now_ms(),
        status_updated_at_ms: now_ms(),
    };
    node.svc.store_message(&delivered).expect("store delivered");

    // Try to go back to Queued — should fail
    use zero_messaging::dm::DmError;
    let err = node
        .svc
        .update_status(conv.conversation_id, msg_id, MessageStatus::Queued)
        .expect_err("backward transition should fail");
    assert!(
        matches!(err, DmError::InvalidStatusTransition { .. }),
        "expected InvalidStatusTransition, got: {:?}",
        err
    );
}

#[test]
fn multiple_messages_pagination() {
    let node = setup_node(5, 0xDD, 6);
    let conv = node.svc.open_conversation(make_identity(6)).expect("open");

    let mut ids: Vec<MessageId> = Vec::new();
    for i in 0..10u8 {
        let id = node
            .svc
            .send_text(conv.conversation_id, format!("msg {i}"))
            .expect("send");
        ids.push(id);
    }

    // List latest 5
    let page1 = node
        .svc
        .history(conv.conversation_id, None, 5)
        .expect("page 1");
    assert_eq!(page1.len(), 5);

    // They should be the 5 most recent (descending order)
    let before = page1.last().map(|m| m.id);
    let page2 = node
        .svc
        .history(conv.conversation_id, before, 5)
        .expect("page 2");
    assert_eq!(page2.len(), 5);

    // No overlap between pages
    let page1_ids: std::collections::HashSet<MessageId> = page1.iter().map(|m| m.id).collect();
    for m in &page2 {
        assert!(!page1_ids.contains(&m.id), "overlap between pages");
    }

    // All 10 messages accounted for
    let all: Vec<MessageId> = page1.iter().chain(page2.iter()).map(|m| m.id).collect();
    assert_eq!(all.len(), 10);

    // Empty conversation
    let node2 = setup_node(7, 0xEE, 8);
    let conv2 = node2
        .svc
        .open_conversation(make_identity(8))
        .expect("open empty");
    let empty = node2
        .svc
        .history(conv2.conversation_id, None, 10)
        .expect("empty history");
    assert!(empty.is_empty());
}

fn now_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[test]
fn send_latency_under_budget() {
    let node = setup_node(9, 0xFF, 10);
    let conv = node.svc.open_conversation(make_identity(10)).expect("open");

    let mut latencies_ms: Vec<u64> = Vec::new();
    for i in 0..20u8 {
        let t0 = Instant::now();
        node.svc
            .send_text(conv.conversation_id, format!("msg {i}"))
            .expect("send");
        latencies_ms.push(t0.elapsed().as_millis() as u64);
    }

    latencies_ms.sort_unstable();
    let p50 = latencies_ms[latencies_ms.len() / 2];
    let p99 = latencies_ms[latencies_ms.len() * 99 / 100];

    assert!(p50 < 100, "p50 send latency {}ms exceeds 100ms budget", p50);
    assert!(p99 < 100, "p99 send latency {}ms exceeds 100ms budget", p99);
}
