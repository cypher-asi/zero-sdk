//! Criterion benchmark for DM send latency.
//!
//! Budget: 100 ms p50, 50 ms p99 on an idle CI box.

use criterion::{criterion_group, criterion_main, Criterion};
use std::sync::Arc;
use tempfile::TempDir;
use zero_crypto::aad::{IdentityId, MachineId};
use zero_messaging::contacts::store::ContactStore;
use zero_messaging::contacts::types::Contact;
use zero_messaging::dm::service::DmService;
use zero_messaging::dm::types::ConversationId;
use zero_storage::db::ZeroDb;

struct BenchEnv {
    _dir: TempDir,
    svc: DmService,
    conv_id: ConversationId,
}

fn setup_bench_env() -> BenchEnv {
    let dir = TempDir::new().unwrap();
    let db = Arc::new(ZeroDb::open(dir.path()).unwrap());

    let alice = IdentityId([1u8; 16]);
    let bob = IdentityId([2u8; 16]);
    let machine_a = MachineId([0xAA; 16]);

    let contacts = Arc::new(ContactStore::new(Arc::clone(&db), alice));
    contacts
        .add_contact(Contact {
            identity_id: bob,
            label: "Bob".into(),
            machine_keys: vec![],
            last_seen_epoch: None,
            added_at_ms: 1000,
        })
        .unwrap();

    let svc = DmService::new(db, alice, machine_a, contacts);
    let conv = svc.open_conversation(bob).unwrap();

    BenchEnv {
        _dir: dir,
        svc,
        conv_id: conv.conversation_id,
    }
}

fn bench_send_latency(c: &mut Criterion) {
    let env = setup_bench_env();

    c.bench_function("dm_send_text", |b| {
        b.iter(|| {
            env.svc.send_text(env.conv_id, "hi".into()).unwrap();
        });
    });
}

criterion_group!(benches, bench_send_latency);
criterion_main!(benches);
