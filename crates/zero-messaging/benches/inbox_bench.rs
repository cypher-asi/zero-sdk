//! Criterion benchmarks for inbox list and unread operations.
//!
//! Budget: list_inbox(50) over 1000 conversations p50 <= 5ms, p99 <= 50ms.

use criterion::{criterion_group, criterion_main, Criterion};
use std::sync::Arc;
use tempfile::TempDir;
use zero_crypto::aad::{IdentityId, MachineId};
use zero_messaging::dm::types::ConversationId;
use zero_messaging::inbox::types::{ConversationKind, InboxEntry};
use zero_messaging::inbox::InboxService;
use zero_storage::db::ZeroDb;

struct BenchEnv {
    _dir: TempDir,
    svc: InboxService,
}

fn _make_conversation_id(i: usize) -> ConversationId {
    let mut bytes = [0u8; 32];
    bytes[..8].copy_from_slice(&(i as u64).to_be_bytes());
    ConversationId(bytes)
}

fn populate_inbox(count: usize) -> BenchEnv {
    let dir = TempDir::new().expect("tempdir");
    let db = Arc::new(ZeroDb::open(dir.path()).expect("open db"));

    let identity_id = IdentityId([1u8; 16]);
    let machine_id = MachineId([2u8; 16]);

    let svc = InboxService::new(Arc::clone(&db), identity_id, machine_id);

    for i in 0..count {
        let mut conv_bytes = [0u8; 32];
        let idx = (i as u32).to_be_bytes();
        conv_bytes[..4].copy_from_slice(&idx);
        let conversation_id = ConversationId(conv_bytes);

        let entry = InboxEntry {
            conversation_id,
            kind: ConversationKind::Dm,
            last_ts: (i as u64) * 1000 + 1_700_000_000_000,
            unread: ((i % 5) as u32),
            preview_sender: IdentityId([3u8; 16]),
            preview: format!("Message preview for conversation {i}"),
        };
        svc.upsert(entry).expect("upsert");
    }

    BenchEnv { _dir: dir, svc }
}

fn bench_inbox_list_warm(c: &mut Criterion) {
    let env = populate_inbox(1000);

    // Warm the RocksDB cache with one read
    let _ = env.svc.list_inbox(Some(50));

    c.bench_function("inbox_list_warm_1000_limit50", |b| {
        b.iter(|| {
            let result = env.svc.list_inbox(Some(50)).expect("list_inbox");
            assert_eq!(result.len(), 50);
            criterion::black_box(result);
        });
    });
}

fn bench_inbox_list_cold(c: &mut Criterion) {
    let mut group = c.benchmark_group("inbox_list_cold");
    group.sample_size(20);

    group.bench_function("inbox_list_cold_1000_limit50", |b| {
        b.iter_with_setup(
            || populate_inbox(1000),
            |env| {
                let result = env.svc.list_inbox(Some(50)).expect("list_inbox");
                assert_eq!(result.len(), 50);
                criterion::black_box(result);
            },
        );
    });

    group.finish();
}

fn bench_unread_total(c: &mut Criterion) {
    let env = populate_inbox(1000);

    // Warm
    let _ = env.svc.unread_total();

    c.bench_function("unread_total_1000", |b| {
        b.iter(|| {
            let total = env.svc.unread_total().expect("unread_total");
            criterion::black_box(total);
        });
    });
}

criterion_group!(
    benches,
    bench_inbox_list_warm,
    bench_inbox_list_cold,
    bench_unread_total
);
criterion_main!(benches);
