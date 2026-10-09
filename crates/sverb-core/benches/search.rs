//! Full index build of 10k synthetic items (decrypt included) and a
//! 5-char query over them. Targets: build ≈ 50 ms on a modern CPU (< 150 ms on CI),
//! query < 5 ms.
//!
//! `index_build_10k` and `search_query_10k` (gated by `scripts/bench-gate.py`).
#![allow(missing_docs, clippy::unwrap_used, clippy::expect_used)]

use std::hint::black_box;

use ciborium::Value;
use criterion::{Criterion, criterion_group, criterion_main};
use sverb_core::model::{DeviceId, HlcClock, ItemBody, ItemId, ItemKind, VaultId};
use sverb_core::search::{ItemIndex, Query, Scope};
use sverb_crypto::Key32;
use sverb_crypto::envelope::{open_item, seal_item};
use sverb_crypto::random::os_rng;

const N: usize = 10_000;

struct Sealed {
    id: ItemId,
    env: Vec<u8>,
}

fn synthetic(vault: VaultId, key: &Key32) -> Vec<Sealed> {
    let mut clock = HlcClock::default();
    let device = DeviceId::new();
    let mut rng = os_rng();
    let tags: Vec<ItemId> = (0..20).map(|_| ItemId::new()).collect();
    let mut out = Vec::with_capacity(N + tags.len());
    let mut push = |id: ItemId, body: ItemBody| {
        let env = seal_item(
            key,
            vault.as_bytes(),
            id.as_bytes(),
            1,
            &body.to_cbor().unwrap(),
            &mut rng,
        )
        .unwrap();
        out.push(Sealed { id, env });
    };
    for (i, tag) in tags.iter().enumerate() {
        let mut b = ItemBody::new(ItemKind::Tag, 1);
        b.set("name", format!("tag{i}"), &mut clock, device);
        push(*tag, b);
    }
    for i in 0..N {
        let mut b = ItemBody::new(ItemKind::Host, 1);
        b.set(
            "label",
            format!("host-{i}-{}", ["web", "db", "cache", "queue"][i % 4]),
            &mut clock,
            device,
        );
        b.set(
            "address",
            format!("10.{}.{}.{}", i / 65536, (i / 256) % 256, i % 256),
            &mut clock,
            device,
        );
        b.set("username", "deploy", &mut clock, device);
        b.set("password", "hunter2", &mut clock, device);
        b.set(
            "tags",
            Value::Array(vec![Value::Bytes(tags[i % 20].as_bytes().to_vec())]),
            &mut clock,
            device,
        );
        push(ItemId::new(), b);
    }
    out
}

fn build(vault: VaultId, key: &Key32, items: &[Sealed]) -> ItemIndex {
    let bodies: Vec<(ItemId, ItemBody)> = items
        .iter()
        .map(|s| {
            let plain =
                open_item(|_| Some(key), vault.as_bytes(), s.id.as_bytes(), &s.env).unwrap();
            (s.id, ItemBody::from_cbor(&plain).unwrap())
        })
        .collect();
    ItemIndex::build(bodies.iter().map(|(id, b)| (*id, vault, b)))
}

fn bench_search(c: &mut Criterion) {
    let key = Key32::from_bytes([7; 32]);
    let vault = VaultId::new();
    let items = synthetic(vault, &key);

    let mut g = c.benchmark_group("index_build_10k");
    g.sample_size(10);
    g.bench_function("decrypt_and_index", |b| {
        b.iter(|| black_box(build(vault, &key, &items)));
    });
    g.finish();
    let snap = build(vault, &key, &items).snapshot();
    let q = Query::parse("hwb12");
    let mut g = c.benchmark_group("search_query_10k");
    g.bench_function("5char", |b| {
        b.iter(|| black_box(snap.query(&q, Scope::Hosts)));
    });
    g.finish();
}

criterion_group!(benches, bench_search);
criterion_main!(benches);
