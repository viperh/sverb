//! Seal / open of a 1 KiB item envelope (M7-06 `envelope_seal_open_1k`, informational).
#![allow(missing_docs, clippy::unwrap_used)]

use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use sverb_crypto::Key32;
use sverb_crypto::envelope::{open_item, seal_item};
use sverb_crypto::random::os_rng;

fn bench_envelope(c: &mut Criterion) {
    let vk = Key32::from_bytes([7; 32]);
    let (vault, item) = ([1; 16], [2; 16]);
    let body: Vec<u8> = (0..1024u32).map(|i| (i * 31 % 251) as u8).collect();
    let mut rng = os_rng();
    let env = seal_item(&vk, &vault, &item, 1, &body, &mut rng).unwrap();

    let mut g = c.benchmark_group("envelope_seal_open_1k");
    g.bench_function("seal_1KiB", |b| {
        b.iter(|| seal_item(&vk, &vault, &item, 1, black_box(&body), &mut rng).unwrap());
    });
    g.bench_function("open_1KiB", |b| {
        b.iter(|| open_item(|_| Some(&vk), &vault, &item, black_box(&env)).unwrap());
    });
    g.finish();
}

criterion_group!(benches, bench_envelope);
criterion_main!(benches);
