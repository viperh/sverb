//! M7-06 `argon2_unlock` (informational; SPEC §5.3: 0.5–1 s): one password KDF with
//! the production parameters, what every password unlock pays.
#![allow(missing_docs, clippy::unwrap_used)]

use std::hint::black_box;
use std::time::Duration;

use criterion::{Criterion, criterion_group, criterion_main};
use sverb_core::vault::Argon2Cost;
use sverb_crypto::kdf::{Argon2Params, argon2id};

fn bench(c: &mut Criterion) {
    let cost = Argon2Cost::PRODUCTION;
    let params = Argon2Params {
        m_kib: cost.m_kib,
        t: cost.t,
        p: cost.p,
        salt: [9; 16],
    };
    let mut g = c.benchmark_group("argon2_unlock");
    g.sample_size(10);
    g.measurement_time(Duration::from_secs(15));
    g.bench_function("production", |b| {
        b.iter(|| {
            black_box(argon2id(black_box(b"correct horse battery staple"), &params).unwrap())
        });
    });
    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
