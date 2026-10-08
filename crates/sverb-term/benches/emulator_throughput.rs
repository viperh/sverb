//! T-19 (M1-09): emulator parse throughput on a mixed text + SGR stream (SPEC §19: ≥ 100 MB/s).
//!
//! `cargo bench -p sverb-term --bench emulator_throughput`. M7-06: `emulator_parse`,
//! gated by `scripts/bench-gate.py` (≥ 100 MB/s locally, ≥ 50 MB/s on CI). Each
//! iteration feeds 1 MiB; criterion runs enough iterations to cover well over 100 MB.
#![allow(missing_docs, clippy::unwrap_used)]

use std::hint::black_box;

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use sverb_term::{AlacrittyEmulator, Emulator, EmulatorConfig};

/// A deterministic mixed stream: colored words, plain text, line feeds, some UTF-8.
fn mixed_stream(target_len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(target_len + 256);
    let mut i: u32 = 0;
    while out.len() < target_len {
        let color = 31 + (i % 7);
        out.extend_from_slice(format!("\x1b[{color};1mword{i}\x1b[0m ").as_bytes());
        out.extend_from_slice(b"the quick brown fox jumps over the lazy dog ");
        if i.is_multiple_of(3) {
            out.extend_from_slice("caf\u{e9} \u{4e2d}\u{6587} ".as_bytes());
        }
        if i % 4 == 3 {
            out.extend_from_slice(b"\r\n");
        }
        i = i.wrapping_add(1);
    }
    out
}

fn bench(c: &mut Criterion) {
    let chunk = mixed_stream(1024 * 1024);
    let mut group = c.benchmark_group("emulator_parse");
    group.throughput(Throughput::Bytes(chunk.len() as u64));
    group.sample_size(20);
    group.bench_function("mixed_1MiB", |b| {
        let mut emu = AlacrittyEmulator::new(EmulatorConfig::default());
        b.iter(|| {
            // Feed in 16 KiB reads, as the session read loop does.
            for part in chunk.chunks(16 * 1024) {
                emu.feed(black_box(part));
            }
            black_box(emu.take_responses());
        });
    });
    group.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
