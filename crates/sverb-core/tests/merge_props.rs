//! M4-06: property tests for the field-level merge (SPEC §12.4, §19).
//!
//! - T-05: `merge` is commutative, associative and idempotent on random bodies.
//! - T-06: N = 2..5 simulated offline devices make random edits, then exchange bodies
//!   through a network that reorders, duplicates and delays; every device ends with an
//!   identical store, equal to the per-field maximum of every write ever made.

use std::collections::{BTreeMap, HashMap};
use std::time::Duration;

use ciborium::Value;
use proptest::prelude::*;
use sverb_core::model::{
    DeviceId, Hlc, HlcClock, ItemBody, ItemId, ItemKind, ManualClock, Stamped, merge, merge_all,
};

const T0: Duration = Duration::from_secs(1_800_000_000);

fn dev(b: u8) -> DeviceId {
    DeviceId::from_bytes([b; 16])
}

// ---------------------------------------------------------------------------------
// T-05: algebraic properties over random bodies.

/// Small alphabets so that collisions (same key, same HLC, same device) are frequent.
fn arb_value() -> impl Strategy<Value = Value> {
    prop_oneof![
        Just(Value::Null),
        (0_i64..3).prop_map(Value::from),
        prop::sample::select(vec!["x", "y"]).prop_map(Value::from),
        prop::collection::vec((0_i64..2).prop_map(Value::from), 0..3).prop_map(Value::Array),
    ]
}

fn arb_stamp() -> impl Strategy<Value = (Hlc, DeviceId)> {
    (0_u64..4, 0_u8..3).prop_map(|(h, d)| (Hlc::from_u64(h), dev(d)))
}

fn arb_body() -> impl Strategy<Value = ItemBody> {
    let kind = prop::sample::select(vec![ItemKind::Host, ItemKind::Snippet]);
    let key = prop::sample::select(vec!["label", "port", "proxy.addr", "tags", "zz.unknown"]);
    let fields = prop::collection::btree_map(key, (arb_value(), arb_stamp()), 0..5);
    let deleted = prop::option::of((any::<bool>(), arb_stamp()));
    (kind, 1_u16..4, fields, deleted).prop_map(|(kind, schema_version, fields, deleted)| ItemBody {
        kind,
        schema_version,
        fields: fields
            .into_iter()
            .map(|(k, (v, (h, d)))| (k.to_owned(), Stamped::new(v, h, d)))
            .collect::<BTreeMap<_, _>>(),
        deleted: deleted.map(|(v, (h, d))| Stamped::new(v, h, d)),
    })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1000))]

    // T-05
    #[test]
    fn merge_is_commutative(a in arb_body(), b in arb_body()) {
        prop_assert_eq!(merge(&a, &b).body, merge(&b, &a).body);
    }

    // T-05
    #[test]
    fn merge_is_associative(a in arb_body(), b in arb_body(), c in arb_body()) {
        let left = merge(&merge(&a, &b).body, &c).body;
        let right = merge(&a, &merge(&b, &c).body).body;
        prop_assert_eq!(left, right);
    }

    // T-05
    #[test]
    fn merge_is_idempotent(a in arb_body(), b in arb_body()) {
        let aa = merge(&a, &a);
        prop_assert_eq!(&aa.body, &a);
        prop_assert!(!aa.changed());
        prop_assert!(!aa.resurrected);
        // Re-delivering the same remote body changes nothing.
        let ab = merge(&a, &b).body;
        let again = merge(&ab, &b);
        prop_assert_eq!(&again.body, &ab);
        prop_assert!(again.changed_fields.is_empty());
    }

    // T-05: `resurrected` is exactly "was deleted, no longer is".
    #[test]
    fn resurrection_flag_matches_deletion_rule(a in arb_body(), b in arb_body()) {
        let out = merge(&a, &b);
        prop_assert_eq!(out.resurrected, a.is_deleted() && !out.body.is_deleted());
    }
}

// ---------------------------------------------------------------------------------
// T-06: N-device simulation.

/// SplitMix64: a tiny deterministic RNG driven by the proptest-chosen seed.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    fn below(&mut self, n: usize) -> usize {
        // n is tiny, so the modulo bias is irrelevant here.
        (self.next() % n as u64) as usize
    }

    fn chance(&mut self, percent: u64) -> bool {
        self.next() % 100 < percent
    }

    fn shuffle<T>(&mut self, v: &mut [T]) {
        for i in (1..v.len()).rev() {
            let j = self.below(i + 1);
            v.swap(i, j);
        }
    }
}

const FIELDS: [&str; 5] = ["label", "port", "username", "tags", "x.future"];

struct SimDevice {
    id: DeviceId,
    physical: ManualClock,
    clock: HlcClock,
    store: HashMap<ItemId, ItemBody>,
    skew_warnings: usize,
}

impl SimDevice {
    /// A device whose wall clock is off by `offset_ms` (positive = ahead).
    fn new(n: u8, offset_ms: i64) -> Self {
        let start = if offset_ms >= 0 {
            T0 + Duration::from_millis(offset_ms.unsigned_abs())
        } else {
            T0 - Duration::from_millis(offset_ms.unsigned_abs())
        };
        let physical = ManualClock::new(start);
        Self {
            id: dev(n + 1),
            clock: HlcClock::new(physical.clone()),
            physical,
            store: HashMap::new(),
            skew_warnings: 0,
        }
    }

    /// Receives a body: observe every stamp (as the sync engine does), then merge.
    fn receive(&mut self, item: ItemId, body: &ItemBody) {
        let stamps = body
            .fields
            .values()
            .map(Stamped::stamp)
            .chain(body.deleted.as_ref().map(Stamped::stamp));
        for (hlc, from) in stamps {
            if self.clock.observe(hlc, from).is_err() {
                self.skew_warnings += 1;
            }
        }
        let merged = match self.store.get(&item) {
            Some(local) => merge(local, body).body,
            None => body.clone(),
        };
        self.store.insert(item, merged);
    }
}

/// A body in flight to `to`. Messages are delivered in random order, possibly more
/// than once, possibly long after they were sent.
struct Message {
    to: usize,
    item: ItemId,
    body: ItemBody,
}

#[derive(Default)]
struct SimNetwork {
    in_flight: Vec<Message>,
}

impl SimNetwork {
    fn send(&mut self, to: usize, item: ItemId, body: ItemBody) {
        self.in_flight.push(Message { to, item, body });
    }

    /// Delivers one random message; with some probability a duplicate stays queued.
    fn deliver_one(&mut self, rng: &mut Rng, devices: &mut [SimDevice]) {
        if self.in_flight.is_empty() {
            return;
        }
        let i = rng.below(self.in_flight.len());
        let msg = if rng.chance(20) {
            let m = &self.in_flight[i];
            Message {
                to: m.to,
                item: m.item,
                body: m.body.clone(),
            }
        } else {
            self.in_flight.swap_remove(i)
        };
        devices[msg.to].receive(msg.item, &msg.body);
    }

    fn drain(&mut self, rng: &mut Rng, devices: &mut [SimDevice]) {
        while !self.in_flight.is_empty() {
            self.deliver_one(rng, devices);
        }
    }
}

fn random_value(rng: &mut Rng) -> Value {
    match rng.below(3) {
        0 => Value::from(rng.below(4) as i64),
        1 => Value::from(["a", "b", "c"][rng.below(3)]),
        _ => Value::Array((0..rng.below(3)).map(|i| Value::from(i as i64)).collect()),
    }
}

/// Every register ever written, per item and key (the oracle for the final state).
#[derive(Default)]
struct Oracle {
    fields: HashMap<(ItemId, String), Vec<Stamped<Value>>>,
    tombs: HashMap<ItemId, Vec<Stamped<bool>>>,
}

fn local_op(rng: &mut Rng, d: &mut SimDevice, items: &[ItemId], oracle: &mut Oracle) {
    d.physical
        .advance(Duration::from_millis(rng.below(2_000) as u64));
    let item = items[rng.below(items.len())];
    let body = d
        .store
        .entry(item)
        .or_insert_with(|| ItemBody::new(ItemKind::Host, 1));
    let field = FIELDS[rng.below(FIELDS.len())];
    match rng.below(10) {
        // set
        0..=4 => {
            body.set(field, random_value(rng), &mut d.clock, d.id);
        }
        // unset
        5 => {
            body.unset(field, &mut d.clock, d.id);
        }
        // delete
        6 | 7 => body.delete(&mut d.clock, d.id),
        // restore (undo)
        8 => body.restore(&mut d.clock, d.id),
        // edit-after-delete: delete, then edit it again later
        _ => {
            body.delete(&mut d.clock, d.id);
            d.physical
                .advance(Duration::from_millis(rng.below(500) as u64));
            body.set(field, random_value(rng), &mut d.clock, d.id);
        }
    }
    for (k, s) in &body.fields {
        oracle
            .fields
            .entry((item, k.clone()))
            .or_default()
            .push(s.clone());
    }
    if let Some(t) = &body.deleted {
        oracle.tombs.entry(item).or_default().push(t.clone());
    }
}

fn simulate(seed: u64, n: usize) -> Result<(), TestCaseError> {
    let mut rng = Rng(seed);
    let items: Vec<ItemId> = (0..3_u8)
        .map(|i| ItemId::from_bytes([0xa0 + i; 16]))
        .collect();
    // Clocks within ±10 minutes of each other, so some stamps trip the skew clamp.
    let mut devices: Vec<SimDevice> = (0..n)
        .map(|i| {
            let offset = rng.below(1_200_001) as i64 - 600_000;
            SimDevice::new(i as u8, offset)
        })
        .collect();
    let mut net = SimNetwork::default();
    let mut oracle = Oracle::default();

    // Offline edits interleaved with partial, delayed exchanges.
    let steps = 20 + rng.below(80);
    for _ in 0..steps {
        match rng.below(10) {
            0..=5 => {
                let i = rng.below(n);
                local_op(&mut rng, &mut devices[i], &items, &mut oracle);
            }
            6 | 7 => {
                let from = rng.below(n);
                let to = rng.below(n);
                let item = items[rng.below(items.len())];
                if let Some(b) = devices[from].store.get(&item) {
                    net.send(to, item, b.clone());
                }
            }
            _ => net.deliver_one(&mut rng, &mut devices),
        }
    }

    // Final exchange: every device sends every body to every other device; the
    // stale in-flight messages are mixed in, shuffled and duplicated.
    for (from, device) in devices.iter().enumerate() {
        for (item, body) in &device.store {
            for to in 0..n {
                if to != from {
                    for _ in 0..1 + rng.below(2) {
                        net.send(to, *item, body.clone());
                    }
                }
            }
        }
    }
    rng.shuffle(&mut net.in_flight);
    net.drain(&mut rng, &mut devices);

    // Convergence: identical stores everywhere.
    for d in &devices[1..] {
        prop_assert_eq!(&d.store, &devices[0].store);
    }

    // And the converged state is the join of everything ever written.
    for (item, body) in &devices[0].store {
        let joined = merge_all(devices.iter().filter_map(|d| d.store.get(item)));
        prop_assert_eq!(joined.as_ref(), Some(body));
        for (key, reg) in &body.fields {
            let best = oracle.fields[&(*item, key.clone())]
                .iter()
                .max_by(|a, b| a.cmp_stamp(b))
                .map(Stamped::stamp);
            prop_assert_eq!(Some(reg.stamp()), best, "field {}", key);
        }
        let best_tomb = oracle
            .tombs
            .get(item)
            .and_then(|t| t.iter().max_by(|a, b| a.cmp_stamp(b)))
            .map(Stamped::stamp);
        prop_assert_eq!(body.deleted.as_ref().map(Stamped::stamp), best_tomb);
    }
    // Every key ever written to an item survives.
    for (item, key) in oracle.fields.keys() {
        prop_assert!(devices[0].store[item].contains(key));
    }
    Ok(())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1000))]

    // T-06
    #[test]
    fn n_devices_converge(seed in any::<u64>(), n in 2_usize..=5) {
        simulate(seed, n)?;
    }
}

/// T-06 sanity: the simulation does exercise deletes, resurrections and skew.
#[test]
fn simulation_covers_interesting_cases() {
    let (mut deleted, mut resurrected, mut skew) = (0, 0, 0);
    for seed in 0..200 {
        let mut rng = Rng(seed);
        let item = ItemId::from_bytes([1; 16]);
        let mut a = SimDevice::new(0, 0);
        let mut b = SimDevice::new(1, 400_000 + rng.below(300_000) as i64);
        let mut oracle = Oracle::default();
        for _ in 0..10 {
            local_op(&mut rng, &mut a, &[item], &mut oracle);
            local_op(&mut rng, &mut b, &[item], &mut oracle);
        }
        let (Some(la), Some(lb)) = (a.store.get(&item).cloned(), b.store.get(&item).cloned())
        else {
            continue;
        };
        let out = merge(&la, &lb);
        deleted += usize::from(out.body.is_deleted());
        resurrected += usize::from(out.resurrected);
        a.receive(item, &lb);
        skew += a.skew_warnings;
    }
    assert!(deleted > 0, "no deleted outcomes");
    assert!(resurrected > 0, "no resurrections");
    assert!(skew > 0, "no skew warnings");
}
