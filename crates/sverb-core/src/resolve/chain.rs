//! M2-05: jump-chain expansion (SPEC §6.1.4).
//!
//! A host's resolved `jump_chain` lists host items to hop through. Each hop is itself
//! a host whose **own** resolved `jump_chain` is expanded first (a hop with its own
//! chain inserts those hops before it), recursively. [`expand_chain`] returns the
//! effective hops in connection order (the target is not included), and rejects
//!
//! - **cycles** (a host reached again while it is being expanded, the target
//!   included): "Jump chain cycle: A → B → A";
//! - **depth**: more than [`MAX_JUMP_HOPS`] effective hops: "Jump chain too deep (> 8)".
//!
//! A hop the caller cannot resolve (a deleted host) is skipped and logged at `debug`,
//! like every other missing reference (§12.4). The same host may appear twice when two
//! branches share it (no cycle): it is then connected twice, as OpenSSH would.
//!
//! Pure: the caller supplies the per-hop resolution (`sverb_core::resolve` over its
//! lookup), so the host form, copy-as-command and the connector's resolver share it.

use tracing::debug;

use super::ResolvedHost;
use crate::model::ItemId;

/// The most hops an effective chain may have (the target not counted).
pub const MAX_JUMP_HOPS: usize = 8;

/// Why a jump chain cannot be expanded.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ChainError {
    /// More than [`MAX_JUMP_HOPS`] effective hops.
    #[error("Jump chain too deep (> {MAX_JUMP_HOPS})")]
    TooDeep,
    /// A host reached again while it is being expanded: the path, first and last
    /// entries equal (display names).
    #[error("Jump chain cycle: {}", .0.join(" → "))]
    Cycle(Vec<String>),
}

/// One effective hop.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainHop {
    /// The host item.
    pub id: ItemId,
    /// Its resolved settings (credentials, port, its own direct chain).
    pub host: ResolvedHost,
}

impl ChainHop {
    /// The name shown for the hop (label, else address).
    pub fn name(&self) -> &str {
        display_name(&self.host)
    }
}

/// The name shown for a resolved host: its label, else its address.
pub fn display_name(host: &ResolvedHost) -> &str {
    if host.label.is_empty() {
        &host.address
    } else {
        &host.label
    }
}

/// Expand `target`'s jump chain recursively (see the module docs). `target_id` is the
/// target's item (`None` for an unsaved target); `resolve_hop` resolves a host item,
/// `None` when it no longer exists.
///
/// # Errors
/// [`ChainError::Cycle`] or [`ChainError::TooDeep`].
pub fn expand_chain<F>(
    target_id: Option<ItemId>,
    target: &ResolvedHost,
    mut resolve_hop: F,
) -> Result<Vec<ChainHop>, ChainError>
where
    F: FnMut(ItemId) -> Option<ResolvedHost>,
{
    let hops = expand_by(target_id, display_name(target), &target.jump_chain, |id| {
        let host = resolve_hop(id)?;
        let name = display_name(&host).to_owned();
        let chain = host.jump_chain.clone();
        Some(HopInfo {
            value: host,
            name,
            chain,
        })
    })?;
    Ok(hops
        .into_iter()
        .map(|(id, host)| ChainHop { id, host })
        .collect())
}

/// What [`expand_by`] needs to know about a hop.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HopInfo<T> {
    /// Whatever the caller keeps per hop.
    pub value: T,
    /// The name shown in a cycle path.
    pub name: String,
    /// The hop's own direct jump chain.
    pub chain: Vec<ItemId>,
}

/// [`expand_chain`] over any per-hop value (the connector expands over its resolved
/// targets): `target_chain` is the target's direct chain; `resolve_hop` describes a
/// host item (`None`: missing, skipped). Returns the effective hops in order.
///
/// # Errors
/// [`ChainError::Cycle`] or [`ChainError::TooDeep`].
pub fn expand_by<T, F>(
    target_id: Option<ItemId>,
    target_name: &str,
    target_chain: &[ItemId],
    mut resolve_hop: F,
) -> Result<Vec<(ItemId, T)>, ChainError>
where
    F: FnMut(ItemId) -> Option<HopInfo<T>>,
{
    let mut stack: Vec<(Option<ItemId>, String)> = vec![(target_id, target_name.to_owned())];
    let mut out = Vec::new();
    for hop in target_chain {
        visit(*hop, &mut stack, &mut out, &mut resolve_hop)?;
    }
    Ok(out)
}

fn visit<T, F>(
    id: ItemId,
    stack: &mut Vec<(Option<ItemId>, String)>,
    out: &mut Vec<(ItemId, T)>,
    resolve_hop: &mut F,
) -> Result<(), ChainError>
where
    F: FnMut(ItemId) -> Option<HopInfo<T>>,
{
    if let Some(pos) = stack.iter().position(|(seen, _)| *seen == Some(id)) {
        let mut path: Vec<String> = stack[pos..].iter().map(|(_, n)| n.clone()).collect();
        path.push(stack[pos].1.clone());
        return Err(ChainError::Cycle(path));
    }
    let Some(info) = resolve_hop(id) else {
        debug!(host = %id.short(), "missing jump host reference");
        return Ok(());
    };
    stack.push((Some(id), info.name));
    for inner in &info.chain {
        visit(*inner, stack, out, resolve_hop)?;
    }
    stack.pop();
    out.push((id, info.value));
    if out.len() > MAX_JUMP_HOPS {
        return Err(ChainError::TooDeep);
    }
    Ok(())
}

/// The route shown below the form's chain editor:
/// `you → bastion → inner-bastion → target`.
pub fn effective_route(hops: &[ChainHop], target: &str) -> String {
    let mut parts = vec!["you"];
    parts.extend(hops.iter().map(ChainHop::name));
    parts.push(target);
    parts.join(" → ")
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use std::collections::BTreeMap;

    use super::*;
    use crate::resolve::{GlobalDefaults, LookupTable, Settings, Target, resolve_settings};

    fn id(b: u8) -> ItemId {
        ItemId::from_bytes([b; 16])
    }

    fn host(label: &str, chain: &[u8]) -> ResolvedHost {
        let target = Target {
            label: label.to_owned(),
            address: format!("{}.example", label.to_lowercase()),
            group_id: None,
        };
        let own = Settings {
            jump_chain: Some(chain.iter().map(|b| id(*b)).collect()),
            ..Settings::default()
        };
        resolve_settings(
            &target,
            &own,
            &LookupTable::default(),
            None,
            &GlobalDefaults::default(),
        )
    }

    fn world(hosts: &[(u8, &str, &[u8])]) -> BTreeMap<ItemId, ResolvedHost> {
        hosts
            .iter()
            .map(|(b, label, chain)| (id(*b), host(label, chain)))
            .collect()
    }

    fn names(hops: &[ChainHop]) -> Vec<&str> {
        hops.iter().map(ChainHop::name).collect()
    }

    /// T-01: T → [B], B → [A] expands to [A, B] (then T).
    #[test]
    fn t01_recursive_expansion() {
        let w = world(&[(1, "A", &[]), (2, "B", &[1])]);
        let t = host("T", &[2]);
        let hops = expand_chain(Some(id(9)), &t, |i| w.get(&i).cloned()).unwrap();
        assert_eq!(names(&hops), ["A", "B"]);
        assert_eq!(hops[0].id, id(1));
        assert_eq!(effective_route(&hops, "T"), "you → A → B → T");
        // No chain: no hops.
        let lone = host("T", &[]);
        assert!(
            expand_chain(None, &lone, |i| w.get(&i).cloned())
                .unwrap()
                .is_empty()
        );
    }

    /// T-02: 8 effective hops are fine, 9 are rejected (here through recursion: each
    /// hop jumps through the previous one).
    #[test]
    fn t02_depth_limit() {
        let chain = |n: u8| {
            let mut hosts: Vec<(u8, String, Vec<u8>)> = Vec::new();
            for b in 1..=n {
                let prev: Vec<u8> = if b > 1 { vec![b - 1] } else { vec![] };
                hosts.push((b, format!("h{b}"), prev));
            }
            hosts
                .into_iter()
                .map(|(b, l, c)| (id(b), host(&l, &c)))
                .collect::<BTreeMap<_, _>>()
        };
        let w8 = chain(8);
        let hops = expand_chain(None, &host("T", &[8]), |i| w8.get(&i).cloned()).unwrap();
        assert_eq!(hops.len(), MAX_JUMP_HOPS);
        assert_eq!(names(&hops)[0], "h1");
        let w9 = chain(9);
        let err = expand_chain(None, &host("T", &[9]), |i| w9.get(&i).cloned()).unwrap_err();
        assert_eq!(err, ChainError::TooDeep);
        assert_eq!(err.to_string(), "Jump chain too deep (> 8)");
        // A flat chain of 9 too.
        let flat = world(&[
            (1, "a", &[]),
            (2, "b", &[]),
            (3, "c", &[]),
            (4, "d", &[]),
            (5, "e", &[]),
            (6, "f", &[]),
            (7, "g", &[]),
            (8, "h", &[]),
            (9, "i", &[]),
        ]);
        let t = host("T", &[1, 2, 3, 4, 5, 6, 7, 8, 9]);
        assert_eq!(
            expand_chain(None, &t, |i| flat.get(&i).cloned()),
            Err(ChainError::TooDeep)
        );
    }

    /// T-03: T → [B], B → [A], A → [B]: a cycle naming the path.
    #[test]
    fn t03_cycle_through_recursion() {
        let w = world(&[(1, "A", &[2]), (2, "B", &[1])]);
        let err = expand_chain(Some(id(9)), &host("T", &[2]), |i| w.get(&i).cloned()).unwrap_err();
        assert_eq!(
            err,
            ChainError::Cycle(vec!["B".into(), "A".into(), "B".into()])
        );
        assert_eq!(err.to_string(), "Jump chain cycle: B → A → B");
        // Back to the target itself.
        let w = world(&[(1, "A", &[9])]);
        let err = expand_chain(Some(id(9)), &host("T", &[1]), |i| w.get(&i).cloned()).unwrap_err();
        assert_eq!(err.to_string(), "Jump chain cycle: T → A → T");
    }

    /// Missing hops are skipped; a shared hop (diamond) is no cycle.
    #[test]
    fn missing_hops_are_skipped_and_diamonds_allowed() {
        let w = world(&[(1, "A", &[]), (2, "B", &[1])]);
        let hops = expand_chain(None, &host("T", &[7, 1, 2]), |i| w.get(&i).cloned()).unwrap();
        assert_eq!(names(&hops), ["A", "A", "B"]);
    }
}
