//! `--on <host|#tag|group>` target resolution (SPEC §16, §9.7).
//!
//! Each argument, in order:
//! 1. `#tag` → every host with that tag (case-insensitive name), by label;
//! 2. a group name → every host in the group or its subgroups, by label;
//! 3. otherwise the usual host resolution (label, address, unique fuzzy match;
//!    [`resolve_host_arg`]).
//!
//! The result keeps first-seen order and drops duplicates. A tag or group without
//! hosts, and an unknown tag, are errors.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use crate::host_arg::{HostArgError, HostCandidate, resolve_host_arg};
use crate::model::ItemId;

/// A host as target resolution sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetHost {
    /// The item.
    pub id: ItemId,
    /// Display label.
    pub label: String,
    /// Address.
    pub address: String,
    /// Its group.
    pub group: Option<ItemId>,
    /// Its tags.
    pub tags: Vec<ItemId>,
}

/// Hosts, tags and groups to resolve against.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TargetCatalog {
    /// Every host.
    pub hosts: Vec<TargetHost>,
    /// Tag names by id.
    pub tags: BTreeMap<ItemId, String>,
    /// Groups by id: name and parent.
    pub groups: BTreeMap<ItemId, (String, Option<ItemId>)>,
}

/// Why `--on` did not resolve.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TargetError {
    /// No tag has this name.
    UnknownTag(String),
    /// The tag or group has no hosts.
    NoHosts(String),
    /// Host resolution failed.
    Host(HostArgError),
}

impl fmt::Display for TargetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownTag(t) => write!(f, "no tag named `{t}`"),
            Self::NoHosts(what) => write!(f, "`{what}` has no hosts"),
            Self::Host(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for TargetError {}

impl TargetCatalog {
    /// `g` is `ancestor` or below it (cycles are cut off).
    fn within(&self, g: ItemId, ancestor: ItemId) -> bool {
        let mut cur = Some(g);
        for _ in 0..64 {
            match cur {
                Some(x) if x == ancestor => return true,
                Some(x) => cur = self.groups.get(&x).and_then(|(_, p)| *p),
                None => return false,
            }
        }
        false
    }

    fn sorted(&self, mut hosts: Vec<&TargetHost>) -> Vec<ItemId> {
        hosts.sort_by(|a, b| {
            a.label
                .to_lowercase()
                .cmp(&b.label.to_lowercase())
                .then(a.id.cmp(&b.id))
        });
        hosts.into_iter().map(|h| h.id).collect()
    }

    /// The hosts one argument stands for.
    ///
    /// # Errors
    /// See [`TargetError`].
    pub fn resolve_one(&self, arg: &str) -> Result<Vec<ItemId>, TargetError> {
        if let Some(tag) = arg.strip_prefix('#') {
            let ids: BTreeSet<ItemId> = self
                .tags
                .iter()
                .filter(|(_, n)| n.eq_ignore_ascii_case(tag))
                .map(|(id, _)| *id)
                .collect();
            if ids.is_empty() {
                return Err(TargetError::UnknownTag(tag.to_owned()));
            }
            let hosts: Vec<&TargetHost> = self
                .hosts
                .iter()
                .filter(|h| h.tags.iter().any(|t| ids.contains(t)))
                .collect();
            if hosts.is_empty() {
                return Err(TargetError::NoHosts(arg.to_owned()));
            }
            return Ok(self.sorted(hosts));
        }
        let groups: Vec<ItemId> = self
            .groups
            .iter()
            .filter(|(_, (n, _))| n.eq_ignore_ascii_case(arg))
            .map(|(id, _)| *id)
            .collect();
        if !groups.is_empty() {
            let hosts: Vec<&TargetHost> = self
                .hosts
                .iter()
                .filter(|h| {
                    h.group
                        .is_some_and(|g| groups.iter().any(|want| self.within(g, *want)))
                })
                .collect();
            if hosts.is_empty() {
                return Err(TargetError::NoHosts(arg.to_owned()));
            }
            return Ok(self.sorted(hosts));
        }
        let candidates: Vec<HostCandidate<ItemId>> = self
            .hosts
            .iter()
            .map(|h| HostCandidate {
                id: h.id,
                label: h.label.clone(),
                address: h.address.clone(),
            })
            .collect();
        resolve_host_arg(arg, &candidates)
            .map(|(h, _)| vec![h.id])
            .map_err(TargetError::Host)
    }

    /// Every argument's hosts, first-seen order, no duplicates.
    ///
    /// # Errors
    /// The first argument that does not resolve.
    pub fn resolve(&self, args: &[String]) -> Result<Vec<ItemId>, TargetError> {
        let mut seen = BTreeSet::new();
        let mut out = Vec::new();
        for arg in args {
            for id in self.resolve_one(arg)? {
                if seen.insert(id) {
                    out.push(id);
                }
            }
        }
        Ok(out)
    }

    /// The host with `id`.
    pub fn host(&self, id: ItemId) -> Option<&TargetHost> {
        self.hosts.iter().find(|h| h.id == id)
    }
}
