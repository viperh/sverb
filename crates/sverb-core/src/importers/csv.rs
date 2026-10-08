//! CSV import (§9.13): columns `label,address,port,username,group,tags`.
//!
//! - A header row is required. Column names are case-insensitive and in any order;
//!   only `address` is mandatory. Unknown columns are ignored with a warning.
//! - Quoting follows RFC 4180 (the `csv` crate).
//! - `group` is a path `a/b/c`: missing groups are created (the preview notes them).
//! - `tags` are separated by `;` or `|` (a comma would need quoting); unknown tags are
//!   created.
//! - Rows with a bad address or port are skipped with their line number.

use std::collections::BTreeMap;

use super::{
    Draft, GroupDraft, HostDraft, ImportError, ImportPlan, ImportSource, PlanRef, PlannedItem,
    Skipped, preview::fill_fields,
};
use crate::model::{ItemKind, tag::tag_key, validate::validate_address};

/// The columns, in export order.
pub const COLUMNS: [&str; 6] = ["label", "address", "port", "username", "group", "tags"];

/// Splits a `tags` cell on `;` or `|`.
pub fn split_tags(cell: &str) -> Vec<String> {
    cell.split([';', '|'])
        .map(str::trim)
        .filter(|t| !t.is_empty())
        .map(str::to_owned)
        .collect()
}

/// Parses CSV text into a plan (all items `New`).
///
/// # Errors
/// [`ImportError::Format`] without a header row or an `address` column.
pub fn parse(text: &str) -> Result<ImportPlan, ImportError> {
    let mut plan = ImportPlan::new(ImportSource::Csv);
    let mut reader = ::csv::ReaderBuilder::new()
        .has_headers(true)
        .flexible(true)
        .trim(::csv::Trim::All)
        .from_reader(text.as_bytes());
    let headers = reader
        .headers()
        .map_err(|e| ImportError::Format(format!("cannot read the CSV header: {e}")))?
        .clone();
    let mut col: BTreeMap<&'static str, usize> = BTreeMap::new();
    for (i, h) in headers.iter().enumerate() {
        let name = h.trim().trim_start_matches('\u{feff}').to_ascii_lowercase();
        match COLUMNS.iter().find(|c| **c == name) {
            Some(c) => {
                col.entry(c).or_insert(i);
            }
            None => plan
                .warnings
                .push(format!("unknown column {:?} ignored", h.trim())),
        }
    }
    if !col.contains_key("address") {
        return Err(ImportError::Format(
            "the CSV needs a header row with an `address` column (label,address,port,username,group,tags)"
                .to_owned(),
        ));
    }

    let mut groups: BTreeMap<String, PlanRef> = BTreeMap::new(); // path (lowercase) → ref
    let mut tags: BTreeMap<String, PlanRef> = BTreeMap::new(); // tag key → ref
    let mut hosts: Vec<(PlannedItem, Option<String>, Vec<String>)> = Vec::new();
    for record in reader.records() {
        let record = match record {
            Ok(r) => r,
            Err(e) => {
                let line = e.position().map(|p| p.line());
                plan.skipped.push(Skipped::new(
                    line.map(|l| format!("line {l}")),
                    format!("cannot read the row: {e}"),
                ));
                continue;
            }
        };
        let line = record.position().map_or(0, |p| p.line());
        let at = Some(format!("line {line}"));
        let cell = |c: &str| {
            col.get(c)
                .and_then(|&i| record.get(i))
                .map(str::trim)
                .unwrap_or("")
        };
        if record.iter().all(|c| c.trim().is_empty()) {
            continue;
        }
        let address = match validate_address(cell("address")) {
            Ok(a) => a,
            Err(e) => {
                plan.skipped.push(Skipped::new(
                    at,
                    format!("invalid address {:?}: {}", cell("address"), e.message),
                ));
                continue;
            }
        };
        let port = match cell("port") {
            "" => None,
            p => match p.parse::<u16>() {
                Ok(n) if n > 0 => Some(n),
                _ => {
                    plan.skipped
                        .push(Skipped::new(at, format!("invalid port {p:?}")));
                    continue;
                }
            },
        };
        let label = match cell("label") {
            "" => address.clone(),
            l => l.to_owned(),
        };
        let username = Some(cell("username").to_owned()).filter(|u| !u.is_empty());
        let group = Some(cell("group").trim_matches('/').to_owned()).filter(|g| !g.is_empty());
        let draft = HostDraft {
            label: label.clone(),
            address,
            port,
            username,
            ..HostDraft::default()
        };
        let mut item = PlannedItem::new(ItemKind::Host, label, Draft::Host(Box::new(draft)));
        item.source_line = at;
        hosts.push((item, group, split_tags(cell("tags"))));
    }

    // Groups and tags first (so references point backwards), then hosts.
    for (_, group, _) in &hosts {
        if let Some(path) = group {
            let mut parent: Option<PlanRef> = None;
            let mut prefix = String::new();
            for part in path.split('/').map(str::trim).filter(|p| !p.is_empty()) {
                if !prefix.is_empty() {
                    prefix.push('/');
                }
                prefix.push_str(&part.to_lowercase());
                let r = match groups.get(&prefix) {
                    Some(r) => *r,
                    None => {
                        let r = plan.push(PlannedItem::new(
                            ItemKind::Group,
                            part,
                            Draft::Group(GroupDraft {
                                name: part.to_owned(),
                                parent,
                                ..GroupDraft::default()
                            }),
                        ));
                        groups.insert(prefix.clone(), r);
                        r
                    }
                };
                parent = Some(r);
            }
        }
    }
    for (_, _, host_tags) in &hosts {
        for t in host_tags {
            let key = tag_key(t);
            if let std::collections::btree_map::Entry::Vacant(slot) = tags.entry(key) {
                slot.insert(plan.push(PlannedItem::new(ItemKind::Tag, t, Draft::Tag(t.clone()))));
            }
        }
    }
    for (mut item, group, host_tags) in hosts {
        if let Draft::Host(h) = &mut item.draft {
            h.group = group.and_then(|g| {
                let key: Vec<String> = g
                    .split('/')
                    .map(str::trim)
                    .filter(|p| !p.is_empty())
                    .map(str::to_lowercase)
                    .collect();
                groups.get(&key.join("/")).copied()
            });
            h.tags = host_tags
                .iter()
                .filter_map(|t| tags.get(&tag_key(t)).copied())
                .collect();
        }
        plan.push(item);
    }
    fill_fields(&mut plan);
    Ok(plan)
}
