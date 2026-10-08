//! `known_hosts` import (§9.5, §9.13), reusing the M1-15 parser: hashed entries stay
//! hashed, `@cert-authority` / `@revoked` markers are kept, entries already in the
//! vault (same pattern and key) are duplicates, and repeated lines in the file are
//! skipped.

use super::{Draft, ImportPlan, ImportSource, PlannedItem, Skipped, preview::fill_fields};
use crate::known_hosts::parse_known_hosts;
use crate::model::{ItemKind, KnownHost};

/// A display label: the pattern (hashed ones shortened) and the key type.
fn label(k: &KnownHost) -> String {
    let pattern = if k.host_pattern.starts_with("|1|") {
        let short: String = k.host_pattern.chars().take(12).collect();
        format!("{short}… (hashed)")
    } else {
        k.host_pattern.clone()
    };
    format!("{pattern} {}", k.key_type)
}

/// Parses a `known_hosts` file into a plan (all items `New`).
pub fn parse(text: &str) -> ImportPlan {
    let mut plan = ImportPlan::new(ImportSource::KnownHosts);
    let (entries, warnings) = parse_known_hosts(text);
    for w in warnings {
        if w.reason.ends_with("(kept as is)") {
            plan.warnings.push(format!("line {}: {}", w.line, w.reason));
        } else {
            plan.skipped
                .push(Skipped::new(Some(format!("line {}", w.line)), w.reason));
        }
    }
    let mut seen: Vec<(String, String, String)> = Vec::new();
    for entry in entries {
        let key = (
            entry.host_pattern.clone(),
            entry.key_type.clone(),
            entry.public_key.clone(),
        );
        if seen.contains(&key) {
            plan.skipped.push(Skipped::new(
                None,
                format!("{}: repeated in the file", label(&entry)),
            ));
            continue;
        }
        seen.push(key);
        plan.push(PlannedItem::new(
            ItemKind::KnownHost,
            label(&entry),
            Draft::KnownHost(entry),
        ));
    }
    fill_fields(&mut plan);
    plan
}
