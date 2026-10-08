//! Workspace invariants read from `cargo metadata` (M0-01 T-04, T-05).
//!
//! - every workspace package is MIT-licensed and declares a `rust-version`;
//! - the crate layering of `tasks/M0-01` §2.3 holds: each crate depends directly
//!   only on the internal crates it is allowed to, and its transitive closure over
//!   *normal* dependencies (all features on) contains none of its forbidden crates;
//! - the local-only binary (`--no-default-features`) links no `sverb-sync`.
//!
//! The CI layering job (M0-02) runs this file.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::{
    collections::{BTreeSet, HashMap, HashSet},
    path::PathBuf,
};

use cargo_metadata::{CargoOpt, DependencyKind, Metadata, MetadataCommand, PackageId};

/// Crates that count as "I/O" for `sverb-crypto`, which must do none.
const IO_CRATES: &[&str] = &[
    "tokio",
    "async-std",
    "smol",
    "mio",
    "hyper",
    "reqwest",
    "rusqlite",
    "sqlx",
    "ratatui",
    "ratatui-core",
    "crossterm",
    "russh",
    "portable-pty",
];

/// One row of the M0-01 §2.3 table.
struct Rule {
    krate: &'static str,
    /// Direct internal (`sverb-*`) normal dependencies allowed. `None` = any.
    allowed_internal: Option<&'static [&'static str]>,
    /// Crates that must not appear anywhere in the normal-dependency closure.
    forbidden: &'static [&'static str],
}

const CLIENT_CRATES: &[&str] = &[
    "sverb-core",
    "sverb-crypto",
    "sverb-proto",
    "sverb-store",
    "sverb-conn",
    "sverb-term",
    "sverb-sync",
    "sverb-tui",
];

const RULES: &[Rule] = &[
    Rule {
        krate: "sverb-crypto",
        allowed_internal: Some(&[]),
        forbidden: IO_CRATES,
    },
    Rule {
        krate: "sverb-proto",
        allowed_internal: Some(&["sverb-crypto"]),
        forbidden: &["ratatui", "crossterm", "rusqlite", "russh"],
    },
    Rule {
        krate: "sverb-core",
        allowed_internal: Some(&["sverb-crypto", "sverb-proto"]),
        forbidden: &["ratatui", "crossterm", "clap"],
    },
    Rule {
        krate: "sverb-store",
        allowed_internal: Some(&["sverb-core", "sverb-crypto"]),
        forbidden: &["ratatui", "crossterm"],
    },
    Rule {
        krate: "sverb-conn",
        // M1-08: the session actor owns a `Box<dyn sverb_term::Emulator>` (task decision).
        allowed_internal: Some(&["sverb-core", "sverb-term"]),
        forbidden: &["ratatui", "crossterm"],
    },
    Rule {
        krate: "sverb-term",
        // M3-05: recordings are sealed with `sverb_crypto::recording` (no I/O crate).
        allowed_internal: Some(&["sverb-core", "sverb-crypto"]),
        forbidden: &["crossterm"],
    },
    Rule {
        krate: "sverb-sync",
        allowed_internal: Some(&["sverb-core", "sverb-store", "sverb-proto", "sverb-crypto"]),
        forbidden: &["ratatui", "crossterm"],
    },
    Rule {
        krate: "sverb-tui",
        allowed_internal: Some(CLIENT_CRATES),
        forbidden: &[],
    },
    Rule {
        krate: "sverb-server",
        allowed_internal: Some(&["sverb-proto", "sverb-crypto"]),
        forbidden: &[
            "sverb-core",
            "sverb-store",
            "sverb-conn",
            "sverb-term",
            "sverb-tui",
            "sverb-sync",
            "ratatui",
            "crossterm",
            "russh",
            "rusqlite",
        ],
    },
    Rule {
        krate: "sverb-e2e",
        allowed_internal: None,
        forbidden: &[],
    },
    Rule {
        krate: "sverb",
        allowed_internal: Some(CLIENT_CRATES),
        forbidden: &["sverb-server"],
    },
];

fn metadata(features: Option<CargoOpt>) -> Metadata {
    let mut cmd = MetadataCommand::new();
    cmd.manifest_path(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../Cargo.toml"));
    if let Some(f) = features {
        cmd.features(f);
    }
    cmd.exec().expect("cargo metadata")
}

/// Normal-dependency graph: package id -> (dependency name, id) pairs.
fn normal_graph(meta: &Metadata) -> HashMap<&PackageId, Vec<(String, &PackageId)>> {
    let resolve = meta.resolve.as_ref().expect("resolve graph");
    resolve
        .nodes
        .iter()
        .map(|node| {
            let deps = node
                .deps
                .iter()
                .filter(|d| d.dep_kinds.iter().any(|k| k.kind == DependencyKind::Normal))
                .map(|d| (meta[&d.pkg].name.to_string(), &d.pkg))
                .collect();
            (&node.id, deps)
        })
        .collect()
}

/// Names of every package reachable from `root` over normal dependencies.
fn closure(
    graph: &HashMap<&PackageId, Vec<(String, &PackageId)>>,
    root: &PackageId,
) -> BTreeSet<String> {
    let mut seen: HashSet<&PackageId> = HashSet::new();
    let mut names = BTreeSet::new();
    let mut stack = vec![root];
    while let Some(id) = stack.pop() {
        for (name, dep) in graph.get(id).into_iter().flatten() {
            if seen.insert(dep) {
                names.insert(name.clone());
                stack.push(dep);
            }
        }
    }
    names
}

fn package_id<'a>(meta: &'a Metadata, name: &str) -> &'a PackageId {
    &meta
        .workspace_packages()
        .into_iter()
        .find(|p| p.name.as_str() == name)
        .unwrap_or_else(|| panic!("workspace package {name} not found"))
        .id
}

/// T-04
#[test]
fn every_package_is_mit_with_rust_version() {
    let meta = metadata(None);
    let mut problems = Vec::new();
    for p in meta.workspace_packages() {
        if p.license.as_deref() != Some("MIT") {
            problems.push(format!("{}: license = {:?}", p.name, p.license));
        }
        if p.rust_version.is_none() {
            problems.push(format!("{}: rust-version not set", p.name));
        }
    }
    assert!(problems.is_empty(), "{problems:#?}");
}

/// Every workspace crate is covered by a layering rule, and every rule names a real crate.
#[test]
fn layering_rules_cover_the_workspace() {
    let meta = metadata(None);
    let actual: BTreeSet<String> = meta
        .workspace_packages()
        .iter()
        .map(|p| p.name.to_string())
        .collect();
    let ruled: BTreeSet<String> = RULES.iter().map(|r| r.krate.to_string()).collect();
    assert_eq!(actual, ruled, "update RULES when adding or removing crates");
}

/// T-05
#[test]
fn dependency_direction_holds() {
    let meta = metadata(Some(CargoOpt::AllFeatures));
    let graph = normal_graph(&meta);
    let mut problems = Vec::new();
    for rule in RULES {
        let id = package_id(&meta, rule.krate);
        if let Some(allowed) = rule.allowed_internal {
            for (name, _) in graph.get(id).into_iter().flatten() {
                if name.starts_with("sverb") && !allowed.contains(&name.as_str()) {
                    problems.push(format!("{} must not depend on {name}", rule.krate));
                }
            }
        }
        let reach = closure(&graph, id);
        for bad in rule.forbidden {
            if reach.contains(*bad) {
                problems.push(format!(
                    "{} (transitively) depends on forbidden {bad}",
                    rule.krate
                ));
            }
        }
    }
    assert!(problems.is_empty(), "{problems:#?}");
}

/// T-02 (graph part): the local-only build links no sync code.
#[test]
fn local_only_binary_has_no_sync() {
    let meta = metadata(Some(CargoOpt::NoDefaultFeatures));
    let graph = normal_graph(&meta);
    let reach = closure(&graph, package_id(&meta, "sverb"));
    assert!(
        !reach.contains("sverb-sync"),
        "sverb --no-default-features pulls in sverb-sync"
    );

    let meta = metadata(None);
    let graph = normal_graph(&meta);
    let reach = closure(&graph, package_id(&meta, "sverb"));
    assert!(
        reach.contains("sverb-sync"),
        "the default build must include sync"
    );
}

// M0-05 T-11: the template's panic crates are gone. `libc` itself stays in the graph
// (tokio, crossterm, … use it), so for `libc` only a *direct* dependency is checked.
#[test]
fn template_panic_crates_are_removed() {
    const REMOVED: &[&str] = &["human-panic", "better-panic", "libc"];
    let meta = metadata(Some(CargoOpt::AllFeatures));
    let sverb = meta
        .workspace_packages()
        .into_iter()
        .find(|p| p.name.as_str() == "sverb")
        .expect("sverb package");
    let direct: Vec<&str> = sverb
        .dependencies
        .iter()
        .map(|d| d.name.as_str())
        .filter(|name| REMOVED.contains(name))
        .collect();
    assert!(direct.is_empty(), "sverb still depends on {direct:?}");

    let graph = normal_graph(&meta);
    let reach = closure(&graph, package_id(&meta, "sverb"));
    for name in ["human-panic", "better-panic"] {
        assert!(
            !reach.contains(name),
            "sverb (transitively) depends on {name}"
        );
    }
}
