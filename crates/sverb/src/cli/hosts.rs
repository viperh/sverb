//! M0-07 / M1-07: `sverb hosts list | add | rm` (SPEC §16).
//!
//! The vault is unlocked through [`require_unlocked`](super::vault::require_unlocked)
//! (keyring, else the master password on a TTY, else exit 3). Writes go through the
//! TUI's item service (`ItemOps`: HLC-stamped, sealed with the vault key, marked
//! dirty for a future sync).
//!
//! - `list [--json] [--tag t]... [--group g]`: a table of label, address, port, user,
//!   group and tags; JSON is `{"version":1,"data":[{id,label,address,port,user,group,tags}]}`.
//!   Secrets are never printed.
//! - `add <address> [--label] [--user] [--port] [--group g] [--create-group] [--tag t]...`:
//!   validates (exit 2), creates missing tags by name, and fails with exit 4 on an
//!   unknown group unless `--create-group` creates it. Prints the new id.
//! - `rm <host> [--yes]`: resolves the host (label, address, unique fuzzy match;
//!   ambiguous → exit 4 listing candidates), confirms on a TTY, tombstones it.
//!   Without a TTY `--yes` is required.

use std::collections::BTreeMap;
use std::io::{BufRead, Write};
use std::sync::Arc;

use clap::Subcommand;
use serde::Serialize;
use sverb_core::error_report::ErrorReport;
use sverb_core::model::{Group, Host, ItemId, ItemKind, Tag, validate::validate_address};
use sverb_core::search::{ItemIndex, resolve_host_arg};
use sverb_tui::services::vault::items::{ItemError, ItemOps};

use super::{CliError, Ctx, output, vault::require_unlocked, write_out};

/// `sverb hosts …`
#[derive(Subcommand, Debug, PartialEq, Eq)]
pub(crate) enum HostsCmd {
    /// List hosts
    List {
        /// Print JSON (`{"version":1,"data":…}`)
        #[arg(long)]
        json: bool,
        /// Only hosts with this tag (repeatable; all must match)
        #[arg(long = "tag", value_name = "TAG")]
        tags: Vec<String>,
        /// Only hosts in this group
        #[arg(long, value_name = "GROUP")]
        group: Option<String>,
    },
    /// Add a host
    Add {
        /// Hostname or IP address
        address: String,
        /// Display label (defaults to the address)
        #[arg(long)]
        label: Option<String>,
        /// Login user
        #[arg(long)]
        user: Option<String>,
        /// SSH port
        #[arg(long, value_parser = clap::value_parser!(u16).range(1..))]
        port: Option<u16>,
        /// Group to put the host in (must exist unless --create-group)
        #[arg(long)]
        group: Option<String>,
        /// Create the group if it does not exist
        #[arg(long, requires = "group")]
        create_group: bool,
        /// Tag (repeatable; missing tags are created)
        #[arg(long = "tag", value_name = "TAG")]
        tags: Vec<String>,
    },
    /// Remove a host
    Rm {
        /// Label, address or unique fuzzy match
        host: String,
        /// Do not ask for confirmation (required without a terminal)
        #[arg(long, short = 'y')]
        yes: bool,
    },
}

pub(crate) async fn run(cmd: HostsCmd, ctx: &Ctx, out: &mut dyn Write) -> Result<u8, CliError> {
    let unlocked = require_unlocked(ctx).await?;
    let ops = ItemOps::new(unlocked.engine, Arc::new(unlocked.vault));
    let tty = ctx.tty.stdin && ctx.tty.stderr;
    run_with(cmd, &ops, tty, &mut || read_yes(), out).await
}

/// `y`/`yes` on stdin.
fn read_yes() -> bool {
    let mut line = String::new();
    std::io::stdin().lock().read_line(&mut line).is_ok()
        && matches!(line.trim().to_lowercase().as_str(), "y" | "yes")
}

fn item_error(e: ItemError) -> CliError {
    match e {
        ItemError::Invalid(errors) => CliError::Usage(
            errors
                .iter()
                .map(|e| e.message.clone())
                .collect::<Vec<_>>()
                .join("; "),
        ),
        ItemError::NotFound => CliError::NotFound(e.to_string()),
        other => CliError::Failure(ErrorReport::msg(other.to_string())),
    }
}

/// One `hosts list --json` entry.
#[derive(Debug, Serialize, PartialEq, Eq)]
pub(crate) struct HostJson {
    id: String,
    label: String,
    address: String,
    port: u16,
    user: Option<String>,
    group: Option<String>,
    tags: Vec<String>,
}

/// Names of the items of `kind` by id.
async fn names(ops: &ItemOps, kind: ItemKind) -> Result<BTreeMap<ItemId, String>, CliError> {
    let items = ops.list(&[kind]).await.map_err(item_error)?;
    Ok(items
        .into_iter()
        .filter_map(|i| {
            let name = match kind {
                ItemKind::Tag => Tag::try_from(&i.body).ok().map(|t| t.name),
                ItemKind::Group => Group::try_from(&i.body).ok().map(|g| g.name),
                _ => None,
            }?;
            Some((i.id, name))
        })
        .collect())
}

fn find_by_name(map: &BTreeMap<ItemId, String>, name: &str) -> Option<ItemId> {
    map.iter()
        .find(|(_, n)| n.eq_ignore_ascii_case(name))
        .map(|(id, _)| *id)
}

/// The command body, with the vault already unlocked (tests call this).
pub(crate) async fn run_with(
    cmd: HostsCmd,
    ops: &ItemOps,
    tty: bool,
    confirm: &mut dyn FnMut() -> bool,
    out: &mut dyn Write,
) -> Result<u8, CliError> {
    match cmd {
        HostsCmd::List { json, tags, group } => list(ops, json, &tags, group.as_deref(), out).await,
        HostsCmd::Add {
            address,
            label,
            user,
            port,
            group,
            create_group,
            tags,
        } => {
            let id = add(
                ops,
                AddArgs {
                    address,
                    label,
                    user,
                    port,
                    group,
                    create_group,
                    tags,
                },
            )
            .await?;
            write_out(out, &format!("{id}\n"))?;
            Ok(super::exit::OK)
        }
        HostsCmd::Rm { host, yes } => rm(ops, &host, yes, tty, confirm, out).await,
    }
}

async fn list(
    ops: &ItemOps,
    json: bool,
    tags: &[String],
    group: Option<&str>,
    out: &mut dyn Write,
) -> Result<u8, CliError> {
    let tag_names = names(ops, ItemKind::Tag).await?;
    let group_names = names(ops, ItemKind::Group).await?;
    let mut hosts = Vec::new();
    for item in ops.list(&[ItemKind::Host]).await.map_err(item_error)? {
        let Ok(h) = Host::try_from(&item.body) else {
            continue;
        };
        let host_tags: Vec<String> = h
            .tags
            .iter()
            .filter_map(|t| tag_names.get(t).cloned())
            .collect();
        let host_group = h.group_id.and_then(|g| group_names.get(&g).cloned());
        let tags_ok = tags
            .iter()
            .all(|want| host_tags.iter().any(|t| t.eq_ignore_ascii_case(want)));
        let group_ok = group.is_none_or(|g| {
            host_group
                .as_deref()
                .is_some_and(|hg| hg.eq_ignore_ascii_case(g))
        });
        if !(tags_ok && group_ok) {
            continue;
        }
        hosts.push(HostJson {
            id: item.id.to_string(),
            label: h.display_label().to_owned(),
            address: h.address.clone(),
            port: h.port_or_default(),
            user: h.username.clone(),
            group: host_group,
            tags: host_tags,
        });
    }
    hosts.sort_by(|a, b| {
        a.label
            .to_lowercase()
            .cmp(&b.label.to_lowercase())
            .then_with(|| a.id.cmp(&b.id))
    });
    if json {
        output::write_json(out, &hosts)?;
        return Ok(super::exit::OK);
    }
    write_out(out, &table(&hosts))?;
    Ok(super::exit::OK)
}

fn table(hosts: &[HostJson]) -> String {
    let header = ["LABEL", "ADDRESS", "PORT", "USER", "GROUP", "TAGS"];
    let rows: Vec<[String; 6]> = hosts
        .iter()
        .map(|h| {
            [
                h.label.clone(),
                h.address.clone(),
                h.port.to_string(),
                h.user.clone().unwrap_or_else(|| "-".into()),
                h.group.clone().unwrap_or_else(|| "-".into()),
                if h.tags.is_empty() {
                    "-".into()
                } else {
                    h.tags.join(",")
                },
            ]
        })
        .collect();
    let mut widths = header.map(|h| h.chars().count());
    for r in &rows {
        for (w, c) in widths.iter_mut().zip(r) {
            *w = (*w).max(c.chars().count());
        }
    }
    let line = |cells: &[String]| {
        let parts: Vec<String> = cells
            .iter()
            .zip(widths)
            .map(|(c, w)| format!("{c:<w$}"))
            .collect();
        format!("{}\n", parts.join("  ").trim_end())
    };
    let mut s = line(&header.map(str::to_owned));
    for r in &rows {
        s.push_str(&line(r));
    }
    s
}

struct AddArgs {
    address: String,
    label: Option<String>,
    user: Option<String>,
    port: Option<u16>,
    group: Option<String>,
    create_group: bool,
    tags: Vec<String>,
}

async fn add(ops: &ItemOps, a: AddArgs) -> Result<ItemId, CliError> {
    // Validate before creating tags or groups.
    let address = validate_address(a.address.trim())
        .map_err(|e| CliError::Usage(format!("invalid address {:?}: {}", a.address, e.message)))?;
    if a.user
        .as_deref()
        .is_some_and(|u| u.is_empty() || u.chars().any(char::is_whitespace))
    {
        return Err(CliError::Usage("invalid user name".into()));
    }
    let group_id = match &a.group {
        None => None,
        Some(name) => match find_by_name(&names(ops, ItemKind::Group).await?, name) {
            Some(id) => Some(id),
            None if a.create_group => {
                let g = Group {
                    name: name.clone(),
                    ..Group::default()
                };
                let w = ops
                    .save(ItemKind::Group, None, None, move |body, clock, device| {
                        g.apply_to(body, clock, device);
                        Ok(())
                    })
                    .await
                    .map_err(item_error)?;
                Some(w.id)
            }
            None => {
                return Err(CliError::NotFound(format!(
                    "no group named {name:?} (use --create-group to create it)"
                )));
            }
        },
    };
    let mut tag_names = names(ops, ItemKind::Tag).await?;
    let mut tag_ids = Vec::new();
    for name in &a.tags {
        let name = name.trim();
        if name.is_empty() {
            return Err(CliError::Usage("empty tag name".into()));
        }
        let id = match find_by_name(&tag_names, name) {
            Some(id) => id,
            None => {
                let t = Tag {
                    name: name.to_owned(),
                    ..Tag::default()
                };
                let w = ops
                    .save(ItemKind::Tag, None, None, move |body, clock, device| {
                        t.apply_to(body, clock, device);
                        Ok(())
                    })
                    .await
                    .map_err(item_error)?;
                tag_names.insert(w.id, name.to_owned());
                w.id
            }
        };
        if !tag_ids.contains(&id) {
            tag_ids.push(id);
        }
    }
    let host = Host {
        label: a.label.unwrap_or_default(),
        address,
        port: a.port,
        group_id,
        tags: tag_ids,
        username: a.user,
        ..Host::default()
    };
    let w = ops
        .save(ItemKind::Host, None, None, move |body, clock, device| {
            host.apply_to(body, clock, device);
            Ok(())
        })
        .await
        .map_err(item_error)?;
    Ok(w.id)
}

async fn rm(
    ops: &ItemOps,
    arg: &str,
    yes: bool,
    tty: bool,
    confirm: &mut dyn FnMut() -> bool,
    out: &mut dyn Write,
) -> Result<u8, CliError> {
    let hosts = ops.list(&[ItemKind::Host]).await.map_err(item_error)?;
    let mut index = ItemIndex::build(hosts.iter().map(|h| (h.id, h.vault, &h.body)));
    let id = resolve_host_arg(&index.snapshot(), arg)?;
    let label = hosts
        .iter()
        .find(|h| h.id == id)
        .and_then(|h| Host::try_from(&h.body).ok())
        .map(|h| h.display_label().to_owned())
        .unwrap_or_default();
    if !yes {
        if !tty {
            return Err(CliError::Usage(
                "refusing to remove a host without a terminal to confirm; pass --yes".into(),
            ));
        }
        eprint!("Remove host {label:?}? [y/N] ");
        let _ = std::io::stderr().flush();
        if !confirm() {
            eprintln!("Cancelled.");
            return Ok(super::exit::OK);
        }
    }
    ops.delete(id).await.map_err(item_error)?;
    write_out(out, &format!("removed {label}\n"))?;
    Ok(super::exit::OK)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    use sverb_core::secret::SecretString;
    use sverb_core::vault::{Argon2Cost, MemKeyring};
    use sverb_store::Store;
    use sverb_tui::services::vault::VaultEngine;

    use super::*;

    const PW: &str = "correct horse battery staple violin";

    struct Home(PathBuf);

    impl Drop for Home {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    async fn ops(tag: &str) -> (ItemOps, Home) {
        static N: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "sverb-m1-07-cli-{tag}-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::SeqCst)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let store =
            Store::open_at(dir.join("sverb.db"), Arc::new(sverb_store::SystemClock)).unwrap();
        let engine = VaultEngine::new(store, Arc::new(MemKeyring::new()), Argon2Cost::TEST);
        let vault = engine.initialize(PW, false).await.unwrap().vault;
        (ItemOps::new(engine, Arc::new(vault)), Home(dir))
    }

    async fn run(ops: &ItemOps, args: &str) -> (Result<u8, CliError>, String) {
        let cli = super::super::Cli::try_parse_with(
            &sverb_core::paths::Paths::resolve(
                &sverb_core::paths::MapEnv::new().var("SVERB_HOME", "/nonexistent"),
            )
            .unwrap(),
            std::iter::once("sverb").chain(args.split_whitespace()),
        )
        .unwrap();
        let Some(super::super::Command::Hosts(cmd)) = cli.command else {
            panic!("not a hosts command");
        };
        let mut out = Vec::new();
        let res = run_with(cmd, ops, false, &mut || true, &mut out).await;
        (res, String::from_utf8(out).unwrap())
    }

    // T-13
    #[tokio::test]
    async fn t13_add_then_list_json() {
        let (ops, _home) = ops("t13").await;
        let (res, out) = run(&ops, "hosts add 10.0.0.1 --user root --port 2222 --tag web").await;
        assert_eq!(res, Ok(0));
        let id = out.trim().to_owned();
        assert!(id.parse::<ItemId>().is_ok(), "{out}");
        let (res, out) = run(&ops, "hosts list --json").await;
        assert_eq!(res, Ok(0));
        let expected = format!(
            "{{\"version\":1,\"data\":[{{\"id\":\"{id}\",\"label\":\"10.0.0.1\",\"address\":\"10.0.0.1\",\
             \"port\":2222,\"user\":\"root\",\"group\":null,\"tags\":[\"web\"]}}]}}\n"
        );
        assert_eq!(out, expected);
        // A second add reuses the tag; filters work.
        run(&ops, "hosts add db.internal --label db --tag WEB --tag db")
            .await
            .0
            .unwrap();
        let (_, out) = run(&ops, "hosts list --tag db").await;
        assert!(
            out.contains("db.internal") && !out.contains("10.0.0.1"),
            "{out}"
        );
        assert_eq!(names(&ops, ItemKind::Tag).await.unwrap().len(), 2);
        let (_, table) = run(&ops, "hosts list").await;
        assert!(table.starts_with("LABEL"), "{table}");
        let row: Vec<&str> = table.lines().nth(1).unwrap().split_whitespace().collect();
        assert_eq!(
            row,
            ["10.0.0.1", "10.0.0.1", "2222", "root", "-", "web"],
            "{table}"
        );
    }

    // T-14
    #[tokio::test]
    async fn t14_invalid_address_exits_2() {
        let (ops, _home) = ops("t14").await;
        for bad in ["bad\u{20}host", "root@x", "h:22"] {
            let cmd = HostsCmd::Add {
                address: bad.into(),
                label: None,
                user: None,
                port: None,
                group: None,
                create_group: false,
                tags: vec!["web".into()],
            };
            let res = run_with(cmd, &ops, false, &mut || true, &mut Vec::new()).await;
            let err = res.unwrap_err();
            assert_eq!(err.exit_code(), 2, "{bad}: {err}");
            assert!(err.to_string().contains("invalid address"), "{err}");
        }
        assert!(
            names(&ops, ItemKind::Tag).await.unwrap().is_empty(),
            "nothing created"
        );
    }

    // T-15
    #[tokio::test]
    async fn t15_unknown_group_exits_4_unless_created() {
        let (ops, _home) = ops("t15").await;
        let (res, _) = run(&ops, "hosts add x --group nope").await;
        let err = res.unwrap_err();
        assert_eq!(err.exit_code(), 4);
        assert!(err.to_string().contains("--create-group"));
        let (res, _) = run(&ops, "hosts add x --group nope --create-group").await;
        assert_eq!(res, Ok(0));
        let (_, out) = run(&ops, "hosts list --group nope --json").await;
        assert!(out.contains("\"group\":\"nope\""), "{out}");
        // The group exists now: no second one is created.
        run(&ops, "hosts add y --group nope --create-group")
            .await
            .0
            .unwrap();
        assert_eq!(names(&ops, ItemKind::Group).await.unwrap().len(), 1);
    }

    // T-16
    #[tokio::test]
    async fn t16_rm_ambiguous_then_exact() {
        let (ops, _home) = ops("t16").await;
        for args in [
            "hosts add 10.0.0.1 --label prod-web-1",
            "hosts add 10.0.0.2 --label prod-web-2",
            "hosts add 10.0.0.3 --label db",
        ] {
            run(&ops, args).await.0.unwrap();
        }
        let (res, _) = run(&ops, "hosts rm web").await;
        let err = res.unwrap_err();
        assert_eq!(err.exit_code(), 4);
        let msg = err.to_string();
        assert!(
            msg.contains("prod-web-1") && msg.contains("prod-web-2"),
            "{msg}"
        );
        // Without a terminal, --yes is required.
        let (res, _) = run(&ops, "hosts rm prod-web-1").await;
        assert_eq!(res.unwrap_err().exit_code(), 2);
        let (res, out) = run(&ops, "hosts rm prod-web-1 --yes").await;
        assert_eq!(res, Ok(0));
        assert!(out.contains("removed prod-web-1"));
        let (_, out) = run(&ops, "hosts list").await;
        assert!(!out.contains("prod-web-1") && out.contains("prod-web-2"));
        // A declined confirmation on a TTY keeps the host.
        let cmd = HostsCmd::Rm {
            host: "db".into(),
            yes: false,
        };
        assert_eq!(
            run_with(cmd, &ops, true, &mut || false, &mut Vec::new()).await,
            Ok(0)
        );
        assert!(run(&ops, "hosts list").await.1.contains("db"));
    }

    // T-17
    #[tokio::test]
    async fn t17_list_never_prints_secrets() {
        let (ops, _home) = ops("t17").await;
        let host = Host {
            label: "vault-db".into(),
            address: "10.0.0.7".into(),
            password: Some(SecretString::from("CANARY-SECRET-PW")),
            ..Host::default()
        };
        ops.save(ItemKind::Host, None, None, move |b, c, d| {
            host.apply_to(b, c, d);
            Ok(())
        })
        .await
        .unwrap();
        for args in ["hosts list", "hosts list --json"] {
            let (res, out) = run(&ops, args).await;
            assert_eq!(res, Ok(0));
            assert!(out.contains("vault-db"));
            assert!(!out.contains("CANARY"), "{args}: {out}");
        }
    }
}
