//! `sverb snippet run <snippet> --on <host|#tag|group>... [--json]
//! [--var name=value]... [--concurrency N] [--timeout S]` (SPEC §16, §9.7).
//!
//! - Always *Exec on hosts*, whatever the snippet's `run_mode`.
//! - `<snippet>`: an item id or the snippet's name (exact, else a unique
//!   case-insensitive match).
//! - `--on`: `#tag` → hosts with the tag, a group name → every host in the group and its
//!   subgroups, otherwise host resolution (label, address, unique fuzzy). Deduplicated
//!   (`sverb_core::snippet::targets`).
//! - Variables: `--var name=value` (repeatable), then defaults. Missing ones are asked
//!   on a terminal (secret ones without echo); without a terminal the command exits 2
//!   listing them.
//! - Runs at most `--concurrency` hosts at a time (default 10), each command limited
//!   to `--timeout` seconds (default `ssh.exec_timeout_secs`). Host keys must already
//!   be known and credentials stored: prompts are refused (the host's row says why).
//! - Output: per-host blocks (`== host (exit 0, 1.2s) ==`, stdout, stderr), or with
//!   `--json` `{"version":1,"data":[{host, exit, signal, stdout, stderr, truncated,
//!   duration_ms}]}` (`stdout_b64`/`stderr_b64` when a stream is not UTF-8).
//! - Exit code: 0 all ok, 7 some failed, 1 all failed.

use std::collections::BTreeMap;
use std::io::{BufRead, Write};
use std::sync::Arc;
use std::time::Duration;

use clap::Subcommand;
use sverb_conn::ssh::exec::snippets::{
    HostExecutor, RunJob, RunTarget, SNIPPET_CONCURRENCY, SshExecutor, run_on_hosts, today,
};
use sverb_core::error_report::ErrorReport;
use sverb_core::model::{Group, Host, ItemId, ItemKind, Snippet, Tag, VarDef};
use sverb_core::snippet::{
    Summary, TargetCatalog, TargetError, TargetHost, Template, Values, effective_vars, missing,
    results, with_defaults,
};
use sverb_tui::services::vault::{
    VaultService,
    items::{ItemError, ItemOps},
};

use super::{CliError, Ctx, exit, vault::require_unlocked, write_out};

/// `sverb snippet …`
#[derive(Subcommand, Debug, PartialEq, Eq)]
pub(crate) enum SnippetCmd {
    /// Run a snippet on one or more hosts
    Run {
        /// Snippet name or id
        snippet: String,
        /// Target: a host, `#tag` or group (repeatable)
        #[arg(long = "on", value_name = "HOST|#TAG|GROUP", required = true)]
        on: Vec<String>,
        /// Print JSON (`{"version":1,"data":…}`)
        #[arg(long)]
        json: bool,
        /// A variable value, `name=value` (repeatable)
        #[arg(long = "var", value_name = "NAME=VALUE")]
        vars: Vec<String>,
        /// Hosts worked on at once (default 10)
        #[arg(long, value_parser = clap::value_parser!(u64).range(1..))]
        concurrency: Option<u64>,
        /// Seconds per command (default `ssh.exec_timeout_secs`)
        #[arg(long, value_name = "S", value_parser = clap::value_parser!(u64).range(1..))]
        timeout: Option<u64>,
    },
}

/// What `snippet run` was asked to do.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct RunArgs {
    pub snippet: String,
    pub on: Vec<String>,
    pub json: bool,
    /// `name=value`
    pub vars: Vec<String>,
    pub concurrency: Option<usize>,
    pub timeout_secs: Option<u64>,
}

/// Asks for a missing variable on the terminal (`None`: no terminal / cancelled).
pub(crate) type AskVar<'a> = &'a mut dyn FnMut(&VarDef) -> Option<String>;

/// `sverb snippet …`
pub(crate) async fn run(cmd: SnippetCmd, ctx: &Ctx, out: &mut dyn Write) -> Result<u8, CliError> {
    match cmd {
        SnippetCmd::Run {
            snippet,
            on,
            json,
            vars,
            concurrency,
            timeout,
        } => {
            let args = RunArgs {
                snippet,
                on,
                json,
                vars,
                concurrency: concurrency.and_then(|c| usize::try_from(c).ok()),
                timeout_secs: timeout,
            };
            run_args(args, ctx, out).await
        }
    }
}

/// Unlock, connect through the vault, run.
pub(crate) async fn run_args(
    args: RunArgs,
    ctx: &Ctx,
    out: &mut dyn Write,
) -> Result<u8, CliError> {
    let unlocked = require_unlocked(ctx).await?;
    let vault = VaultService::from_unlocked(unlocked.engine, unlocked.vault);
    let ops = vault
        .item_ops()
        .ok_or_else(|| CliError::Failure(ErrorReport::msg("the vault is locked")))?;
    let config = Arc::new(ctx.config.clone());
    let connector = Arc::new(sverb_tui::services::ssh::ssh_connector(
        Some(vault),
        Arc::clone(&config),
    ));
    let executor: Arc<dyn HostExecutor> = Arc::new(SshExecutor::new(connector));
    let tty = ctx.tty.stdin && ctx.tty.stderr;
    let default_timeout = u64::from(ctx.config.ssh.exec_timeout_secs.max(1));
    let mut ask = ask_var;
    let ask: Option<AskVar<'_>> = if tty { Some(&mut ask) } else { None };
    run_with(args, &ops, executor, default_timeout, ask, out).await
}

/// Read one variable from the terminal (secret ones without echo).
fn ask_var(v: &VarDef) -> Option<String> {
    if v.secret {
        return super::vault::read_secret(&format!("{} (secret): ", v.name))
            .ok()
            .map(|s| s.to_string());
    }
    eprint!("{}: ", v.name);
    let _ = std::io::stderr().flush();
    let mut line = String::new();
    std::io::stdin().lock().read_line(&mut line).ok()?;
    if line.is_empty() {
        return None; // EOF
    }
    Some(line.trim_end_matches(['\r', '\n']).to_owned())
}

fn item_error(e: ItemError) -> CliError {
    CliError::Failure(ErrorReport::msg(e.to_string()))
}

/// The snippet named `arg` (id, exact name, unique case-insensitive name).
fn find_snippet(snippets: &[(ItemId, Snippet)], arg: &str) -> Result<(ItemId, Snippet), CliError> {
    if let Ok(id) = arg.parse::<ItemId>()
        && let Some(s) = snippets.iter().find(|(i, _)| *i == id)
    {
        return Ok(s.clone());
    }
    let exact: Vec<_> = snippets.iter().filter(|(_, s)| s.name == arg).collect();
    if let [one] = exact.as_slice() {
        return Ok((*one).clone());
    }
    let folded: Vec<_> = snippets
        .iter()
        .filter(|(_, s)| s.name.eq_ignore_ascii_case(arg))
        .collect();
    match folded.as_slice() {
        [one] => Ok((*one).clone()),
        [] => Err(CliError::NotFound(format!("no snippet named `{arg}`"))),
        many => Err(CliError::NotFound(format!(
            "`{arg}` matches {} snippets; use the id: {}",
            many.len(),
            many.iter()
                .map(|(id, s)| format!("{} ({id})", s.name))
                .collect::<Vec<_>>()
                .join(", ")
        ))),
    }
}

/// Hosts, tags and groups of the vault.
async fn catalog(ops: &ItemOps) -> Result<(TargetCatalog, BTreeMap<ItemId, String>), CliError> {
    let items = ops
        .list(&[ItemKind::Host, ItemKind::Tag, ItemKind::Group])
        .await
        .map_err(item_error)?;
    let mut c = TargetCatalog::default();
    let mut labels = BTreeMap::new();
    for item in items {
        match item.body.kind {
            ItemKind::Host => {
                if let Ok(h) = Host::try_from(&item.body) {
                    labels.insert(item.id, h.display_label().to_owned());
                    c.hosts.push(TargetHost {
                        id: item.id,
                        label: h.display_label().to_owned(),
                        address: h.address.clone(),
                        group: h.group_id,
                        tags: h.tags.clone(),
                    });
                }
            }
            ItemKind::Tag => {
                if let Ok(t) = Tag::try_from(&item.body) {
                    c.tags.insert(item.id, t.name);
                }
            }
            ItemKind::Group => {
                if let Ok(g) = Group::try_from(&item.body)
                    && !g.is_vault_defaults
                {
                    c.groups.insert(item.id, (g.name, g.parent_id));
                }
            }
            _ => {}
        }
    }
    Ok((c, labels))
}

fn target_error(e: TargetError) -> CliError {
    match e {
        TargetError::Host(h) => CliError::HostArg(h),
        other => CliError::NotFound(other.to_string()),
    }
}

/// Parse `name=value` pairs.
fn parse_vars(pairs: &[String], vars: &[VarDef]) -> Result<Values, CliError> {
    let mut values = Values::new();
    for pair in pairs {
        let Some((name, value)) = pair.split_once('=') else {
            return Err(CliError::Usage(format!(
                "--var expects name=value, got `{pair}`"
            )));
        };
        let name = name.trim();
        let Some(def) = vars.iter().find(|v| v.name == name) else {
            return Err(CliError::Usage(format!(
                "the snippet has no variable `{name}` (it has: {})",
                vars.iter()
                    .map(|v| v.name.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            )));
        };
        values.set(name, value, def.secret);
    }
    Ok(values)
}

/// The command with the vault open (tests call this with a fake executor).
pub(crate) async fn run_with(
    args: RunArgs,
    ops: &ItemOps,
    executor: Arc<dyn HostExecutor>,
    default_timeout_secs: u64,
    mut ask: Option<AskVar<'_>>,
    out: &mut dyn Write,
) -> Result<u8, CliError> {
    let snippets: Vec<(ItemId, Snippet)> = ops
        .list(&[ItemKind::Snippet])
        .await
        .map_err(item_error)?
        .into_iter()
        .filter_map(|i| Snippet::try_from(&i.body).ok().map(|s| (i.id, s)))
        .collect();
    let (snippet_id, snippet) = find_snippet(&snippets, &args.snippet)?;
    let template = Template::parse(&snippet.script).map_err(|e| {
        CliError::Failure(ErrorReport::msg(format!(
            "snippet `{}` does not parse: {e}",
            snippet.name
        )))
    })?;
    let vars = effective_vars(&template, &snippet.variables);
    let mut given = parse_vars(&args.vars, &vars)?;
    let absent = missing(&vars, &given);
    if !absent.is_empty() {
        match ask.as_mut() {
            Some(ask) => {
                for name in &absent {
                    let Some(def) = vars.iter().find(|v| &v.name == name) else {
                        continue;
                    };
                    let Some(value) = ask(def) else {
                        return Err(CliError::Usage(format!("no value for variable `{name}`")));
                    };
                    given.set(name.clone(), &value, def.secret);
                }
            }
            None => {
                return Err(CliError::Usage(format!(
                    "missing values for variables: {} (pass --var name=value)",
                    absent.join(", ")
                )));
            }
        }
    }
    let values = with_defaults(&vars, &given);
    let (catalog, labels) = catalog(ops).await?;
    let hosts = catalog.resolve(&args.on).map_err(target_error)?;
    let targets: Vec<RunTarget> = hosts
        .iter()
        .enumerate()
        .map(|(index, id)| RunTarget {
            index,
            host_id: Some(*id),
            label: labels.get(id).cloned().unwrap_or_default(),
        })
        .collect();
    let job = Arc::new(RunJob {
        snippet: Some(snippet_id),
        template,
        values,
        date: today(),
        timeout: Duration::from_secs(args.timeout_secs.unwrap_or(default_timeout_secs).max(1)),
    });
    let concurrency = args.concurrency.unwrap_or(SNIPPET_CONCURRENCY).max(1);
    let results = run_on_hosts(executor, job, targets, concurrency, Arc::new(|_| {})).await;
    if args.json {
        let mut text = results::to_json_string(&results);
        text.push('\n');
        write_out(out, &text)?;
    } else {
        write_out(out, &results::to_text(&results))?;
    }
    Ok(match results::summarize(&results) {
        Summary::AllOk => exit::OK,
        Summary::Partial => exit::PARTIAL,
        Summary::AllFailed => exit::FAILURE,
    })
}

#[cfg(test)]
#[path = "snippet_tests.rs"]
mod tests;
