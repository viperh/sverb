//! The Hosts detail pane: every field of the selected host, notes rendered as
//! plain Markdown text (bold / italic / code / list styling only; links shown with
//! their URL, not clickable), last connected (relative) and the vault.

use ratatui::{
    style::{Modifier, Style},
    text::{Line, Span},
};

use sverb_core::model::ItemId;
use sverb_core::resolve::{GlobalDefaults, ResolvedHost, SettingKey, Source};

use super::catalog::{HostCatalog, HostSummary};
use crate::theme::Theme;

/// "3 minutes ago", relative to `now` (both UNIX ms).
pub fn relative_time(then: i64, now: i64) -> String {
    let secs = (now - then).max(0) / 1000;
    let (n, unit) = match secs {
        0..=59 => return "just now".to_owned(),
        60..=3_599 => (secs / 60, "minute"),
        3_600..=86_399 => (secs / 3_600, "hour"),
        86_400..=2_591_999 => (secs / 86_400, "day"),
        2_592_000..=31_535_999 => (secs / 2_592_000, "month"),
        _ => (secs / 31_536_000, "year"),
    };
    let s = if n == 1 { "" } else { "s" };
    format!("{n} {unit}{s} ago")
}

fn row(label: &str, value: impl Into<String>, theme: &Theme) -> Line<'static> {
    Line::from(vec![
        Span::styled(format!("{label:<14}"), theme.dim),
        Span::styled(value.into(), theme.base),
    ])
}

fn inherited(label: &str, value: impl Into<String>, theme: &Theme) -> Line<'static> {
    Line::from(vec![
        Span::styled(format!("{label:<14}"), theme.dim),
        Span::styled(value.into(), theme.dim),
    ])
}

fn yes_no(v: bool) -> &'static str {
    if v { "yes" } else { "no" }
}

/// The detail lines for `host`.
pub fn host_lines(host: &HostSummary, catalog: &HostCatalog, theme: &Theme) -> Vec<Line<'static>> {
    let mut lines = Vec::new();
    let name = |map: &std::collections::BTreeMap<sverb_core::model::ItemId, String>,
                id: sverb_core::model::ItemId| {
        map.get(&id)
            .cloned()
            .unwrap_or_else(|| format!("(missing {})", id.short()))
    };
    // Values the host doesn't set show where they come from.
    let r = catalog.resolve(host, &GlobalDefaults::default());
    lines.push(row("Label", host.display_label().to_owned(), theme));
    lines.push(row("Address", host.address.clone(), theme));
    match host.port {
        Some(p) => lines.push(row("Port", p.to_string(), theme)),
        None => lines.push(inherited(
            "Port",
            with_source(r.port.to_string(), r.source(SettingKey::Port)),
            theme,
        )),
    }
    match (&r.username, r.source(SettingKey::Username)) {
        (Some(u), Source::Host) if host.username.as_deref().is_some_and(|x| !x.is_empty()) => {
            lines.push(row("User", u.clone(), theme));
        }
        (Some(u), Source::Host) => {
            lines.push(inherited("User", format!("{u} (from identity)"), theme));
        }
        (Some(u), src) => lines.push(inherited("User", with_source(u.clone(), src), theme)),
        (None, _) => lines.push(inherited("User", "(local user)", theme)),
    }
    // A deleted identity resolves as none (§12.4); the chip says so. An
    // identity inherited from a group or the vault defaults shows its source.
    let missing_identity = r
        .warnings
        .iter()
        .any(|w| matches!(w, sverb_core::resolve::ResolveWarning::MissingIdentity(_)));
    match (host.identity_id, r.identity_id) {
        (Some(id), _) if catalog.identities.contains_key(&id) => {
            lines.push(row(
                "Identity",
                catalog.identities[&id].label.clone(),
                theme,
            ));
        }
        (None, Some(id)) => {
            let label = catalog
                .identities
                .get(&id)
                .map_or_else(|| id.short(), |i| i.label.clone());
            lines.push(inherited(
                "Identity",
                with_source(label, r.source(SettingKey::IdentityId)),
                theme,
            ));
        }
        _ => {}
    }
    if missing_identity {
        lines.push(Line::from(vec![
            Span::styled(format!("{:<14}", "Identity"), theme.dim),
            Span::styled("[! missing identity]", theme.warn),
        ]));
    }
    if host.has_password {
        lines.push(row("Password", "•••••••• (stored)", theme));
    }
    if let Some(id) = host.key_id {
        lines.push(row("Key", name(&catalog.keys, id), theme));
    }
    if let Some(id) = host.group_id {
        // A deleted group resolves as none (§12.4); say so.
        match catalog.group_name(id) {
            Some(g) => lines.push(row("Group", group_path(id, catalog, g), theme)),
            None => lines.push(Line::from(vec![
                Span::styled(format!("{:<14}", "Group"), theme.dim),
                Span::styled("[! missing group]", theme.warn),
            ])),
        }
    }
    let tags = catalog.tags_of(host);
    if !tags.is_empty() {
        let names: Vec<String> = tags.iter().map(|t| format!("#{}", t.name)).collect();
        lines.push(row("Tags", names.join(" "), theme));
    }
    if !host.jump_chain.is_empty() {
        let hops: Vec<String> = host
            .jump_chain
            .iter()
            .map(|j| {
                catalog.hosts.get(j).map_or_else(
                    || format!("(missing {})", j.short()),
                    |h| h.display_label().to_owned(),
                )
            })
            .collect();
        lines.push(row("Jump via", hops.join(" → "), theme));
    }
    if let Some(p) = &host.proxy {
        lines.push(row("Proxy", p.describe(), theme));
    }
    if let Some(a) = host.agent_forwarding {
        let src = host
            .agent_source
            .clone()
            .unwrap_or_else(|| "builtin".to_owned());
        let v = if a {
            format!("yes ({src})")
        } else {
            "no".to_owned()
        };
        lines.push(row("Agent fwd", v, theme));
    }
    if let Some(k) = host.keepalive_secs {
        lines.push(row("Keepalive", format!("{k} s"), theme));
    }
    if let Some(c) = &host.charset {
        lines.push(row("Charset", c.clone(), theme));
    }
    if let Some(b) = &host.backspace {
        lines.push(row("Backspace", b.clone(), theme));
    }
    if let Some(s) = &host.color_scheme {
        lines.push(row("Colors", s.clone(), theme));
    }
    if let Some(v) = host.request_pty_for_exec {
        lines.push(row("PTY for exec", yes_no(v), theme));
    }
    if let Some(id) = host.startup_snippet_id {
        lines.push(row("On start", name(&catalog.snippets, id), theme));
    }
    if !host.port_forwards.is_empty() {
        lines.push(row(
            "Forwards",
            format!("{} rule(s)", host.port_forwards.len()),
            theme,
        ));
    }
    for (k, v) in &host.env {
        lines.push(row("Env", format!("{k}={v}"), theme));
    }
    // Settings inherited from a group or the vault defaults.
    lines.extend(inherited_lines(&r, catalog, theme));
    match host.last_connected_at {
        Some(t) => lines.push(row("Connected", relative_time(t, catalog.loaded_at), theme)),
        None => lines.push(inherited("Connected", "never", theme)),
    }
    let vault = catalog
        .vault_names
        .get(&host.vault)
        .cloned()
        .unwrap_or_else(|| "Personal".to_owned());
    lines.push(row("Vault", vault, theme));
    if catalog.is_read_only_vault(host.vault) {
        lines.push(Line::styled("Read-only vault", theme.warn));
    }
    if catalog.overrides.contains_key(&host.id) {
        lines.push(inherited(
            "Credentials",
            "your override (personal vault)",
            theme,
        ));
    }
    if host.read_only {
        lines.push(Line::styled(
            "Read-only: update sverb to edit this host",
            theme.warn,
        ));
    }
    if let Some(notes) = host.notes.as_deref().filter(|n| !n.trim().is_empty()) {
        lines.push(Line::raw(""));
        lines.push(Line::styled("Notes", theme.accent));
        lines.extend(markdown(notes, theme));
    }
    lines
}

/// Markdown as styled plain text: `#` headings bold, `-`/`*` list items as `•`,
/// `**bold**`, `*italic*`/`_italic_`, `` `code` `` and `[text](url)` → `text <url>`.
pub fn markdown(text: &str, theme: &Theme) -> Vec<Line<'static>> {
    let mut lines = Vec::new();
    let mut in_code = false;
    for raw in text.lines() {
        let trimmed = raw.trim_start();
        if trimmed.starts_with("```") {
            in_code = !in_code;
            continue;
        }
        if in_code {
            lines.push(Line::styled(format!("  {raw}"), theme.accent));
            continue;
        }
        let indent = raw.len() - trimmed.len();
        if let Some(h) = trimmed.strip_prefix('#') {
            let h = h.trim_start_matches('#').trim();
            lines.push(Line::from(inline(
                h,
                theme.base.add_modifier(Modifier::BOLD),
                theme,
            )));
            continue;
        }
        let item = trimmed
            .strip_prefix("- ")
            .or_else(|| trimmed.strip_prefix("* "))
            .or_else(|| trimmed.strip_prefix("+ "));
        match item {
            Some(rest) => {
                let mut spans = vec![Span::styled(
                    format!("{}• ", " ".repeat(indent)),
                    theme.base,
                )];
                spans.extend(inline(rest, theme.base, theme));
                lines.push(Line::from(spans));
            }
            None => lines.push(Line::from(inline(raw, theme.base, theme))),
        }
    }
    lines
}

/// Inline Markdown spans.
fn inline(text: &str, base: Style, theme: &Theme) -> Vec<Span<'static>> {
    let mut spans = Vec::new();
    let mut cur = String::new();
    let chars: Vec<char> = text.chars().collect();
    let mut i = 0;
    let flush = |cur: &mut String, spans: &mut Vec<Span<'static>>| {
        if !cur.is_empty() {
            spans.push(Span::styled(std::mem::take(cur), base));
        }
    };
    let find = |from: usize, pat: &[char]| -> Option<usize> {
        (from..chars.len()).find(|&j| chars[j..].starts_with(pat))
    };
    while i < chars.len() {
        let c = chars[i];
        if c == '`'
            && let Some(end) = find(i + 1, &['`'])
        {
            flush(&mut cur, &mut spans);
            let code: String = chars[i + 1..end].iter().collect();
            spans.push(Span::styled(code, theme.accent));
            i = end + 1;
            continue;
        }
        if chars[i..].starts_with(&['*', '*'])
            && let Some(end) = find(i + 2, &['*', '*'])
            && end > i + 2
        {
            flush(&mut cur, &mut spans);
            let s: String = chars[i + 2..end].iter().collect();
            spans.push(Span::styled(s, base.add_modifier(Modifier::BOLD)));
            i = end + 2;
            continue;
        }
        if (c == '*' || c == '_')
            && let Some(end) = find(i + 1, &[c])
            && end > i + 1
        {
            flush(&mut cur, &mut spans);
            let s: String = chars[i + 1..end].iter().collect();
            spans.push(Span::styled(s, base.add_modifier(Modifier::ITALIC)));
            i = end + 1;
            continue;
        }
        if c == '['
            && let Some(close) = find(i + 1, &[']'])
            && chars.get(close + 1) == Some(&'(')
            && let Some(paren) = find(close + 2, &[')'])
        {
            flush(&mut cur, &mut spans);
            let label: String = chars[i + 1..close].iter().collect();
            let url: String = chars[close + 2..paren].iter().collect();
            spans.push(Span::styled(label, base.add_modifier(Modifier::UNDERLINED)));
            spans.push(Span::styled(format!(" <{url}>"), theme.dim));
            i = paren + 1;
            continue;
        }
        cur.push(c);
        i += 1;
    }
    flush(&mut cur, &mut spans);
    spans
}

/// `value (from group "prod")`, `value (default)`.
fn with_source(value: String, src: &Source) -> String {
    match src {
        Source::BuiltinDefault | Source::GlobalConfig => format!("{value} (default)"),
        Source::Host => value,
        // This user's own credentials for a shared host (§13.4).
        Source::Override { .. } => format!("{value} (your override)"),
        src => format!("{value} (from {src})"),
    }
}

/// `root / prod / web` for a group.
fn group_path(id: ItemId, catalog: &HostCatalog, name: &str) -> String {
    let parents =
        sverb_core::model::group::ancestors(id, |g| catalog.lookup.groups.get(&g)?.parent_id);
    let mut names: Vec<&str> = parents
        .iter()
        .rev()
        .filter_map(|p| catalog.group_name(*p))
        .collect();
    names.push(name);
    names.join(" / ")
}

/// Labels of the settings shown as "inherited" lines.
const INHERITED_ROWS: [(SettingKey, &str); 14] = [
    (SettingKey::IdentityId, "Identity"),
    (SettingKey::Password, "Password"),
    (SettingKey::KeyId, "Key"),
    (SettingKey::JumpChain, "Jump via"),
    (SettingKey::Proxy, "Proxy"),
    (SettingKey::AgentForwarding, "Agent fwd"),
    (SettingKey::KeepaliveSecs, "Keepalive"),
    (SettingKey::Charset, "Charset"),
    (SettingKey::Backspace, "Backspace"),
    (SettingKey::ColorScheme, "Colors"),
    (SettingKey::RequestPtyForExec, "PTY for exec"),
    (SettingKey::StartupSnippetId, "On start"),
    (SettingKey::Env, "Env"),
    (SettingKey::RecordSessions, "Recording"),
];

fn ref_name(key: SettingKey, id: ItemId, catalog: &HostCatalog) -> String {
    let name = match key {
        SettingKey::IdentityId => catalog.identities.get(&id).map(|i| i.label.clone()),
        SettingKey::KeyId => catalog.keys.get(&id).cloned(),
        SettingKey::StartupSnippetId => catalog.snippets.get(&id).cloned(),
        _ => None,
    };
    name.unwrap_or_else(|| id.short())
}

/// One dim line per setting that comes from a group or the vault defaults.
fn inherited_lines(r: &ResolvedHost, catalog: &HostCatalog, theme: &Theme) -> Vec<Line<'static>> {
    let mut out = Vec::new();
    for (key, label) in INHERITED_ROWS {
        let src = r.source(key);
        // And from this user's credential override.
        if !matches!(
            src,
            Source::Group { .. } | Source::VaultDefaults | Source::Override { .. }
        ) {
            continue;
        }
        let value = match key {
            SettingKey::IdentityId => r.identity_id.map(|id| ref_name(key, id, catalog)),
            SettingKey::KeyId => r.key_id.map(|id| ref_name(key, id, catalog)),
            SettingKey::StartupSnippetId => {
                r.startup_snippet_id.map(|id| ref_name(key, id, catalog))
            }
            SettingKey::KeepaliveSecs => Some(format!("{} s", r.keepalive_secs)),
            SettingKey::Env => Some(
                r.env
                    .iter()
                    .map(|(k, v)| format!("{k}={v}"))
                    .collect::<Vec<_>>()
                    .join(" "),
            ),
            _ => r.display(key),
        };
        if let Some(v) = value {
            out.push(inherited(label, with_source(v, src), theme));
        }
    }
    out
}

/// The detail lines of a group: path, contents, "N hosts inherit these settings"
/// and the defaults it sets.
pub fn group_lines(id: ItemId, catalog: &HostCatalog, theme: &Theme) -> Vec<Line<'static>> {
    let Some(g) = catalog.lookup.groups.get(&id) else {
        return vec![Line::styled("This group no longer exists.", theme.dim)];
    };
    let mut lines = vec![row("Group", group_path(id, catalog, &g.name), theme)];
    if let Some(i) = &g.icon {
        lines.push(row("Icon", i.clone(), theme));
    }
    let (hosts, groups) = catalog.group_contents(id);
    let plural =
        |n: usize, one: &str, many: &str| format!("{n} {}", if n == 1 { one } else { many });
    lines.push(row(
        "Contains",
        format!(
            "{} · {}",
            plural(hosts, "host", "hosts"),
            plural(groups, "subgroup", "subgroups")
        ),
        theme,
    ));
    let n = catalog.inheriting_hosts(id);
    lines.push(Line::raw(""));
    lines.push(Line::styled(
        format!(
            "{} inherit{} these settings",
            plural(n, "host", "hosts"),
            if n == 1 { "s" } else { "" }
        ),
        theme.accent,
    ));
    // What this group sets (its own defaults).
    let own = catalog.inherited(Some(id), None, &GlobalDefaults::default());
    let d = &g.defaults;
    let mut any = false;
    for key in SettingKey::ALL {
        if !d.is_set(key) {
            continue;
        }
        any = true;
        let value = match key {
            SettingKey::IdentityId => d.identity_id.map(|i| ref_name(key, i, catalog)),
            SettingKey::KeyId => d.key_id.map(|i| ref_name(key, i, catalog)),
            SettingKey::StartupSnippetId => d.startup_snippet_id.map(|i| ref_name(key, i, catalog)),
            _ => own.display(key),
        }
        .unwrap_or_else(|| "(none)".to_owned());
        lines.push(row(key.field(), value, theme));
    }
    if !any {
        lines.push(Line::styled("No defaults set (e edits them).", theme.dim));
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relative_times() {
        let m = 60_000;
        assert_eq!(relative_time(0, 10_000), "just now");
        assert_eq!(relative_time(0, 3 * m), "3 minutes ago");
        assert_eq!(relative_time(0, 60 * m), "1 hour ago");
        assert_eq!(relative_time(0, 49 * 60 * m), "2 days ago");
        assert_eq!(relative_time(5, 0), "just now");
    }

    #[test]
    fn markdown_styles_without_markup() {
        let theme = Theme::default();
        let lines = markdown(
            "# Title\n- **bold** and *it* `code`\nsee [docs](https://x.y)",
            &theme,
        );
        let text: Vec<String> = lines
            .iter()
            .map(|l| l.spans.iter().map(|s| s.content.as_ref()).collect())
            .collect();
        assert_eq!(
            text,
            ["Title", "• bold and it code", "see docs <https://x.y>"]
        );
        assert!(
            lines[1]
                .spans
                .iter()
                .any(|s| s.style.add_modifier.contains(Modifier::BOLD))
        );
    }
}
