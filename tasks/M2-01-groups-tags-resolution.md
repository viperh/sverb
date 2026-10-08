# M2-01 — Groups, tags and settings resolution with provenance

| | |
|---|---|
| **Milestone** | M2 — Organization & power features |
| **Touches** | `crates/sverb-core/src/resolve.rs` (full version), `crates/sverb-core/src/model/{group.rs, tag.rs}`, `crates/sverb-tui/src/views/hosts/` (tree mode, group editor, tag actions), `crates/sverb-tui/src/widgets/form/` (inherited placeholders) |
| **Spec refs** | §4.3, §4.11, §4.13 (vault defaults), §9.2, §8.5 (filter by `#tag`), §12.4 (missing refs → None), §19 (settings resolution table tests) |
| **Depends on** | M1-07 |
| **Blocks** | M2-02, M2-05, M2-11, M3-01 … |

---

## 1. Current state in the codebase
`sverb-core::resolve` (M1-13) builds a minimal `ResolvedHost` from the host itself plus global config. The Hosts list is
flat. The `Group`, `HostDefaults` and `Tag` typed views exist (M1-02) without UI.

## 2. Detailed description

### 2.1 Resolution (§4.3)
`resolve(host: &Host, store: &impl ItemLookup, vault: &Vault, config: &Config) -> ResolvedHost`:
- The order for every inheritable setting: **Host → Group → parent Group → … → vault defaults → global config**.
- Inheritable settings are every `Option` field of Host except label and address (§4.3 "same optional fields as Host minus
  label/address"): port, identity_id, username, password, key_id, jump_chain (an empty Vec counts as "unset"? **Decision:**
  `jump_chain`, `env`, `tags`, `port_forwards` are inheritable only when the host's value is absent, not when it's empty; the
  form distinguishes "inherit" from "explicitly empty"), proxy, agent_forwarding, agent_source, env, startup_snippet_id,
  keepalive_secs, charset, backspace, color_scheme, algorithms, request_pty_for_exec, plus the M1-16 addition auto_reconnect.
- **Provenance map:** `HashMap<SettingKey, Source>` where `Source = Host | Group{id, name} | VaultDefaults |
  GlobalConfig | BuiltinDefault`. The UI renders it as `port: 2222 (from group "prod")` (§4.3).
- **Credential bundles:** username, password and key resolve together? **Decision:** each field resolves independently, but an
  identity is expanded at the level where it's set (host.identity_id or group.defaults.identity_id) and its username,
  password and key are treated as values at that level. Inline host fields override identity fields (§4.2).
- **Missing references** (deleted group, identity or key) are treated as `None` at read time (§12.4) and logged at debug. The
  detail pane shows a warning chip "missing group".
- **Cycle safety:** group chain walking stops at depth 64 and on revisiting an id (defensive, even though writes reject
  cycles).
- Pure and deterministic, with no I/O beyond the lookup trait.

### 2.2 Groups (§9.2)
- Nested to any depth. The Hosts view becomes a **tree** (M1-06 tree mode), collapsible with `←/→` or `h/l`.
- The group editor (form) has name, parent (reference, excluding self and descendants), icon (a single grapheme or a short name), and
  a **defaults** section with the same fields as the host form's inheritable ones. The detail pane shows "N hosts inherit these
  settings" (count of hosts whose resolved value for at least one field comes from this group).
- **Delete group** dialog (§9.2): "Move its N hosts and M subgroups to the parent group" (default) or "Delete them"
  (danger, with a typed count confirmation if > 10 items).
- Move hosts to a group (`m`, bulk): a group picker.

### 2.3 Tags (§4.11)
- `Tag { name, color }`, unique name per vault (case-insensitive), validated on save. Colors come from a fixed palette of 12
  named colors (rendered via the UI theme, so they work in monochrome as `#name` text).
- Tag actions: `t` on hosts (bulk) → multiselect of existing tags, plus "create new tag" inline. Remove tags the same way.
- Tag management: Settings → Tags (rename, recolor, delete; deleting removes references lazily per §12.4).
- Filter by `#tag` already works in search (M1-05). Add the tag chips rendering in the list.

### 2.4 Vault defaults (§4.13)
Settings → Vault → Defaults: the same editor as group defaults, stored in the `Vault` record (for the personal vault, store it as a
special item kind? **Decision:** store vault defaults as a `Group`-like item with a reserved flag `is_vault_defaults = true`, so
they sync with the same machinery. Document this).

### 2.5 Form integration
Host and group forms show inherited placeholders with provenance (M1-06 §2.2) using `resolve` on the **draft** (live while
editing, so changing the group updates the placeholders).

## 3. Codebase changes
- **Extend** `resolve.rs` and add `provenance.rs`.
- **Add** group/tag views and actions in `views/hosts/`, plus the Settings sub-pages for tags and vault defaults.
- **Docs:** `docs/data-model.md` gets the inheritance rules and decisions above.

## 4. Test cases to implement

**T-01 (unit, table) Resolution chains** (§19 "table tests over nested group chains"), with at least 15 rows. Examples:
port on host → host; port unset on host, set on group → group; unset on host and group, set on the grandparent → grandparent;
unset everywhere → global config; vault default set → vault defaults beats global; identity on the group + inline username on the host
→ username from host, password from the group identity; deleted group reference → resolves as if no group; env set on the host as empty
→ empty (not inherited); env absent → inherited.

**T-02 (unit) Provenance** is reported correctly for every row of T-01.

**T-03 (unit) Defensive cycle.** A corrupted store with a group cycle (injected bypassing validation) → resolution terminates
and returns values from the chain visited once.

**T-04 (property)** For random trees of groups (depth ≤ 6) with random field assignments, `resolve` equals a naive reference
implementation.

**T-05 (reducer) Tree view** collapse and expand, and moving 3 hosts to a group via bulk `m`.

**T-06 (reducer) Delete group → move to parent:** the hosts' `group_id` becomes the parent, and the subgroups are reparented.

**T-07 (reducer) Delete group → delete all**, with a typed confirmation when > 10.

**T-08 (unit) Group detail count** "N hosts inherit".

**T-09 (unit) Tag uniqueness** (case-insensitive) per vault.

**T-10 (reducer) Bulk tag add/remove** on 5 hosts → only the `tags` field changes on each.

**T-11 (snapshot)** Host form with inherited placeholders showing `(from group "prod")`.

**T-12 (integration)** Changing the group's default port changes the resolved port for a connected host's next connection only (an
existing session is unaffected).

## 5. Passing functional characteristics
- [ ] Every inheritable setting resolves Host → Group chain → vault defaults → global config, with provenance.
- [ ] Missing references resolve as `None` without errors. Cycles can't hang resolution.
- [ ] Groups nest arbitrarily, show as a collapsible tree, have defaults editors, and deletion offers move vs delete.
- [ ] Tags can be created, assigned in bulk, filtered with `#tag`, renamed and deleted.
- [ ] Forms display inherited values and their source live.
