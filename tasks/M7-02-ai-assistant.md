# M7-02 — Optional AI command assistant — **DROPPED**

> **Dropped on 2026-10-08 by the user ("I don't need ai assistant. remove it.").** Do not implement this task.
> The agent's work was deleted before merging. The AI pieces that earlier tasks added are being removed by a
> cleanup step (see `04-PROGRESS.md`, row M7-02): `ActionName::AiPrompt` / `leader a`, the `[ai]` config section
> (`AiConfig`, validation, defaults, schema), the palette rule, and the keymap/which-key snapshots.
> SPEC §9.11 is marked removed, and the `[ai]` block and the `leader a` row are gone from SPEC.md. The text below
> is kept for history only.

| | |
|---|---|
| **Milestone** | M7 |
| **Touches** | new module `crates/sverb-tui/src/services/ai/{mod.rs, provider.rs, anthropic.rs, openai_compat.rs, context.rs}` (or a new crate `sverb-ai` if dependencies grow), `crates/sverb-tui/src/views/ai_prompt.rs` |
| **Spec refs** | §9.11, §15 `[ai]` |
| **Depends on** | M1-11 (paste), M0-06 (config) |
| **Blocks** | — |

---

## 1. Current state in the codebase
The `[ai]` config keys exist (M0-06). There's no `leader a` binding yet. Add it in the M0-10 registry as `ai_prompt`, enabled only when `ai.enabled`.

## 2. Detailed description
- **Disabled by default.** Enabled per user with their own API key, read from the env var named by `ai.api_key_env` (default `ANTHROPIC_API_KEY`). The key is **never stored** in config or
  the vault? The spec says "with their own API key" and the config only names an env var, so read from env only. Optionally allow storing it as a vault secret (a future
  enhancement; note it).
- **Provider trait:** `async fn suggest(&self, req: AiRequest) -> Result<AiSuggestion { command: String, explanation: String }>`.
  - **Anthropic** (default model `claude-sonnet-5-5`, configurable `ai.model`): Messages API over `reqwest` (rustls), with a system prompt instructing it to return a single
    shell command plus a short explanation in a strict JSON shape (`{"command": "...", "explanation": "..."}`) and to refuse destructive commands without clear intent? Keep
    it simple: return the command, and the user reviews it. Use the latest API version header. Before implementing, consult current Anthropic API docs (the `claude-api`
    skill) for the request format.
  - **OpenAI-compatible** (`ai.provider = "openai-compatible"`, with a base URL; add `ai.base_url`, a spec addition, default `http://localhost:11434/v1` for Ollama):
    `/chat/completions`.
- **Context sent** (§9.11): **only** the user's request, the OS and shell if known (from OSC 133 or `uname` cached from exec, else omitted) and, **optionally**, the last N lines of the
  pane (`ai.send_pane_context = false` by default; N = 50, a spec addition `ai.pane_context_lines`). **Vault data (credentials, host list) is never sent.** Pane lines are sent
  verbatim when enabled.
- **UX:** `leader a` → a prompt dialog: the input line plus a **"What will be sent"** expandable preview showing the exact payload text (the request, OS/shell, pane lines if enabled)
  (§9.11 "the UI clearly indicates what will be sent"). Submit → a spinner (cancellable) → the result dialog with the command (monospace) and explanation. **`Enter` pastes the
  command into the pane (Paste mode, no newline, M1-11), never auto-executes** (§9.11). `e` edits it before pasting, `c` copies, `Esc` discards.
- Errors (no key, HTTP error, timeout of 30 s, malformed response) → a clear message with ErrorReport detail. Never log the prompt or response at `info` (the request may contain
  pane output).
- No network call ever happens unless `ai.enabled = true` **and** the user submits a prompt (consistent with §1.1 "never phones home").

## 3. Codebase changes
- The AI service and dialog. Config additions `ai.base_url`, `ai.pane_context_lines` (M0-06 table and schema). Feature-gate the module behind a cargo feature `ai` (default on) to allow
  minimal builds.

## 4. Test cases to implement

**T-01 (unit)** Context builder: `send_pane_context=false` → the payload contains only the request plus OS/shell. True → also exactly the last N pane lines. **Never** host labels or credentials
(a canary test with a vault containing a canary host label).

**T-02 (unit, mock HTTP)** Anthropic request shape (model, headers, messages) matches the expected snapshot. The response is parsed into a command and explanation.

**T-03 (unit, mock HTTP)** OpenAI-compatible request and response.

**T-04 (unit)** Malformed JSON → a graceful error. Timeout → an error.

**T-05 (reducer)** `ai.enabled=false` → `leader a` unbound and the palette action hidden.

**T-06 (reducer)** The preview shows exactly the payload text that will be sent.

**T-07 (reducer)** Enter → `SendToSession(Paste(command))` without `\r`, and nothing is auto-executed.

**T-08 (integration)** No outbound connection unless enabled and submitted (reuse the M4-09 T-08 network monitor).

**T-09 (unit)** A missing env var → the message "Set ANTHROPIC_API_KEY to use the AI assistant".

## 5. Passing functional characteristics
- [ ] The assistant is off by default, enabled with the user's own key from an env var, and supports Anthropic (default `claude-sonnet-5-5`) and OpenAI-compatible (incl. Ollama) endpoints.
- [ ] Only the request, OS/shell and (opt-in) pane lines are sent, never vault data. The UI previews exactly what will be sent.
- [ ] Suggestions are shown for review with an explanation. Enter pastes and never auto-executes.
- [ ] No network traffic happens without explicit use.
