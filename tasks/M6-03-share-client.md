# M6-03 — Terminal sharing client: host flow, approval, view/control, viewer pane, `sverb join`

| | |
|---|---|
| **Milestone** | M6 (exit criterion: "Remote pair-debugging session works across NAT through the server") |
| **Touches** | `crates/sverb-sync/src/share/{host.rs, viewer.rs}`, `crates/sverb-tui/src/views/share/{start_dialog.rs, approve_dialog.rs, viewers_panel.rs}`, viewer pane kind in `views/sessions`, `crates/sverb/src/cli/mod.rs` (`join`) |
| **Spec refs** | §14.1, §14.2 (snapshot), §14.3, §8.4 (pane kinds), §17 (shared-terminal hijack) |
| **Depends on** | M6-01, M6-02, M1-10 (`snapshot_vt`), M2-12 (palette join) |
| **Blocks** | — |

---

## 1. Current state in the codebase
The relay (M6-01), share crypto (M6-02) and emulator `snapshot_vt` (M1-09) exist. Panes are SSH or local (M1-17).

## 2. Detailed description

### 2.1 Host side (§14.1)
1. `leader S` on a pane → the start dialog: mode (`view` default / `control`), expiry (15 min, 1 h, 4 h, 24 h), "viewers must have a sverb account" (checkbox), and "skip approval"
   (unchecked by default, with a warning when checked).
2. `POST /v1/shares` → share_id. Generate `share_key` locally. Show the link `sverb://join/<server>/<id>#<key>` (and the https form) with copy-to-clipboard (M1-11). The link
   stays visible in the viewers panel.
3. Open the host WS (`/v1/shares/{id}/host`).
4. On `viewer_joined` plus `Hello`: verify the MAC (M6-02). Failure → kick. Success → the **approval modal** (§14.1.6): viewer name (or "anonymous"), account email if any, IP hint,
   `[a]pprove / [d]eny`. Skipped if "skip approval" was set. Meanwhile, send `ApprovalPending`.
5. On approval: `Welcome`, then a **Snapshot frame** (`emulator.snapshot_vt()`, cols, rows; §14.2: visible grid + cursor + modes, no scrollback), then live `Output` frames
   (a tap in the session actor that copies each output chunk to the share task after it's fed to the emulator), `Resize` on pane resize.
6. **Control mode** (§14.3): viewer `Input` frames are injected into the host session (as raw bytes, written to the transport) **only** if that viewer has control.
   Granting control per viewer is the host's choice (in the viewers panel: toggle control → `ControlGranted(true)`). The host sees a `⚠ shared · control` banner
   on the pane (and `⚠ shared · view` in view mode).
7. The viewers panel (`leader S` again while sharing): the list of viewers with control status, kick, revoke control, copy link, stop sharing.
8. **End** (§14.3): the host stops, the session ends, or expiry → `Bye` to all → `DELETE /v1/shares/{id}`.
- Backpressure: the share task has a bounded queue. If it falls behind, drop output and resend a fresh **Snapshot** (keeps viewers consistent without blocking the
  session).

### 2.2 Viewer side
- `sverb join <link>` (CLI → TUI `LaunchIntent::Join`), pasting a link into the palette (M2-12), or quick connect. Requires a server reachable from the link. Auth uses the
  current account if logged in to that server, otherwise joins anonymously (if allowed) asking for a display name.
- Handshake (M6-02) → waits with "Waiting for host approval…" → receives the snapshot → a **viewer pane** (a new tab) with its own emulator **sized to the host's dimensions**,
  letterboxed (centered with padding) or clipped if the local pane is smaller (§14.3), with a status `viewing <name>'s session (read-only)`.
- In view mode, keystrokes aren't sent (only the leader works). In control mode with `ControlGranted(true)`, keys are encoded **using the viewer emulator's modes** (which mirror the
  host's via the snapshot and stream) and sent as `Input` frames.
- Sequence or auth errors (M6-02) → close with the message "Share connection integrity error".
- `Bye` or close → the pane shows "Share ended (<reason>)".
- The viewer pane kind can't be split-duplicated or saved in workspaces (M3-03).

### 2.3 Stretch (§14.3)
The read-only web viewer (xterm.js + WebCrypto at `/s/<id>`) is **out of scope** (an open question, §22.3).

## 3. Codebase changes
- The share host and viewer modules in `sverb-sync` (feature `sync`), the session-actor output tap (a broadcast channel per session for observers, also useful for recording), the views, and the CLI join intent.

## 4. Test cases to implement

**T-01 (integration, TestServer)** Host shares a local-pty pane in view mode → the viewer joins → host approves → the viewer's emulator grid equals the host's after the snapshot. Subsequent
output (`echo hi`) appears on the viewer within 1 s.

**T-02** Deny → the viewer sees "denied" and is disconnected.

**T-03** A wrong key in the link → the host rejects the MAC and the viewer is kicked. No approval modal is shown to the host.

**T-04** Control mode: before ControlGranted, viewer keys are ignored by the host. After granting, the viewer typing `ls\r` executes on the host session. Revoke → ignored again.

**T-05** View mode: viewer input frames are dropped by the host even if crafted.

**T-06** Snapshot correctness with the alt screen (vim open on the host) → the viewer shows vim's screen with the correct modes.

**T-07** Host resize → the viewer gets Resize, letterboxing changes, and nothing breaks if the viewer window is smaller (clipping).

**T-08** Slow viewer → the host is unaffected. After the backlog, the viewer receives a fresh snapshot.

**T-09** Session ends on the host → Bye → the viewer pane shows ended.

**T-10** Expiry → the share is closed on both sides.

**T-11 (reducer)** `⚠ shared · control` banner rendering and the viewers panel actions (snapshot tests).

**T-12 (CLI)** `sverb join <link>` launches the TUI and opens a viewer tab.

**T-13 (M6 exit criterion, e2e)** Host and viewer in separate Docker networks (no direct route) through the server container → a pair-debugging session with control works.

## 5. Passing functional characteristics
- [ ] `leader S` shares a pane with mode, expiry and account requirements, and shows a link whose key never reaches the server.
- [ ] The host approves each viewer (unless skipped). Viewers get a snapshot plus a live stream in a correctly sized pane.
- [ ] Control mode injects only granted viewers' input. The host can revoke control or kick at any time, with a visible banner.
- [ ] Sharing ends on stop, session end or expiry. Integrity errors close the channel.
- [ ] `sverb join <link>` and palette paste join a share. It works across NAT through the relay.
