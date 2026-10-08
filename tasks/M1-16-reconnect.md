# M1-16 — Disconnect banner and auto-reconnect with preserved scrollback

| | |
|---|---|
| **Milestone** | M1 |
| **Touches** | `crates/sverb-conn/src/session/actor.rs` (reconnect loop), `crates/sverb-tui/src/widgets/terminal_pane.rs` (banner), `crates/sverb-tui/src/app` (keys `r/c/l` on a disconnected pane) |
| **Spec refs** | §6.1.2, §6.1.9 (`Exited` → no banner), §1 (flaky networks handled by keepalive + reconnect), §9.6 (forwards restart on reconnect) |
| **Depends on** | M1-13 |
| **Blocks** | M2-08 (auto-start forwards restart), M3-03 |

---

## 1. Current state in the codebase
Sessions reach `Disconnected{reason}` (M1-08/M1-13). Nothing happens afterwards, and the pane just stops updating.

## 2. Detailed description
- **Banner** (§6.1.2), rendered over the bottom of the pane while the emulator content stays visible:
  `Disconnected (<reason short>) — [Enter] reconnect · leader x close · leader i details`. **Changed from the spec's
  `[r]`/`[c]`/`[l]`**: a user typing `cd …` exactly when the link drops would otherwise close the pane and lose scrollback
  (`03-KEYBINDINGS.md` §3.1 A4). `leader i` opens the detail view with the
  `ErrorReport` chain and, after M3-06, the ConnLog entry.
- While the banner is shown, the pane is in a special **Disconnected** input state: only `Enter`, the leader (so
  `leader x`/`leader i`) and scrolling are handled. All other keys are swallowed, never sent and never interpreted, with a
  one-line hint flash "Session disconnected — Enter to reconnect".
- **No banner for `Exited(code)`** (§6.1.9). Instead show the footer "Session ended (exit N) — [Enter] reconnect · leader x close", which is
  less alarming. Plain letters are swallowed (`03-KEYBINDINGS.md` §4.4).
- **Reconnect:**
  - Manual `r` → `SessionCmd::Reconnect` → the actor goes `Disconnected → Resolving` and runs the full connect flow
    (including host-key checks and auth prompts) with the **same emulator**, so **scrollback is kept** (§6.1.2). Before
    reconnecting, the emulator gets a visual separator line written into it: `── reconnected at HH:MM:SS ──` (dim).
    Also reset the terminal modes the old remote left on (alt screen, mouse modes, bracketed paste, DECCKM) by feeding
    a soft reset (`ESC[!p`), then leaving the alt screen, so a crashed vim doesn't leave the pane in app-cursor mode.
  - **Auto-reconnect** (optional, off by default): per host `auto_reconnect: Option<bool>` falls back to the global
    `ssh.auto_reconnect` (**new config key — the spec says "optional auto-reconnect" without a key; add
    `ssh.auto_reconnect = false` and document it in M0-06's table**). Exponential backoff 1 s, 2 s, 4 s, 8 s, 16 s,
    30 s, 30 s … up to **10 tries**, with ±20% jitter. Countdown in the banner: "Reconnecting in 4 s (attempt 3/10) —
    [Enter] now · [Esc] cancel · leader x close". Not attempted for reasons `HostKey`, `Auth` (it would hit the same wall) or `Exited`.
  - Auth prompts during auto-reconnect pause the countdown loop (state `AwaitingUser`).
- **Port forwards** (M2-08): a dropped connection stops its rules (child cancellation tokens), and a successful reconnect
  restarts the auto-start ones.
- The tab bar marker for disconnected panes is the disconnected marker (§8.4, M1-17).
- Each reconnect attempt creates a new ConnLog entry (M3-06 hook).

## 3. Codebase changes
- **Extend** the session actor with the reconnect loop and the backoff schedule (a pure function in
  `sverb-conn::session::backoff`).
- **Extend** the `TerminalPane` widget with banner rendering and the reducer with the Disconnected input state.
- **Add** the config key `ssh.auto_reconnect` (M0-06 table, schema, default file) and the host field
  `auto_reconnect` (M1-02 view, M1-07 form). Mark it "spec addition" in `docs/data-model.md`.

## 4. Test cases to implement

**T-01 (unit) Backoff schedule.** Attempts 1..10 → base delays 1, 2, 4, 8, 16, 30, 30, 30, 30, 30, with jitter within ±20%
(seeded RNG). There's no 11th attempt.

**T-02 (unit) No auto-reconnect for HostKey/Auth/Exited.**

**T-03 (reducer) Banner keys.** On a Disconnected pane, `Enter` → `Reconnect` cmd. `leader x` → `CloseSession`. `leader i` →
detail view. Typing `c`, `d`, `r`, `l`, `x` → all swallowed: no `CloseSession`, no `Reconnect`, no `SendToSession` (K-06).

**T-04 (snapshot)** Banner rendering at 80×24 for Timeout, and the Exited footer.

**T-05 (integration, MockTransport) Scrollback preserved.** Write 500 lines, disconnect, reconnect → the emulator scrollback
still has ≥ 500 lines plus the separator.

**T-06 (integration) Mode reset.** The remote enabled the alt screen and DECCKM before dropping → after reconnect, the modes are
cleared.

**T-07 (e2e) Container restart.** With `auto_reconnect = true`, `docker restart` the SSH container → the session
reconnects automatically (allow up to 30 s) and output works.

**T-08 (e2e) Auto-reconnect gives up** after 10 attempts when the container stays down (virtual time, or a shortened schedule
via a test override) → the final banner shows "gave up after 10 attempts".

**T-09 (reducer) Cancel countdown** with `Esc` → no more attempts. A plain `c` does nothing.

## 5. Passing functional characteristics
- [ ] Disconnected panes show the §6.1.2 banner with reconnect, close and view-log. Exited sessions show a calmer footer.
- [ ] Manual reconnect reuses the emulator, so scrollback is kept, with a separator and a mode reset.
- [ ] Optional auto-reconnect uses 1→30 s exponential backoff with jitter, at most 10 tries, and skips auth and host-key failures.
- [ ] Forwards stop on drop and auto-start ones restart on reconnect (hook verified once M2-08 lands).
- [ ] Keys can't leak to a dead session.
