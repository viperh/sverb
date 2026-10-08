# M3-02 — Broadcast input

| | |
|---|---|
| **Milestone** | M3 |
| **Touches** | `crates/sverb-tui/src/views/sessions/broadcast.rs`, reducer input routing, `widgets/terminal_pane.rs` (border highlight), status bar segment |
| **Spec refs** | §9.8, §7.3 ("Encoding is per pane"), §8.3 (`leader b`), §9.7 (snippet runs broadcast) |
| **Depends on** | M3-01, M1-11, M2-09 |
| **Blocks** | M3-03 (broadcast sets saved in workspaces) |

---

## 1. Current state in the codebase
Input routing in Terminal mode sends `SessionCmd::Key(chord)` to the focused pane's session (M1-11), and each session encodes with its own modes.
`Tab.broadcast` exists as an empty field (M1-17).

## 2. Detailed description
- **`BroadcastSet`** per tab: `Off | AllPanes | Custom(BTreeSet<PaneId>)`.
- **`leader b`** toggles `AllPanes` for the current tab (§9.8). If the set was `Custom`, `leader b` turns broadcast off.
- **`leader B`** toggles the focused pane's membership in a `Custom` set (building it from Off). With fewer than 2 members, the set is
  shown as "pending" (the border is highlighted but nothing is duplicated until ≥ 2 members).
- **While active** (§9.8):
  - Every **key** typed in the focused pane (when it's a member) is sent as `SessionCmd::Key(chord)` to **every member**. Each pane encodes
    with **its own** terminal modes (§7.3). The focused pane's bytes are never copied.
  - **Paste** is broadcast (each pane applies its own bracketed-paste rule, M1-11).
  - **Snippet runs** in Paste / Paste & execute mode are broadcast (§9.9 → §9.7).
  - **Resize is never broadcast** (§9.8).
  - The leader and sverb actions are not broadcast.
  - If the focused pane is **not** a member of a `Custom` set, input goes only to the focused pane (no broadcast).
  - Panes that are disconnected, locked or awaiting a prompt are skipped silently (the status shows `×N (M skipped)`).
- **Visuals:** every member gets the theme's `broadcast_border` style (plus a `≋` marker in the border title for monochrome). The status bar shows
  `BROADCAST ×N` (§9.8). The tab title gets a `≋` marker.
- **Safety:** turning on broadcast with > 4 panes shows a one-time-per-session confirmation "Broadcast input to N panes?".
- Broadcast sets are per tab and survive pane splits (a new pane joins `AllPanes` implicitly but not a `Custom` set) and closes (closed panes are removed
  from the set).

## 3. Codebase changes
- **Create** `broadcast.rs` (pure set logic plus target computation). Modify the reducer's terminal-mode routing, paste and snippet paths to fan out.

## 4. Test cases to implement

**T-01 (reducer) AllPanes.** 3 panes, `leader b`, type `ls\r` → each of the 3 sessions receives `Key(l)`, `Key(s)`, `Key(Enter)`.

**T-02 (unit) Per-pane encoding.** Pane A has DECCKM on and pane B off. Broadcast `Up` → A gets `ESC O A` and B gets `ESC [ A` (via each session's encoder; test with
mock sessions holding different modes).

**T-03 (reducer) Custom set.** `leader B` on panes 1 and 3 → typing in pane 1 reaches 1 and 3, not 2. Typing in pane 2 (not a member) → only 2.

**T-04 (reducer) Single-member custom set** → no duplication, and the border is highlighted.

**T-05 (reducer) Resize** with broadcast on → only geometric resizes per pane, with no duplication.

**T-06 (reducer) Paste broadcast** → each member gets `Paste` (per-pane bracket logic).

**T-07 (reducer) Snippet in broadcast** → all members receive the snippet text.

**T-08 (reducer) Skipping** a disconnected member and the status count.

**T-09 (reducer) Leader not broadcast**: `ctrl-\ -` splits only, and no session receives bytes.

**T-10 (reducer) Confirmation** with 5 panes, once per session.

**T-11 (snapshot)** Broadcast borders and status `BROADCAST ×3` at 160×48, plus monochrome `NO_COLOR`.

**T-12 (e2e)** Two SSH panes, broadcast on, type `touch /tmp/bcast` → the file exists on both containers.

## 5. Passing functional characteristics
- [ ] `leader b` toggles broadcast for all panes in the tab. `leader B` builds custom sets.
- [ ] Keys, paste and snippet runs are duplicated to every member, each encoded with the member's own modes. Resize and sverb actions are never broadcast.
- [ ] Members are highlighted, and the status bar shows `BROADCAST ×N`.
- [ ] Unavailable panes are skipped safely. Large broadcasts need confirmation.
