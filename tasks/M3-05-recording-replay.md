# M3-05 — Encrypted session recording, replay player, `sverb export recording`

| | |
|---|---|
| **Milestone** | M3 |
| **Touches** | `crates/sverb-term/src/recording/{writer.rs, reader.rs, asciicast.rs}`, `crates/sverb-crypto/src/recording.rs` (from M1-01), `crates/sverb-tui/src/views/logs/replay.rs`, `crates/sverb/src/cli/export.rs` (`recording`) |
| **Spec refs** | §7.5, §9.12 (replay player), §5.1 (state dir), §5.2 (`device_local.recording_dir`), §4.12 (recording path device-local), §15 `[recording]`, §17 (recordings encrypted) |
| **Depends on** | M1-04 (LMK), M1-10, M1-08 |
| **Blocks** | M3-06 |

---

## 1. Current state in the codebase
`sverb-crypto::recording` provides the key derivation and chunk sealing (M1-01). `SessionCmd::StartRecording/StopRecording` exist (M1-08) but are no-ops. `leader R` is bound (M0-10).

## 2. Detailed description

### 2.1 What is recorded (§7.5)
- **asciicast v2:** a header line `{"version":2,"width":W,"height":H,"timestamp":unix,"env":{"TERM":…},"title":<host label>}` followed by
  event lines `[elapsed_secs, "o", "<output utf-8>"]` and resize events `[t, "r", "WxH"]`.
- **Input is not recorded by default.** With `recording.include_input = true`, input events `[t, "i", "…"]` are added, and the UI shows a one-time warning
  that this can capture passwords.
- Output is recorded **after** charset decoding (UTF-8) as the emulator sees it.
- Triggers: global `recording.enabled`, per host (a new host field `record_sessions: Option<bool>`, inherited; **spec says "per host"**, so add
  it to the M1-02 model and the form), or toggled live with `leader R` (status bar `REC ●`).

### 2.2 Encrypted container `<conn_id>.cast.sv` (§7.5)
- Stored in `state_dir/recordings/` (`device_local.recording_dir` records the path for the ConnLog item; recordings never sync).
- File layout: a magic header `SVREC1\0` + `conn_id(16)` + a `u32` chunk size, then repeated chunks, each `u32 BE length || nonce(24) || ct`.
  Each chunk's plaintext is **≤ 64 KiB of asciicast lines** (whole lines; a single huge output event is split across several events).
- Key `HKDF(LMK, info="sverb/recording/v1")` and `aad = conn_id || chunk_index (u64 BE) || is_last (u8)`, from M1-01.
- The **final chunk is flagged** `is_last = 1`, so **truncation is detected** ("recording incomplete") while a crash still leaves a readable prefix
  (all complete earlier chunks decrypt).
- Flush policy: seal and write a chunk when 64 KiB is buffered, or after 5 s of buffered data (so a crash loses at most 5 s), with `fsync` on
  close. The writer runs in its own task fed by a bounded channel from the session actor. If the channel is full, drop output events and write a
  `[t,"m","dropped N bytes"]` marker (asciicast marker event), so recording never blocks the session.
- File mode 0600.
- **Locking the vault** stops new chunks from being sealed? The LMK is zeroized on lock (M1-04). **Decision:** the writer derives the recording key once
  at start and holds it (zeroized on close). Recording continues while locked (sessions stay connected), which matches §5.3 "sessions stay connected".
  Document this.

### 2.3 Replay (§9.12)
- From the Logs view (M3-06): open the recording, decrypt chunk by chunk (streaming), and feed it into a fresh emulator sized per the header and resize events.
- **Player controls:** play/pause `Space`, speed 1×/2×/4× (`+`/`-`), seek ±5 s (`←`/`→`; seeking backwards replays from the start or the nearest snapshot
  checkpoint; store an emulator snapshot every 30 s of recording time in memory for fast seeking), **idle time capped at 2 s**, `q`/`Esc` to close.
  The progress bar shows elapsed / total.
- Incomplete recordings play up to the last valid chunk and show "recording incomplete (truncated)".
- Requires an unlocked vault.

### 2.4 Export (§7.5, §16)
`sverb export recording <id> <out.cast>` (`id` = conn log id or file name) → after a confirmation ("This writes the terminal output in plain text…"; `--yes`
to skip), it writes plain asciicast v2 for `asciinema play`. Also available in the TUI Logs view.

## 3. Codebase changes
- Writer, reader and player modules. Add the host field `record_sessions`. Implement the CLI export.

## 4. Test cases to implement

**T-01 (unit)** The asciicast header and event JSON escaping (control chars, unicode) is valid per spec, and `asciinema`-compatible (validate against a fixture with a JSON parse).

**T-02 (integration)** Record 300 KB of output → multiple chunks, each ≤ 64 KiB plaintext, and the last has `is_last`. Decrypt round-trip → the original events.

**T-03 (unit)** Truncation: drop the last chunk → the reader reports incomplete and returns the earlier events.

**T-04 (unit)** Chunk reorder or swap → auth failure (AAD includes the index). A chunk from another recording → auth failure (conn_id).

**T-05 (unit)** Input is excluded by default and included with the config.

**T-06 (integration)** Crash simulation: kill the writer after 5 s of activity without close → the prefix up to the last flushed chunk is readable.

**T-07 (integration)** Backpressure: block the file writes → the session continues, and a marker event is written once unblocked.

**T-08 (unit)** Player idle cap: a gap of 30 s in the events → played as 2 s.

**T-09 (unit)** Seek backwards via a checkpoint gives the same screen as linear replay.

**T-10 (reducer)** `leader R` toggles recording, and the status bar shows `REC ●`.

**T-11 (CLI)** `export recording` produces a valid `.cast` file (parse each line as JSON), and refuses without `--yes` when there's no TTY.

**T-12 (integration)** File modes 0600, and no plaintext canary from the output appears in the `.cast.sv` bytes.

## 5. Passing functional characteristics
- [ ] Sessions can be recorded globally, per host or by toggle, as asciicast v2 output plus resize (input only if opted in).
- [ ] Recordings are stored as independently sealed ≤ 64 KiB chunks with index-bound AAD and a last-chunk flag. Truncation is detected and prefixes survive crashes.
- [ ] Recording never blocks or slows the session.
- [ ] The replay player supports pause, 1/2/4× speed, ±5 s seek and a 2 s idle cap.
- [ ] `sverb export recording` writes plain asciicast after confirmation.
