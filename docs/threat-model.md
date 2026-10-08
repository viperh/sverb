# Threat model

Placeholder (SPEC §17; filled in by M7-05).

<!-- M5-03 -->
## Server compromise: public-key substitution (SPEC §13.3, §17)

The sync server stores only ciphertext, but it is the directory of account public keys
(`GET /v1/users/{id}/public-keys`) and of org and vault membership. A malicious or compromised
server could try to substitute a member's keys, so that a vault key is wrapped to the attacker
(grant **to** a victim), or so that a grant signed by the attacker is accepted (grant **from** a
"member").

### Mitigations (M5-03)

- **TOFU pinning.** Every user's keys are pinned on this device the first time they are seen
  (`pinned_keys`, client migration `0003`), whether while granting, listing members or verifying
  grants. Pins are device-local and never synced, so the server can't poison them through sync.
- **Key-change warning.** A key that differs from the pin does not replace it. It is recorded
  as a pending change, the ✓ is cleared, the member shows `⚠ key changed` with a red modal, grants
  **to** that user are blocked (`Trust::keys_for_grant`), and grants **from** that user are not
  trusted (`verify_grant`). This lasts until the user compares safety numbers and chooses "Accept
  new key". Account keypairs survive password changes and recovery (only the bundle is re-wrapped),
  so a legitimate change only happens when an account is re-created.
- **Safety numbers.** 60 digits in 12 groups, computed from the sorted pair of key fingerprints,
  so both members see the same number (`sverb team verify <user>`, Settings → Team). A user who
  compared them out of band marks the member verified (✓, device-local).
- **Grant verification.** A wrapped vault key is used only after both checks pass. First, its
  Ed25519 signature over the canonical grant encoding verifies with the **pinned** key of
  `wrapped_by`. Second, the granter has `manage` on the vault, is an org owner or admin, or is
  the vault's creator, according to the server's membership list. On top of that:
  - personal vault keys are accepted only as self-grants signed with this account's own key;
  - a self-grant claimed for another user is rejected unless that user is the vault creator;
  - unpinned granters and granters with a pending key change are rejected.

### Residual risk

- **First sight.** TOFU trusts whatever key the server serves the first time a user is seen. A
  server that is malicious from the start can substitute a key before it is pinned. Only comparing
  safety numbers out of band (✓) detects that. Members who never verify each other are exposed
  to it.
- **Membership is server-asserted.** The org role and vault permission lists come from the
  server. The client uses them only to *narrow* trust: a grant still needs a valid signature by a
  pinned key. However, a malicious server can claim that a pinned member (for example a former
  admin, or any member it chooses) has `manage`, or that some user is the vault creator. A grant
  that member really signed would then be accepted. The server can't forge grants, but it can
  replay or misattribute authority among real, pinned members.
- **Vault creator TOFU.** The first self-grant of a shared vault is trusted on first sight. The
  server chooses which user it calls the creator, within the set of keys that are already pinned
  or that it serves at first sight.
- **Per-device trust.** Pins and ✓ are per device and are not synced. A new device starts with
  no pins and repeats TOFU. Verify members again on each device that matters.
- **Accepting a changed key** without actually comparing the new safety number defeats the
  warning. The UI and CLI always show the new number and ask before accepting.
