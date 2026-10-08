//! M1-15 known_hosts tests (T-01…T-09, T-13).
//!
//! Fixtures in `testdata/` were generated with OpenSSH 10.5p1's `ssh-keygen` (never
//! from a real `~/.ssh/known_hosts`):
//! - `ed25519.pub`, `ecdsa.pub`, `rsa.pub`, `ca.pub`: `ssh-keygen -t <type> -N ''`;
//! - `*.randomart.txt`: `ssh-keygen -lv -E sha256 -f <key>.pub` (fingerprint line and
//!   randomart, recorded verbatim);
//! - `hashed_example_com.txt`: `example.com <ed25519 key>` hashed with `ssh-keygen -H`;
//! - `host-valid-cert.pub`: `ssh-keygen -s ca -h -I host-cert -n host.test,web.test
//!   -V 20200101:20991231 -z 1 ecdsa.pub`; `host-expired-cert.pub`: the same with
//!   `-n host.test -V 20200101:20210101`; `user-cert.pub`: without `-h` (a user cert);
//! - `sk.txt`: two `sk-*` public keys assembled by hand (an SSH-encoded blob of a
//!   SHA-256 value as the ed25519 key; the ecdsa point of `ecdsa.pub`), both accepted by
//!   `ssh-keygen -lf`;
//! - `known_hosts.txt`: the T-09 file built from the above plus one malformed line.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use pretty_assertions::assert_eq;

use super::{
    check::{CheckResult, KeyInfo, PolicyDecision, PresentedKey, entry_fingerprint},
    hashed,
    lookup::glob,
    *,
};
use crate::{
    config::HostKeyPolicy,
    model::{KnownHost, KnownHostMarker, UnixMillis},
};

const ED25519: &str = include_str!("testdata/ed25519.pub");
const ECDSA: &str = include_str!("testdata/ecdsa.pub");
const RSA: &str = include_str!("testdata/rsa.pub");
const CA: &str = include_str!("testdata/ca.pub");
const CERT_VALID: &str = include_str!("testdata/host-valid-cert.pub");
const CERT_EXPIRED: &str = include_str!("testdata/host-expired-cert.pub");
const CERT_USER: &str = include_str!("testdata/user-cert.pub");
const HASHED: &str = include_str!("testdata/hashed_example_com.txt");
const FIXTURE: &str = include_str!("testdata/known_hosts.txt");

/// 2030-01-01T00:00:00Z: inside the valid cert's window, after the expired one's.
const NOW_2030: u64 = 1_893_456_000;

fn entry(pattern: &str, pub_line: &str, marker: KnownHostMarker) -> KnownHost {
    let mut parts = pub_line.split_whitespace();
    KnownHost {
        host_pattern: pattern.to_owned(),
        key_type: parts.next().unwrap().to_owned(),
        public_key: parts.next().unwrap().to_owned(),
        marker,
        ..KnownHost::default()
    }
}

fn plain(pattern: &str, pub_line: &str) -> KnownHost {
    entry(pattern, pub_line, KnownHostMarker::None)
}

fn key(line: &str) -> PresentedKey {
    PresentedKey::from_openssh(line.trim()).unwrap()
}

/// T-01: the lookup key.
#[test]
fn t01_lookup_key() {
    for (host, port, want) in [
        ("h", 22, "h"),
        ("h", 2222, "[h]:2222"),
        ("::1", 22, "::1"),
        ("::1", 2222, "[::1]:2222"),
    ] {
        assert_eq!(lookup_key(host, port), want, "{host}:{port}");
    }
}

/// T-02: a line hashed by `ssh-keygen -H` matches `example.com` only.
#[test]
fn t02_hashed_match() {
    let (entries, warnings) = parse_known_hosts(HASHED);
    assert!(warnings.is_empty(), "{warnings:?}");
    let pattern = &entries[0].host_pattern;
    assert!(hashed::is_hashed(pattern));
    assert!(hashed::matches(pattern, "example.com"));
    assert!(!hashed::matches(pattern, "example.org"));
    assert!(!hashed::matches(pattern, "[example.com]:2222"));
    assert_eq!(lookup(&entries, "example.com", 22).matching.len(), 1);
    assert!(lookup(&entries, "example.org", 22).is_empty());
    // Malformed hashed fields never match.
    assert!(!hashed::matches("|1|bm9wZQ==|bm9wZQ==", "example.com"));
    assert!(!hashed::matches("|1|", "example.com"));
}

/// T-03: globs, negation and comma lists.
#[test]
fn t03_pattern_globbing() {
    let list = "*.example.com,!bad.example.com";
    assert!(pattern_list_matches(list, "a.example.com"));
    assert!(!pattern_list_matches(list, "bad.example.com"));
    assert!(!pattern_list_matches(list, "example.com"));
    assert!(pattern_list_matches("host,10.0.0.1", "10.0.0.1"));
    assert!(pattern_list_matches("web?.test", "web1.test"));
    assert!(!pattern_list_matches("web?.test", "web12.test"));
    assert!(pattern_list_matches("[*.test]:2222", "[a.test]:2222"));
    assert!(!pattern_list_matches("*.test", "[a.test]:2222"));
    assert!(pattern_list_matches("EXAMPLE.com", "example.COM"));
    // Only negations: nothing matches.
    assert!(!pattern_list_matches("!bad", "good"));
    assert!(glob("a*b*c", "aXXbYYc"));
    assert!(!glob("a*b*c", "aXXbYY"));
    assert!(glob("*", ""));
}

/// T-04: revoked > CA cert valid > exact match > changed > unknown, under each policy.
#[test]
fn t04_decision_table() {
    use HostKeyPolicy::{AcceptNew, Ask, Strict};
    let revoked = CheckResult::Revoked {
        fingerprint: "SHA256:x".into(),
    };
    let cert = CheckResult::CertValid {
        ca_fingerprint: "SHA256:ca".into(),
    };
    let changed = CheckResult::Changed {
        old: vec![],
        cert_note: None,
    };
    let unknown = CheckResult::Unknown { cert_note: None };
    let reject = |d: &PolicyDecision| matches!(d, PolicyDecision::Reject(_));
    type Row<'a> = (&'a CheckResult, HostKeyPolicy, fn(&PolicyDecision) -> bool);
    let rows: [Row<'_>; 15] = [
        (&revoked, Strict, |d| matches!(d, PolicyDecision::Reject(_))),
        (&revoked, Ask, |d| matches!(d, PolicyDecision::Reject(_))),
        (&revoked, AcceptNew, |d| {
            matches!(d, PolicyDecision::Reject(_))
        }),
        (&cert, Strict, |d| *d == PolicyDecision::Accept),
        (&cert, Ask, |d| *d == PolicyDecision::Accept),
        (&cert, AcceptNew, |d| *d == PolicyDecision::Accept),
        (&CheckResult::Known, Strict, |d| {
            *d == PolicyDecision::Accept
        }),
        (&CheckResult::Known, Ask, |d| *d == PolicyDecision::Accept),
        (&CheckResult::Known, AcceptNew, |d| {
            *d == PolicyDecision::Accept
        }),
        (&changed, Strict, |d| matches!(d, PolicyDecision::Reject(_))),
        (&changed, Ask, |d| *d == PolicyDecision::AskChanged),
        (&changed, AcceptNew, |d| {
            matches!(d, PolicyDecision::Reject(_))
        }),
        (&unknown, Strict, |d| matches!(d, PolicyDecision::Reject(_))),
        (&unknown, Ask, |d| *d == PolicyDecision::AskUnknown),
        (&unknown, AcceptNew, |d| *d == PolicyDecision::AutoSave),
    ];
    for (result, policy, ok) in rows {
        let d = decide(policy, result);
        assert!(ok(&d), "{result:?} under {policy:?} gave {d:?}");
    }
    assert!(reject(&decide(Ask, &revoked)));

    // And the precedence itself, through `check`.
    let host = "host.test";
    let ca = entry("*.test", CA, KnownHostMarker::CertAuthority);
    let ecdsa_known = plain(host, ECDSA);
    // Same type, another key: the entry's blob is replaced (only blobs are compared).
    let other_ecdsa = {
        let mut e = plain(host, ECDSA);
        e.public_key = RSA.split_whitespace().nth(1).unwrap().to_owned();
        e
    };
    let cert = key(CERT_VALID);
    let k = key(ECDSA);
    assert!(matches!(
        check([&ca], host, 22, &cert, NOW_2030),
        CheckResult::CertValid { .. }
    ));
    assert_eq!(
        check([&ecdsa_known], host, 22, &k, NOW_2030),
        CheckResult::Known
    );
    assert!(matches!(
        check([&other_ecdsa], host, 22, &k, NOW_2030),
        CheckResult::Changed { ref old, .. } if old.len() == 1
    ));
    assert!(matches!(
        check([&plain(host, ED25519)], host, 22, &k, NOW_2030),
        CheckResult::Unknown { cert_note: None }
    ));
    // A cert whose CA is unknown falls back to its plain key.
    assert!(matches!(
        check([&ecdsa_known], host, 22, &cert, NOW_2030),
        CheckResult::Known
    ));
}

/// T-05: a CA-signed cert whose host key is also `@revoked` is rejected; so is a cert
/// from a revoked CA.
#[test]
fn t05_revoked_beats_ca() {
    let host = "host.test";
    let ca = entry("*.test", CA, KnownHostMarker::CertAuthority);
    let cert = key(CERT_VALID);
    let revoked_key = entry("*", ECDSA, KnownHostMarker::Revoked);
    let r = check([&ca, &revoked_key], host, 22, &cert, NOW_2030);
    assert!(matches!(r, CheckResult::Revoked { .. }), "{r:?}");
    assert!(matches!(
        decide(HostKeyPolicy::AcceptNew, &r),
        PolicyDecision::Reject(_)
    ));

    let revoked_ca = entry("*", CA, KnownHostMarker::Revoked);
    let r = check([&ca, &revoked_ca], host, 22, &cert, NOW_2030);
    assert!(matches!(r, CheckResult::Revoked { .. }), "{r:?}");

    // A revoked plain key beats an exact match.
    let r = check(
        [&plain(host, ECDSA), &revoked_key],
        host,
        22,
        &key(ECDSA),
        NOW_2030,
    );
    assert!(matches!(r, CheckResult::Revoked { .. }));
    // Revocations are per host pattern.
    let elsewhere = entry("other.test", ECDSA, KnownHostMarker::Revoked);
    assert_eq!(
        check(
            [&plain(host, ECDSA), &elsewhere],
            host,
            22,
            &key(ECDSA),
            NOW_2030
        ),
        CheckResult::Known
    );
}

/// T-06: expired, principal mismatch and user certs are not accepted; a valid one is.
#[test]
fn t06_ca_checks() {
    let ca = entry("*.test", CA, KnownHostMarker::CertAuthority);
    let note = |r: CheckResult| match r {
        CheckResult::Unknown { cert_note } | CheckResult::Changed { cert_note, .. } => {
            cert_note.unwrap()
        }
        other => panic!("accepted: {other:?}"),
    };
    // Valid, for both principals.
    for host in ["host.test", "web.test"] {
        let r = check([&ca], host, 22, &key(CERT_VALID), NOW_2030);
        assert!(matches!(r, CheckResult::CertValid { .. }), "{host}: {r:?}");
    }
    // Another port: the CA pattern must match `[host]:port` (as in OpenSSH); the
    // principal is still the bare host name.
    let r = check([&ca], "host.test", 2222, &key(CERT_VALID), NOW_2030);
    assert!(matches!(r, CheckResult::Unknown { .. }), "{r:?}");
    let ca_port = entry("[*.test]:2222", CA, KnownHostMarker::CertAuthority);
    let r = check([&ca_port], "host.test", 2222, &key(CERT_VALID), NOW_2030);
    assert!(matches!(r, CheckResult::CertValid { .. }), "{r:?}");
    // Expired.
    let n = note(check([&ca], "host.test", 22, &key(CERT_EXPIRED), NOW_2030));
    assert!(n.contains("not valid now"), "{n}");
    // Not yet valid.
    let n = note(check([&ca], "host.test", 22, &key(CERT_VALID), 1_000));
    assert!(n.contains("not valid now"), "{n}");
    // Principal mismatch (the CA pattern matches, the cert does not list the host).
    let n = note(check([&ca], "other.test", 22, &key(CERT_VALID), NOW_2030));
    assert!(n.contains("not valid for other.test"), "{n}");
    // A user certificate presented as a host key.
    let n = note(check([&ca], "host.test", 22, &key(CERT_USER), NOW_2030));
    assert!(n.contains("user certificate"), "{n}");
    // The CA does not cover the host.
    let narrow = entry("*.example", CA, KnownHostMarker::CertAuthority);
    let n = note(check(
        [&narrow],
        "host.test",
        22,
        &key(CERT_VALID),
        NOW_2030,
    ));
    assert!(n.contains("not trusted"), "{n}");
    // A plain CA entry (no marker) does not trust certificates.
    let n = note(check(
        [&plain("*.test", CA)],
        "host.test",
        22,
        &key(CERT_VALID),
        NOW_2030,
    ));
    assert!(n.contains("not trusted"), "{n}");
    // A tampered certificate (a principal rewritten after signing) fails the
    // signature check.
    let mut parts = CERT_VALID.split_whitespace();
    let (algo, b64) = (parts.next().unwrap(), parts.next().unwrap());
    let mut blob = key_blob(b64).unwrap();
    let at = blob.windows(8).position(|w| w == b"web.test").unwrap();
    blob[at..at + 8].copy_from_slice(b"evil.tst");
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    let tampered = format!("{algo} {}", STANDARD.encode(&blob));
    let n = note(check([&ca], "evil.tst", 22, &key(&tampered), NOW_2030));
    assert!(n.contains("not trusted") || n.contains("signature"), "{n}");
    let ca_all = entry("*", CA, KnownHostMarker::CertAuthority);
    let n = note(check([&ca_all], "evil.tst", 22, &key(&tampered), NOW_2030));
    assert!(n.contains("signature does not verify"), "{n}");
}

/// T-07: the SHA256 fingerprint equals `ssh-keygen -lf`.
#[test]
fn t07_fingerprint() {
    let recorded = include_str!("testdata/ed25519.randomart.txt");
    let want = recorded.split_whitespace().nth(1).unwrap();
    assert_eq!(want, "SHA256:uYxmMoF3aflKiV/iuu80yjcxVbhqOX/6YopX8ub8Jko");
    let info = key(ED25519).info();
    assert_eq!(info.fingerprint, want);
    assert_eq!(info.key_type, "ssh-ed25519");
    let blob = key_blob(ED25519.split_whitespace().nth(1).unwrap()).unwrap();
    assert_eq!(fingerprint_sha256(&blob), want);
    assert_eq!(entry_fingerprint(&plain("h", ED25519)), want);
}

/// T-08: randomart equals `ssh-keygen -lv` for ed25519, ecdsa and rsa.
#[test]
fn t08_randomart() {
    for (pub_line, recorded) in [
        (ED25519, include_str!("testdata/ed25519.randomart.txt")),
        (ECDSA, include_str!("testdata/ecdsa.randomart.txt")),
        (RSA, include_str!("testdata/rsa.randomart.txt")),
    ] {
        let mut lines = recorded.lines();
        let header = lines.next().unwrap();
        let art: Vec<&str> = lines.collect();
        let info = key(pub_line).info();
        assert_eq!(info.randomart, art.join("\n"), "{pub_line}");
        assert_eq!(header.split_whitespace().nth(1).unwrap(), info.fingerprint);
        assert_eq!(
            header.split_whitespace().next().unwrap(),
            info.bits.to_string()
        );
    }
    // Long titles fall back to `[TYPE]`, like OpenSSH.
    let art = randomart(&[0; 32], "ECDSA-SK-CERT", 256);
    assert!(art.starts_with("+-[ECDSA-SK-CERT]-+"), "{art}");
}

/// T-09: comments, markers, hashed lines, certs, sk keys and one malformed line.
#[test]
fn t09_parser() {
    let (entries, warnings) = parse_known_hosts(FIXTURE);
    assert_eq!(
        warnings,
        [ParseWarning {
            line: 12,
            reason: "missing key".into()
        }]
    );
    let summary: Vec<(&str, &str, KnownHostMarker, Option<&str>)> = entries
        .iter()
        .map(|e| {
            (
                if hashed::is_hashed(&e.host_pattern) {
                    "(hashed)"
                } else {
                    e.host_pattern.as_str()
                },
                e.key_type.as_str(),
                e.marker,
                e.comment.as_deref(),
            )
        })
        .collect();
    use KnownHostMarker::{CertAuthority, None as Plain, Revoked};
    assert_eq!(
        summary,
        [
            (
                "example.com,10.0.0.1",
                "ssh-ed25519",
                Plain,
                Some("a comment with spaces")
            ),
            ("[web.example.com]:2222", "ecdsa-sha2-nistp256", Plain, None),
            ("(hashed)", "ssh-ed25519", Plain, None),
            (
                "*.test,!bad.test",
                "ssh-ed25519",
                CertAuthority,
                Some("test-ca")
            ),
            ("*", "ssh-rsa", Revoked, None),
            (
                "host.test",
                "ecdsa-sha2-nistp256-cert-v01@openssh.com",
                Plain,
                None
            ),
            ("sk.example.com", "sk-ssh-ed25519@openssh.com", Plain, None),
            (
                "sk2.example.com",
                "sk-ecdsa-sha2-nistp256@openssh.com",
                Plain,
                Some("yubikey")
            ),
            ("rsa.example.com", "ssh-rsa", Plain, None),
        ]
    );
    // sk keys decode, with OpenSSH's fingerprints.
    let sk = KeyInfo::of_entry(&entries[6]).unwrap();
    assert_eq!(
        sk.fingerprint,
        "SHA256:j2zvHCyURfdHaEsu3oIKAY579g5uRlsm6vRP5IvWIlQ"
    );
    // Header and first row as `ssh-keygen -lv` prints them for this key.
    assert!(
        sk.randomart
            .starts_with("+[ED25519-SK 256]-+\n|          . .  ..|"),
        "{}",
        sk.randomart
    );
    let sk2 = KeyInfo::of_entry(&entries[7]).unwrap();
    assert_eq!(
        sk2.fingerprint,
        "SHA256:5fZTmb9Oeum6lZzVHjexE8WoXXaPZDv8pnv5HcO5a3Q"
    );

    // Export round-trips.
    let text = export(&entries);
    let (again, w) = parse_known_hosts(&text);
    assert!(w.is_empty());
    assert_eq!(again, entries);
}

#[test]
fn parser_edge_cases() {
    let ed = ED25519.split_whitespace().nth(1).unwrap();
    let text = format!(
        "h ssh-foo {ed}\n\
         @weird h ssh-ed25519 {ed}\n\
         h ssh-ed25519 !!notbase64\n\
         h ssh-rsa {ed}\n\
         |1|bad|bad ssh-ed25519 {ed}\n\
         @cert-authority\n\
         h2 ssh-ed25519 {ed}\n"
    );
    let (entries, warnings) = parse_known_hosts(&text);
    let reasons: Vec<(usize, &str)> = warnings
        .iter()
        .map(|w| (w.line, w.reason.as_str()))
        .collect();
    assert_eq!(
        reasons,
        [
            (1, "key type ssh-foo does not match the key (ssh-ed25519)"),
            (2, "unknown marker @weird"),
            (3, "the key is not valid base64"),
            (4, "key type ssh-rsa does not match the key (ssh-ed25519)"),
            (5, "malformed hashed host name"),
            (6, "missing host patterns"),
        ]
    );
    assert_eq!(entries.len(), 1);

    // An unknown key type whose blob says the same is kept (opaque) with a warning.
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    let mut blob = Vec::new();
    blob.extend_from_slice(&15_u32.to_be_bytes());
    blob.extend_from_slice(b"ssh-future-key1");
    blob.extend_from_slice(&[0, 0, 0, 1, 7]);
    let line = format!("f.example ssh-future-key1 {} c", STANDARD.encode(&blob));
    let (entries, warnings) = parse_known_hosts(&line);
    assert_eq!(entries.len(), 1);
    assert_eq!(
        warnings[0].reason,
        "unknown key type ssh-future-key1 (kept as is)"
    );
    assert_eq!(to_line(&entries[0]), line);
    assert!(KeyInfo::of_entry(&entries[0]).is_some());
}

/// Multiple keys per host: one per type; `key_types_for` lists them.
#[test]
fn multiple_keys_per_host() {
    let entries = [plain("h", ECDSA), plain("h", RSA), plain("other", ED25519)];
    assert_eq!(
        key_types_for(&entries, "h", 22),
        ["ecdsa-sha2-nistp256", "ssh-rsa"]
    );
    assert!(key_types_for(&entries, "h", 2222).is_empty());
    assert_eq!(check(&entries, "h", 22, &key(ECDSA), 0), CheckResult::Known);
    assert_eq!(check(&entries, "h", 22, &key(RSA), 0), CheckResult::Known);
    assert!(matches!(
        check(&entries, "h", 22, &key(ED25519), 0),
        CheckResult::Unknown { .. }
    ));
    // Port-specific entries.
    let entries = [plain("[h]:2222", ED25519)];
    assert_eq!(
        check(&entries, "h", 2222, &key(ED25519), 0),
        CheckResult::Known
    );
    assert!(matches!(
        check(&entries, "h", 22, &key(ED25519), 0),
        CheckResult::Unknown { .. }
    ));
}

/// T-13: with `hash_known_hosts`, new entries are hashed and match on lookup.
#[test]
fn t13_hash_known_hosts() {
    let info = key(ED25519).info();
    let hashed_entry = new_entry("db.example", 2222, &info, true, UnixMillis(5));
    assert!(hashed::is_hashed(&hashed_entry.host_pattern));
    assert!(!hashed_entry.host_pattern.contains("db.example"));
    assert_eq!(hashed_entry.added_at, UnixMillis(5));
    assert_eq!(
        check([&hashed_entry], "db.example", 2222, &key(ED25519), 0),
        CheckResult::Known
    );
    assert!(matches!(
        check([&hashed_entry], "db.example", 22, &key(ED25519), 0),
        CheckResult::Unknown { .. }
    ));
    // Fresh salts: two hashes of the same host differ.
    let again = new_entry("db.example", 2222, &info, true, UnixMillis(5));
    assert_ne!(again.host_pattern, hashed_entry.host_pattern);

    let plain_entry = new_entry("db.example", 2222, &info, false, UnixMillis(5));
    assert_eq!(plain_entry.host_pattern, "[db.example]:2222");
    assert_eq!(
        to_line(&plain_entry),
        format!("[db.example]:2222 {} {}", info.key_type, info.base64)
    );
}

#[test]
fn rsa_signature_names_share_the_key_type() {
    assert!(same_key_type("ssh-rsa", "rsa-sha2-512"));
    assert!(!same_key_type("ssh-ed25519", "ssh-rsa"));
}

/// T-18 (the fuzz target's body as a property test): arbitrary text never panics the
/// parser, the matcher, the export or the key decoding.
mod fuzz {
    use proptest::prelude::*;

    use super::super::{check::KeyInfo, export, lookup, parse_known_hosts};

    proptest! {
        #[test]
        fn parser_never_panics(text in "(?s).{0,400}", lines in proptest::collection::vec(
            "(@cert-authority |@revoked |@x )?[|*?!,a-z0-9.\\[\\]:]{0,30} (ssh-ed25519|ssh-rsa|x) [A-Za-z0-9+/=]{0,80}( c)?",
            0..6,
        )) {
            for input in [text, lines.join("\n")] {
                let (entries, _) = parse_known_hosts(&input);
                let _ = lookup(&entries, "host.example", 2222);
                let _ = export(&entries);
                for e in &entries {
                    let _ = KeyInfo::of_entry(e);
                }
            }
        }
    }
}
