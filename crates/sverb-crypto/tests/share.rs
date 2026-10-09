//! Terminal-share cryptography (§14.2). T-01..T-07.
//!
//! The KAT constants in `t01_*` are FROZEN: any change is a breaking wire
//! change. The HMAC and HKDF values were cross-checked with Python's `hmac` /
//! `hashlib` (HKDF-SHA256 per RFC 5869) when they were generated.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use chacha20::ChaCha20Rng;
use rand_core::SeedableRng;
use sverb_crypto::Key32;
use sverb_crypto::share::{
    Channel, ChannelError, ChannelKeys, Hello, HostHandshake, LinkError, Role, ShareKey, ShareLink,
    ViewerHandshake, Welcome, derive_channel_keys, hello_mac, welcome_mac,
};

const SHARE_KEY: [u8; 32] = [0x11; 32];
const SHARE_ID: [u8; 16] = [0x22; 16];

fn rng(seed: u8) -> ChaCha20Rng {
    ChaCha20Rng::from_seed([seed; 32])
}

fn h(b: &[u8]) -> String {
    hex::encode(b)
}

fn pubkey(scalar: [u8; 32]) -> [u8; 32] {
    x25519_dalek::x25519(scalar, x25519_dalek::X25519_BASEPOINT_BYTES)
}

/// Runs a full handshake and returns (host channel, viewer channel).
fn handshake(key: &ShareKey, viewer_id: u32, seed: u8) -> (Channel, Channel) {
    let (hello, state) = ViewerHandshake::start(key, &SHARE_ID, "alice", &mut rng(seed)).unwrap();
    let (welcome, host) =
        HostHandshake::respond(key, &SHARE_ID, viewer_id, &hello, &mut rng(seed + 100)).unwrap();
    let viewer = state.finish(&welcome, viewer_id).unwrap();
    (host, viewer)
}

// ---------------------------------------------------------------------------
// T-01 (KAT)
// ---------------------------------------------------------------------------

const KAT_VIEWER_PUB: &str = "7b0d47d93427f8311160781c7c733fd89f88970aef490d8aa0ee19a4cb8a1b14";
const KAT_HOST_PUB: &str = "ff2ee45601ec1b67310c7790404585ae697331eee1c1f8cf2419731c1fff3e6b";
const KAT_SHARED: &str = "3c528e9fd39731b15d10de8feb5f71d3f65b73c993581dedb03315a9ed177730";
const KAT_HELLO_MAC: &str = "b968eb8eb8f042941cb5dc3dd325a0fe1bb543bb12d0837f6b5f83219dbf8d21";
const KAT_WELCOME_MAC: &str = "bb4ab20be25152da3156f242d0678e47ada09925cc19c0adbc17ba80eab9c74a";
const KAT_K_H2V: &str = "078f0bb9ce44ac1592db3402b4e84659c3b5f51e6f09f4c59d62272f51e6eb46";
const KAT_K_V2H: &str = "e2d558f98d20f7587683df97e8e9b727c1449ca76a440005fc138eae659e8281";
const KAT_FRAME_H2V_0: &str = "0000000000000000a7abd28eaef430617a3c8d868b0c9cbdb25fdb0c4d";
const KAT_FRAME_H2V_1: &str = "00000000000000010fbdcd28ef5b1ec3b865887ff4d4ff31bbf2bd1daf";
const KAT_FRAME_V2H_0: &str = "000000000000000017340442b7ece03a68ad90bbeac5c853efb8465ce0";

#[test]
fn t01_kat_macs_keys_frames() {
    let key = ShareKey::from_bytes(SHARE_KEY);
    let vpub = pubkey([0x33; 32]);
    let hpub = pubkey([0x44; 32]);
    let shared = x25519_dalek::x25519([0x33; 32], hpub);
    assert_eq!(shared, x25519_dalek::x25519([0x44; 32], vpub));

    let actual = [
        ("viewer_pub", h(&vpub)),
        ("host_pub", h(&hpub)),
        ("shared", h(&shared)),
        ("hello_mac", h(&hello_mac(&key, &SHARE_ID, &vpub, "alice"))),
        (
            "welcome_mac",
            h(&welcome_mac(&key, &SHARE_ID, &vpub, "alice", &hpub)),
        ),
    ];
    let keys = derive_channel_keys(&shared, &key, &SHARE_ID, &vpub, &hpub);
    let k_h2v = h(keys.k_h2v.expose_secret());
    let k_v2h = h(keys.k_v2h.expose_secret());

    let fixed = || ChannelKeys {
        k_h2v: Key32::from_bytes([0x55; 32]),
        k_v2h: Key32::from_bytes([0x66; 32]),
    };
    let mut host = Channel::from_keys(fixed(), SHARE_ID, 7, Role::Host);
    let mut viewer = Channel::from_keys(fixed(), SHARE_ID, 7, Role::Viewer);
    let f0 = host.seal(b"hello").unwrap();
    let f1 = host.seal(b"world").unwrap();
    let v0 = viewer.seal(b"input").unwrap();

    let got = [
        actual[0].1.clone(),
        actual[1].1.clone(),
        actual[2].1.clone(),
        actual[3].1.clone(),
        actual[4].1.clone(),
        k_h2v,
        k_v2h,
        h(&f0),
        h(&f1),
        h(&v0),
    ];
    let want = [
        KAT_VIEWER_PUB,
        KAT_HOST_PUB,
        KAT_SHARED,
        KAT_HELLO_MAC,
        KAT_WELCOME_MAC,
        KAT_K_H2V,
        KAT_K_V2H,
        KAT_FRAME_H2V_0,
        KAT_FRAME_H2V_1,
        KAT_FRAME_V2H_0,
    ];
    if std::env::var_os("SVERB_PRINT_KAT").is_some() {
        for g in &got {
            println!("{g}");
        }
    }
    assert_eq!(got, want.map(str::to_owned));

    // Frame layout: seq (u64 BE) || ct (pt + 16-byte tag).
    assert_eq!(&f0[..8], &[0; 8]);
    assert_eq!(&f1[..8], &[0, 0, 0, 0, 0, 0, 0, 1]);
    assert_eq!(f0.len(), 8 + 5 + 16);
    // And they open in order on the other side.
    assert_eq!(&viewer.open(&f0).unwrap()[..], b"hello");
    assert_eq!(&viewer.open(&f1).unwrap()[..], b"world");
    assert_eq!(&host.open(&v0).unwrap()[..], b"input");
}

// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------

#[test]
fn t02_handshake_derives_identical_keys_and_frames_round_trip() {
    let key = ShareKey::generate(&mut rng(1));
    let (hello, state) = ViewerHandshake::start(&key, &SHARE_ID, "bob", &mut rng(2)).unwrap();
    assert_eq!(&hello.viewer_eph_pub, state.viewer_eph_pub());
    let (welcome, mut host) =
        HostHandshake::respond(&key, &SHARE_ID, 3, &hello, &mut rng(3)).unwrap();
    let mut viewer = state.finish(&welcome, 3).unwrap();
    assert_eq!(host.role(), Role::Host);
    assert_eq!(viewer.role(), Role::Viewer);
    assert_eq!(viewer.viewer_id(), 3);

    for i in 0..5u8 {
        let f = host.seal(&[i; 100]).unwrap();
        assert_eq!(&viewer.open(&f).unwrap()[..], &[i; 100]);
        let g = viewer.seal(&[i ^ 0xff; 3]).unwrap();
        assert_eq!(&host.open(&g).unwrap()[..], &[i ^ 0xff; 3]);
    }
    assert_eq!(host.next_send_seq(), 5);
    assert_eq!(viewer.next_recv_seq(), 5);
    // Empty plaintext is fine.
    let f = host.seal(b"").unwrap();
    assert!(viewer.open(&f).unwrap().is_empty());
}

#[test]
fn t02_host_uses_fresh_ephemeral_per_viewer() {
    let key = ShareKey::from_bytes(SHARE_KEY);
    let (hello_a, _) = ViewerHandshake::start(&key, &SHARE_ID, "a", &mut rng(10)).unwrap();
    let (hello_b, _) = ViewerHandshake::start(&key, &SHARE_ID, "b", &mut rng(11)).unwrap();
    let mut host_rng = rng(12);
    let (wa, _) = HostHandshake::respond(&key, &SHARE_ID, 1, &hello_a, &mut host_rng).unwrap();
    let (wb, _) = HostHandshake::respond(&key, &SHARE_ID, 2, &hello_b, &mut host_rng).unwrap();
    assert_ne!(wa.host_eph_pub, wb.host_eph_pub);
}

// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------

#[test]
fn t03_wrong_key_tampered_name_tampered_welcome() {
    let key = ShareKey::from_bytes(SHARE_KEY);
    let wrong = ShareKey::from_bytes([0x12; 32]);

    // Viewer with the wrong link key → host rejects the Hello.
    let (hello, _) = ViewerHandshake::start(&wrong, &SHARE_ID, "eve", &mut rng(20)).unwrap();
    assert_eq!(
        HostHandshake::respond(&key, &SHARE_ID, 1, &hello, &mut rng(21)).unwrap_err(),
        sverb_crypto::CryptoError::Auth
    );

    // Hello for another share id → rejected.
    let (hello, _) = ViewerHandshake::start(&key, &[0x23; 16], "eve", &mut rng(20)).unwrap();
    assert!(HostHandshake::respond(&key, &SHARE_ID, 1, &hello, &mut rng(21)).is_err());

    // Tampered name → rejected.
    let (hello, state) = ViewerHandshake::start(&key, &SHARE_ID, "alice", &mut rng(22)).unwrap();
    let tampered = Hello {
        name: "mallory".into(),
        ..hello.clone()
    };
    assert_eq!(
        HostHandshake::respond(&key, &SHARE_ID, 1, &tampered, &mut rng(23)).unwrap_err(),
        sverb_crypto::CryptoError::Auth
    );
    // Tampered public key → rejected.
    let mut tampered = hello.clone();
    tampered.viewer_eph_pub[0] ^= 1;
    assert!(HostHandshake::respond(&key, &SHARE_ID, 1, &tampered, &mut rng(23)).is_err());

    // Tampered Welcome → viewer rejects.
    let (welcome, _) = HostHandshake::respond(&key, &SHARE_ID, 1, &hello, &mut rng(24)).unwrap();
    let mut bad = welcome.clone();
    bad.host_eph_pub[5] ^= 0x40;
    assert_eq!(
        state.finish(&bad, 1).unwrap_err(),
        sverb_crypto::CryptoError::Auth
    );

    // A Welcome whose MAC was computed for a different name (transcript
    // binding) → rejected.
    let (_, state) = ViewerHandshake::start(&key, &SHARE_ID, "alice", &mut rng(22)).unwrap();
    let forged = Welcome {
        host_eph_pub: welcome.host_eph_pub,
        mac: welcome_mac(
            &key,
            &SHARE_ID,
            &hello.viewer_eph_pub,
            "someone-else",
            &welcome.host_eph_pub,
        ),
    };
    assert!(state.finish(&forged, 1).is_err());

    // A Hello MAC is never a valid Welcome MAC.
    let (_, state) = ViewerHandshake::start(&key, &SHARE_ID, "alice", &mut rng(22)).unwrap();
    let reflected = Welcome {
        host_eph_pub: welcome.host_eph_pub,
        mac: hello.mac,
    };
    assert!(state.finish(&reflected, 1).is_err());
}

#[test]
fn t03_low_order_point_and_long_name_rejected() {
    let key = ShareKey::from_bytes(SHARE_KEY);
    let zero = [0u8; 32];
    let hello = Hello {
        viewer_eph_pub: zero,
        name: String::new(),
        mac: hello_mac(&key, &SHARE_ID, &zero, ""),
    };
    assert!(HostHandshake::respond(&key, &SHARE_ID, 1, &hello, &mut rng(30)).is_err());

    let long = "x".repeat(sverb_crypto::share::MAX_NAME_LEN + 1);
    assert!(ViewerHandshake::start(&key, &SHARE_ID, &long, &mut rng(31)).is_err());
}

// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------

#[test]
fn t04_viewers_are_isolated() {
    let key = ShareKey::from_bytes(SHARE_KEY);
    let (mut host_a, mut viewer_a) = handshake(&key, 1, 40);
    let (mut host_b, mut viewer_b) = handshake(&key, 2, 41);

    // A frame for viewer B can't be opened by viewer A.
    let fb = host_b.seal(b"for b").unwrap();
    assert_eq!(viewer_a.open(&fb).unwrap_err(), ChannelError::Auth);
    assert_eq!(&viewer_b.open(&fb).unwrap()[..], b"for b");

    // Viewer B can't forge input that the host accepts on A's channel.
    let ib = viewer_b.seal(b"rm -rf /").unwrap();
    assert_eq!(host_a.open(&ib).unwrap_err(), ChannelError::Auth);
}

#[test]
fn t04_frame_replayed_to_other_viewer_id_fails_aad() {
    // Same keys, different viewer_id → AAD mismatch.
    let key = ShareKey::from_bytes(SHARE_KEY);
    let (hello, state) = ViewerHandshake::start(&key, &SHARE_ID, "alice", &mut rng(50)).unwrap();
    let (welcome, mut host) =
        HostHandshake::respond(&key, &SHARE_ID, 1, &hello, &mut rng(51)).unwrap();
    let mut viewer = state.finish(&welcome, 2).unwrap();
    let f = host.seal(b"x").unwrap();
    assert_eq!(viewer.open(&f).unwrap_err(), ChannelError::Auth);

    // Same keys, different share id → AAD mismatch.
    let mk = || ChannelKeys {
        k_h2v: Key32::from_bytes([1; 32]),
        k_v2h: Key32::from_bytes([2; 32]),
    };
    let mut h = Channel::from_keys(mk(), SHARE_ID, 1, Role::Host);
    let mut v = Channel::from_keys(mk(), [0x99; 16], 1, Role::Viewer);
    assert_eq!(
        v.open(&h.seal(b"x").unwrap()).unwrap_err(),
        ChannelError::Auth
    );
}

// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------

#[test]
fn t05_replay_is_sequence_error_and_closes() {
    let (mut host, mut viewer) = handshake(&ShareKey::from_bytes(SHARE_KEY), 1, 60);
    let f0 = host.seal(b"a").unwrap();
    viewer.open(&f0).unwrap();
    assert_eq!(viewer.open(&f0).unwrap_err(), ChannelError::Sequence);
    assert!(viewer.is_closed());
    let f1 = host.seal(b"b").unwrap();
    assert_eq!(viewer.open(&f1).unwrap_err(), ChannelError::Closed);
    assert_eq!(viewer.seal(b"c").unwrap_err(), ChannelError::Closed);
}

#[test]
fn t05_gap_is_sequence_error() {
    let (mut host, mut viewer) = handshake(&ShareKey::from_bytes(SHARE_KEY), 1, 61);
    let _f0 = host.seal(b"a").unwrap();
    let f1 = host.seal(b"b").unwrap();
    assert_eq!(viewer.open(&f1).unwrap_err(), ChannelError::Sequence);
    assert!(viewer.is_closed());
}

#[test]
fn t05_reorder_is_sequence_error() {
    let (mut host, mut viewer) = handshake(&ShareKey::from_bytes(SHARE_KEY), 1, 62);
    let f0 = host.seal(b"a").unwrap();
    let f1 = host.seal(b"b").unwrap();
    let f2 = host.seal(b"c").unwrap();
    viewer.open(&f0).unwrap();
    assert_eq!(viewer.open(&f2).unwrap_err(), ChannelError::Sequence);
    assert_eq!(viewer.open(&f1).unwrap_err(), ChannelError::Closed);
}

#[test]
fn t05_tampered_seq_or_ct_is_auth_error_and_closes() {
    let (mut host, mut viewer) = handshake(&ShareKey::from_bytes(SHARE_KEY), 1, 63);
    let mut f0 = host.seal(b"abc").unwrap();
    f0[7] = 1; // claims seq 1
    assert_eq!(viewer.open(&f0).unwrap_err(), ChannelError::Auth);
    assert!(viewer.is_closed());

    let (mut host, mut viewer) = handshake(&ShareKey::from_bytes(SHARE_KEY), 1, 64);
    assert_eq!(viewer.open(&[0; 7]).unwrap_err(), ChannelError::Auth);
    let _ = host.seal(b"x");

    let (mut host, mut viewer) = handshake(&ShareKey::from_bytes(SHARE_KEY), 1, 65);
    let mut f = host.seal(b"abc").unwrap();
    let last = f.len() - 1;
    f[last] ^= 1;
    assert_eq!(viewer.open(&f).unwrap_err(), ChannelError::Auth);
    let f = host.seal(b"def").unwrap();
    assert_eq!(viewer.open(&f).unwrap_err(), ChannelError::Closed);
}

#[test]
fn t05_manual_close() {
    let (mut host, _viewer) = handshake(&ShareKey::from_bytes(SHARE_KEY), 1, 66);
    host.close();
    assert_eq!(host.seal(b"x").unwrap_err(), ChannelError::Closed);
}

// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------

#[test]
fn t06_direction_confusion_is_auth_error() {
    let (mut host, mut viewer) = handshake(&ShareKey::from_bytes(SHARE_KEY), 1, 70);
    // An h2v frame fed back into the host's v2h decrypt.
    let f = host.seal(b"out").unwrap();
    assert_eq!(host.open(&f).unwrap_err(), ChannelError::Auth);
    // A v2h frame fed back into the viewer's h2v decrypt.
    let g = viewer.seal(b"in").unwrap();
    assert_eq!(viewer.open(&g).unwrap_err(), ChannelError::Auth);

    // Even with identical keys in both directions, the dir byte in the AAD
    // separates them.
    let same = || ChannelKeys {
        k_h2v: Key32::from_bytes([7; 32]),
        k_v2h: Key32::from_bytes([7; 32]),
    };
    let mut h = Channel::from_keys(same(), SHARE_ID, 1, Role::Host);
    let f = h.seal(b"x").unwrap();
    assert_eq!(h.open(&f).unwrap_err(), ChannelError::Auth);
}

// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------

#[test]
fn t07_link_round_trip() {
    let id: [u8; 16] =
        sverb_crypto::share::parse_uuid("0192f5c4-7a1b-7c3d-8e9f-0123456789ab").unwrap();
    let key = ShareKey::generate(&mut rng(80));
    let link = ShareLink::new("sync.example.com:8443", id, key.clone()).unwrap();
    let s = link.to_sverb_link();
    assert!(
        s.starts_with("sverb://join/sync.example.com:8443/0192f5c4-7a1b-7c3d-8e9f-0123456789ab#")
    );
    assert_eq!(s.split_once('#').unwrap().1.len(), 43);
    let parsed = ShareLink::parse(&s).unwrap();
    assert_eq!(parsed, link);
    assert_eq!(parsed.key(), &key);
    assert_eq!(parsed.share_id(), &id);

    let w = link.to_web_link();
    assert!(w.starts_with("https://sync.example.com:8443/s/0192f5c4-"));
    assert_eq!(ShareLink::parse(&w).unwrap(), link);

    // The server part never includes the fragment.
    assert_eq!(parsed.server(), "sync.example.com:8443");
    assert_eq!(parsed.web_base_url(), "https://sync.example.com:8443");
    assert!(!parsed.web_base_url().contains('#'));
    let fragment = s.split_once('#').unwrap().1;
    assert!(!parsed.web_base_url().contains(fragment));

    // Debug never prints the key.
    let dbg = format!("{parsed:?}");
    assert!(!dbg.contains(fragment));

    // Case-insensitive scheme, surrounding whitespace.
    let upper = format!("  SVERB://JOIN/{}  ", &s["sverb://join/".len()..]);
    assert_eq!(ShareLink::parse(&upper).unwrap(), link);
}

#[test]
fn t07_link_errors() {
    let good_id = "0192f5c4-7a1b-7c3d-8e9f-0123456789ab";
    let good_key = sverb_crypto::share::b64url_encode(&[9; 32]);
    let ok = format!("sverb://join/srv/{good_id}#{good_key}");
    assert!(ShareLink::parse(&ok).is_ok());

    let cases = [
        (
            format!("sverb://join/srv/{good_id}"),
            LinkError::MissingFragment,
        ),
        (
            format!("sverb://join/srv/{good_id}#"),
            LinkError::MissingFragment,
        ),
        (
            format!(
                "sverb://join/srv/{good_id}#{}",
                sverb_crypto::share::b64url_encode(&[9; 31])
            ),
            LinkError::Key,
        ),
        (
            format!(
                "sverb://join/srv/{good_id}#{}",
                sverb_crypto::share::b64url_encode(&[9; 33])
            ),
            LinkError::Key,
        ),
        (
            format!("sverb://join/srv/{good_id}#{good_key}="),
            LinkError::Key,
        ),
        (
            format!("sverb://join/srv/{good_id}#not*base64"),
            LinkError::Key,
        ),
        (
            format!("sverb://join/srv/not-a-uuid#{good_key}"),
            LinkError::ShareId,
        ),
        (
            format!("sverb://join/srv/{good_id}/#{good_key}"),
            LinkError::ShareId,
        ),
        (
            format!("sverb://join/{good_id}#{good_key}"),
            LinkError::ShareId,
        ),
        (
            format!("sverb://join//{good_id}#{good_key}"),
            LinkError::Server,
        ),
        (
            format!("sverb://join/u@srv/{good_id}#{good_key}"),
            LinkError::Server,
        ),
        (
            format!("ssh://join/srv/{good_id}#{good_key}"),
            LinkError::Scheme,
        ),
        (
            format!("http://srv/s/{good_id}#{good_key}"),
            LinkError::Scheme,
        ),
        (
            format!("https://srv/x/{good_id}#{good_key}"),
            LinkError::Scheme,
        ),
    ];
    for (link, want) in cases {
        assert_eq!(ShareLink::parse(&link).unwrap_err(), want, "{link}");
    }
    assert_eq!(
        ShareLink::new("a/b", [0; 16], ShareKey::from_bytes([0; 32])).unwrap_err(),
        LinkError::Server
    );
}
