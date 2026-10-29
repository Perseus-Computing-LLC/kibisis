//! Journal format 3 vectors shared with the Python suite (`tests/test_journal_vectors.py`).
//!
//! `tests/fixtures/journal_format3_vectors.json` is written by `tests/fixtures/make_journal_vectors.py`
//! from the Python reference (`kibisis.vault._event_hash` / `_head_mac`). Every vector is recomputed here
//! with `kibisis::journal`, so the two implementations hash byte for byte alike or a test fails.

use kibisis::journal::{
    event_hash_v3, event_payload_v3, head_mac_v1, hmac_sha256_hex, json_quote, verify_chain, ChainError,
    EventFields, JournalHead, GENESIS_HASH, HEAD_MAC_DOMAIN, JOURNAL_FORMAT,
};
use kibisis::AuditEvent;
use serde_json::Value;

fn load() -> Value {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/journal_format3_vectors.json");
    let text = std::fs::read_to_string(path).expect("vector file");
    serde_json::from_str(&text).expect("vector json")
}

fn hex_to_bytes(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("hex"))
        .collect()
}

fn s<'a>(v: &'a Value, k: &str) -> &'a str {
    v[k].as_str().unwrap_or_else(|| panic!("string field {k}"))
}

fn opt_s<'a>(v: &'a Value, k: &str) -> Option<&'a str> {
    v[k].as_str()
}

/// Canonical metadata JSON: sorted keys, no spaces; `null` metadata is `{}`.
///
/// serde_json without `preserve_order` keeps object keys in a BTreeMap, so `to_string` gives the same
/// bytes as Python's `json.dumps(..., sort_keys=True, separators=(",", ":"), ensure_ascii=False)` for
/// the scalar types the vectors use (strings, integers, booleans, null, lists, nested objects).
fn canonical_metadata(v: &Value) -> Option<String> {
    match &v["metadata"] {
        Value::Null => None,
        other => Some(serde_json::to_string(other).expect("canonical metadata")),
    }
}

fn fields<'a>(v: &'a Value, metadata_json: Option<&'a str>) -> EventFields<'a> {
    EventFields {
        sequence: v["sequence"].as_u64().expect("sequence fits u64"),
        timestamp: v["timestamp"].as_f64().expect("timestamp"),
        action: s(v, "action"),
        category: s(v, "category"),
        key: s(v, "key"),
        scope: s(v, "scope"),
        value_sha256: s(v, "value_sha256"),
        prev_hash: s(v, "prev_hash"),
        author_id: opt_s(v, "author_id"),
        metadata_json,
    }
}

#[test]
fn vector_file_header_matches_the_crate() {
    let data = load();
    assert_eq!(data["journal_format"].as_u64().unwrap(), u64::from(JOURNAL_FORMAT));
    assert_eq!(JOURNAL_FORMAT, 3);
    assert_eq!(data["head_mac_domain"].as_str().unwrap().as_bytes(), HEAD_MAC_DOMAIN);
    assert_eq!(GENESIS_HASH, "0".repeat(64));
    assert!(data["events"].as_array().unwrap().len() >= 12);
}

#[test]
fn every_event_vector_rederives_byte_for_byte() {
    let data = load();
    let events = data["events"].as_array().expect("events");
    for v in events {
        let name = s(v, "name");
        let meta = canonical_metadata(v);
        assert_eq!(
            meta.as_deref().unwrap_or("{}"),
            s(v, "metadata_canonical"),
            "{name}: canonical metadata"
        );
        let f = fields(v, meta.as_deref());
        assert_eq!(event_payload_v3(&f), s(v, "payload"), "{name}: payload");
        let hash = event_hash_v3(&f);
        assert_eq!(hash, s(v, "event_hash"), "{name}: event hash");
        let key = hex_to_bytes(s(v, "signing_key_hex"));
        assert_eq!(head_mac_v1(&key, f.sequence, &hash), s(v, "head_mac"), "{name}: head mac");
    }
}

#[test]
fn json_quote_matches_python_ensure_ascii_false() {
    assert_eq!(json_quote(""), "\"\"");
    assert_eq!(json_quote("plain"), "\"plain\"");
    assert_eq!(json_quote("a\"b\\c"), "\"a\\\"b\\\\c\"");
    assert_eq!(json_quote("\n\r\t\u{8}\u{c}"), "\"\\n\\r\\t\\b\\f\"");
    assert_eq!(json_quote("\u{0}\u{1}\u{1f}"), "\"\\u0000\\u0001\\u001f\"");
    // '/' and DEL are not escaped; non-ASCII (BMP and above) is written raw.
    assert_eq!(json_quote("/\u{7f}café日🔑"), "\"/\u{7f}café日🔑\"");
}

#[test]
fn hmac_sha256_matches_rfc_4231() {
    // RFC 4231 test case 2.
    assert_eq!(
        hmac_sha256_hex(b"Jefe", b"what do ya want for nothing?"),
        "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
    );
    // RFC 4231 test case 6: a key longer than the block size is hashed first.
    assert_eq!(
        hmac_sha256_hex(&[0xaa; 131], b"Test Using Larger Than Block-Size Key - Hash Key First"),
        "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
    );
}

#[test]
fn colon_join_ambiguity_is_resolved() {
    let data = load();
    let by_name = |n: &str| {
        data["events"]
            .as_array()
            .unwrap()
            .iter()
            .find(|e| s(e, "name") == n)
            .cloned()
            .unwrap_or_else(|| panic!("vector {n}"))
    };
    let a = by_name("colon_fields_are_unambiguous");
    let b = by_name("colon_fields_are_unambiguous_shifted");
    assert_eq!(
        format!("{}:{}", s(&a, "category"), s(&a, "key")),
        format!("{}:{}", s(&b, "category"), s(&b, "key"))
    );
    assert_ne!(event_hash_v3(&fields(&a, None)), event_hash_v3(&fields(&b, None)));
}

// --- the chain vector: links, head, tail cut, mid-chain edit ----------------------------------------

fn chain() -> (Vec<AuditEvent>, JournalHead, Vec<u8>) {
    let data = load();
    let c = &data["chain"];
    let key = hex_to_bytes(s(c, "signing_key_hex"));
    let events = c["events"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| {
            let ts = v["timestamp"].as_f64().unwrap();
            assert_eq!(ts.fract(), 0.0, "chain timestamps are whole seconds");
            AuditEvent {
                sequence: v["sequence"].as_u64().unwrap(),
                timestamp: ts as u64,
                action: s(v, "action").to_string(),
                category: s(v, "category").to_string(),
                key: s(v, "key").to_string(),
                scope: s(v, "scope").to_string(),
                value_sha256: s(v, "value_sha256").to_string(),
                prev_hash: s(v, "prev_hash").to_string(),
                event_hash: s(v, "event_hash").to_string(),
                author_id: opt_s(v, "author_id").map(str::to_string),
                metadata_json: canonical_metadata(v),
                format: v["format"].as_u64().unwrap() as u8,
            }
        })
        .collect::<Vec<_>>();
    let head = JournalHead {
        sequence: c["head"]["sequence"].as_u64().unwrap(),
        event_hash: s(&c["head"], "event_hash").to_string(),
        mac: s(&c["head"], "mac").to_string(),
    };
    (events, head, key)
}

#[test]
fn chain_vector_verifies() {
    let (events, head, key) = chain();
    assert_eq!(events.len(), 5);
    assert!(events.iter().all(|e| e.format == 3));
    assert_eq!(verify_chain(&events, Some(&head), &key), Ok(()));
    assert_eq!(JournalHead::sign(&key, head.sequence, &head.event_hash), head);
    // An empty journal with no head is sound.
    assert_eq!(verify_chain(&[], None, &key), Ok(()));
}

#[test]
fn chain_vector_tail_cut_fails() {
    let (events, head, key) = chain();
    let cut = &events[..events.len() - 1];
    assert!(matches!(
        verify_chain(cut, Some(&head), &key),
        Err(ChainError::TailCut { head_sequence: 5, last_sequence: Some(4) })
    ));
    assert!(matches!(
        verify_chain(&events[..3], Some(&head), &key),
        Err(ChainError::TailCut { head_sequence: 5, last_sequence: Some(3) })
    ));
    // Every row removed, head left behind.
    assert!(matches!(
        verify_chain(&[], Some(&head), &key),
        Err(ChainError::TailCut { head_sequence: 5, last_sequence: None })
    ));
    // Head removed: a format 3 journal must be anchored.
    assert_eq!(verify_chain(&events, None, &key), Err(ChainError::MissingHead));
    // Re-pointing the head at the new last row needs the signing key.
    let forged = JournalHead {
        sequence: 4,
        event_hash: cut[3].event_hash.clone(),
        mac: "00".repeat(32),
    };
    assert_eq!(verify_chain(cut, Some(&forged), &key), Err(ChainError::HeadMac));
    let resigned = JournalHead::sign(&key, 4, &cut[3].event_hash);
    assert_eq!(verify_chain(cut, Some(&resigned), &key), Ok(()));
    assert_eq!(verify_chain(cut, Some(&resigned), b"not the key"), Err(ChainError::HeadMac));
}

#[test]
fn chain_vector_mid_chain_edit_fails() {
    let (events, head, key) = chain();
    let edits: Vec<(&str, Box<dyn Fn(&mut AuditEvent)>)> = vec![
        ("key", Box::new(|e| e.key = "k9".into())),
        ("author_id", Box::new(|e| e.author_id = Some("mallory".into()))),
        ("metadata", Box::new(|e| e.metadata_json = Some(r#"{"reviewer":"mallory"}"#.into()))),
        ("value_sha256", Box::new(|e| e.value_sha256 = "f".repeat(64))),
        ("timestamp", Box::new(|e| e.timestamp += 1)),
    ];
    for (name, edit) in edits {
        let mut edited = events.clone();
        edit(&mut edited[2]);
        assert_eq!(
            verify_chain(&edited, Some(&head), &key),
            Err(ChainError::HashMismatch { sequence: 3 }),
            "{name}"
        );
    }
    // Rewriting the hash to match the edit breaks the link to the next row instead.
    let mut relinked = events.clone();
    relinked[2].key = "k9".into();
    relinked[2].event_hash = event_hash_v3(&relinked[2].fields());
    assert_eq!(
        verify_chain(&relinked, Some(&head), &key),
        Err(ChainError::BrokenLink { sequence: 4 })
    );
    // Rows out of order or with a gap are rejected before any hashing.
    let mut swapped = events.clone();
    swapped.swap(0, 1);
    assert_eq!(
        verify_chain(&swapped, Some(&head), &key),
        Err(ChainError::Sequence { index: 0, sequence: 2 })
    );
}
