//! Audit journal format 3: canonical-JSON event hashes and an HMAC-signed chain head.
//!
//! This module is the Rust side of the layout the Python vault writes (`kibisis.vault.JOURNAL_FORMAT == 3`,
//! `_event_hash`, `_head_mac`). Both sides are checked against one vector file,
//! `tests/fixtures/journal_format3_vectors.json`, so they hash byte for byte alike.
//!
//! An event's hash is the SHA-256 of a compact JSON array:
//!
//! ```text
//! [sequence, "timestamp.6f", action, category, key, scope, value_sha256, prev_hash, author_id or "", meta_digest]
//! ```
//!
//! where `meta_digest` is the SHA-256 hex of the metadata object as compact JSON with sorted keys (`{}` when
//! there is none). JSON strings escape only `"`, `\` and U+0000..U+001F (as `\b \f \n \r \t` or `\u00xx`),
//! and non-ASCII text is written raw, which is what Python's `json.dumps(..., ensure_ascii=False)` emits.
//!
//! The chain head is `HMAC-SHA256(signing_key, "kibisis audit head v1:" + "[sequence,\"event_hash\"]")`.
//! It is re-signed on every append, so removing rows from the tail, or the head itself, fails
//! [`verify_chain`]. Without a secret key the head catches accidental truncation only.

use std::fmt;

use crate::{sha256, AuditEvent};

/// Layout version written by this crate; rows carry it in [`AuditEvent::format`].
pub const JOURNAL_FORMAT: u8 = 3;

/// `prev_hash` of the first event.
pub const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// Domain separator prefixed to the head MAC payload.
pub const HEAD_MAC_DOMAIN: &[u8] = b"kibisis audit head v1:";

/// Canonical metadata of an event without metadata.
pub const EMPTY_METADATA_JSON: &str = "{}";

const SHA256_BLOCK: usize = 64;

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// HMAC-SHA256 (RFC 2104) as lowercase hex, over the crate's own SHA-256.
pub fn hmac_sha256_hex(key: &[u8], message: &[u8]) -> String {
    let mut block = [0u8; SHA256_BLOCK];
    if key.len() > SHA256_BLOCK {
        block[..32].copy_from_slice(&sha256(key));
    } else {
        block[..key.len()].copy_from_slice(key);
    }
    let mut inner = Vec::with_capacity(SHA256_BLOCK + message.len());
    inner.extend(block.iter().map(|b| b ^ 0x36));
    inner.extend_from_slice(message);
    let inner_hash = sha256(&inner);
    let mut outer = Vec::with_capacity(SHA256_BLOCK + 32);
    outer.extend(block.iter().map(|b| b ^ 0x5c));
    outer.extend_from_slice(&inner_hash);
    hex(&sha256(&outer))
}

/// Quote `s` as a JSON string literal the way Python's `json.dumps(s, ensure_ascii=False)` does.
///
/// Escapes `"` and `\`, writes U+0008/U+000C/U+000A/U+000D/U+0009 as `\b \f \n \r \t`, other code
/// points below U+0020 as `\u00xx` (lowercase hex), and everything else, including `/`, DEL and all
/// non-ASCII text, as itself.
pub fn json_quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// The fields one event's hash covers.
///
/// `metadata_json` must already be canonical: compact (`,` and `:` separators, no spaces) with object keys
/// sorted by code point at every level. `None` means no metadata and hashes as `{}`. Avoid floats in
/// metadata: JSON writers differ in how they print the same double, so a float is not guaranteed to hash
/// alike across implementations.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct EventFields<'a> {
    pub sequence: u64,
    /// Seconds since the UNIX epoch; hashed as its `.6f` rendering.
    pub timestamp: f64,
    pub action: &'a str,
    pub category: &'a str,
    pub key: &'a str,
    pub scope: &'a str,
    pub value_sha256: &'a str,
    pub prev_hash: &'a str,
    pub author_id: Option<&'a str>,
    pub metadata_json: Option<&'a str>,
}

/// SHA-256 hex of the canonical metadata JSON (`{}` when `None`).
pub fn metadata_digest(metadata_json: Option<&str>) -> String {
    hex(&sha256(
        metadata_json.unwrap_or(EMPTY_METADATA_JSON).as_bytes(),
    ))
}

/// The exact bytes [`event_hash_v3`] hashes, as a string. Exposed for vector tests and diagnostics.
pub fn event_payload_v3(f: &EventFields<'_>) -> String {
    let mut out = String::with_capacity(320);
    out.push('[');
    out.push_str(&f.sequence.to_string());
    for field in [
        format!("{:.6}", f.timestamp),
        f.action.to_string(),
        f.category.to_string(),
        f.key.to_string(),
        f.scope.to_string(),
        f.value_sha256.to_string(),
        f.prev_hash.to_string(),
        f.author_id.unwrap_or("").to_string(),
        metadata_digest(f.metadata_json),
    ] {
        out.push(',');
        out.push_str(&json_quote(&field));
    }
    out.push(']');
    out
}

/// Format 3 event hash: SHA-256 hex of [`event_payload_v3`].
pub fn event_hash_v3(f: &EventFields<'_>) -> String {
    hex(&sha256(event_payload_v3(f).as_bytes()))
}

/// Version 1 head MAC: HMAC-SHA256 hex over `"kibisis audit head v1:[sequence,"event_hash"]"`.
pub fn head_mac_v1(signing_key: &[u8], sequence: u64, event_hash: &str) -> String {
    let mut message = Vec::with_capacity(HEAD_MAC_DOMAIN.len() + 90);
    message.extend_from_slice(HEAD_MAC_DOMAIN);
    message.push(b'[');
    message.extend_from_slice(sequence.to_string().as_bytes());
    message.push(b',');
    message.extend_from_slice(json_quote(event_hash).as_bytes());
    message.push(b']');
    hmac_sha256_hex(signing_key, &message)
}

/// The signed chain head: which row is last, under which hash, and the MAC binding the two.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JournalHead {
    pub sequence: u64,
    pub event_hash: String,
    pub mac: String,
}

impl JournalHead {
    /// Sign `(sequence, event_hash)` as the current head.
    pub fn sign(signing_key: &[u8], sequence: u64, event_hash: &str) -> Self {
        JournalHead {
            sequence,
            event_hash: event_hash.to_string(),
            mac: head_mac_v1(signing_key, sequence, event_hash),
        }
    }
}

/// Why a journal failed [`verify_chain`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainError {
    /// Row `index` (0-based) carries `sequence` instead of `index + 1`: a gap, duplicate or reorder.
    Sequence { index: usize, sequence: u64 },
    /// A row this crate cannot recompute (only format 3 is supported).
    UnsupportedFormat { sequence: u64, format: u8 },
    /// A row's `prev_hash` is not the previous row's `event_hash`.
    BrokenLink { sequence: u64 },
    /// A row's recorded `event_hash` is not the hash of its fields: the row was edited.
    HashMismatch { sequence: u64 },
    /// Format 3 rows exist but no signed head does.
    MissingHead,
    /// The head's MAC does not verify under the signing key.
    HeadMac,
    /// The head is signed for a row past the end of the journal: rows were removed from the tail.
    TailCut {
        head_sequence: u64,
        last_sequence: Option<u64>,
    },
    /// The head is signed for a row that is not the last one (or for a different hash at that sequence).
    HeadMismatch {
        head_sequence: u64,
        last_sequence: u64,
    },
}

impl fmt::Display for ChainError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ChainError::Sequence { index, sequence } => {
                write!(f, "row {index} has sequence {sequence}, expected {}", index + 1)
            }
            ChainError::UnsupportedFormat { sequence, format } => {
                write!(f, "row {sequence} has journal format {format}; this crate verifies format 3")
            }
            ChainError::BrokenLink { sequence } => write!(f, "row {sequence} does not link to the row before it"),
            ChainError::HashMismatch { sequence } => write!(f, "row {sequence} was edited: hash mismatch"),
            ChainError::MissingHead => write!(f, "format 3 journal has no signed head"),
            ChainError::HeadMac => write!(f, "signed head does not verify under the signing key"),
            ChainError::TailCut {
                head_sequence,
                last_sequence,
            } => write!(
                f,
                "journal truncated: head signed at sequence {head_sequence}, last row is {}",
                last_sequence.map_or("none".to_string(), |s| s.to_string())
            ),
            ChainError::HeadMismatch {
                head_sequence,
                last_sequence,
            } => write!(
                f,
                "head signed at sequence {head_sequence} does not name the last row ({last_sequence})"
            ),
        }
    }
}

impl std::error::Error for ChainError {}

fn constant_time_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Verify every link and hash in `events`, then the signed head.
///
/// Rows must be in order with sequences `1..=n`. With a head, its MAC must verify under `signing_key` and
/// it must name the last row: a head past the end means rows were cut from the tail; a head with no rows
/// means the whole journal was removed. Without a head, a journal that contains format 3 rows fails
/// ([`ChainError::MissingHead`]); an empty journal with no head is sound.
pub fn verify_chain(
    events: &[AuditEvent],
    head: Option<&JournalHead>,
    signing_key: &[u8],
) -> Result<(), ChainError> {
    let mut expected_prev = GENESIS_HASH;
    for (index, ev) in events.iter().enumerate() {
        if ev.sequence != (index as u64) + 1 {
            return Err(ChainError::Sequence {
                index,
                sequence: ev.sequence,
            });
        }
        if ev.format != JOURNAL_FORMAT {
            return Err(ChainError::UnsupportedFormat {
                sequence: ev.sequence,
                format: ev.format,
            });
        }
        if ev.prev_hash != expected_prev {
            return Err(ChainError::BrokenLink {
                sequence: ev.sequence,
            });
        }
        if !constant_time_eq(&event_hash_v3(&ev.fields()), &ev.event_hash) {
            return Err(ChainError::HashMismatch {
                sequence: ev.sequence,
            });
        }
        expected_prev = &ev.event_hash;
    }

    let anchored = events.iter().any(|ev| ev.format >= 3);
    let head = match head {
        None if anchored => return Err(ChainError::MissingHead),
        None => return Ok(()),
        Some(h) => h,
    };
    if !constant_time_eq(
        &head_mac_v1(signing_key, head.sequence, &head.event_hash),
        &head.mac,
    ) {
        return Err(ChainError::HeadMac);
    }
    match events.last() {
        None => Err(ChainError::TailCut {
            head_sequence: head.sequence,
            last_sequence: None,
        }),
        Some(last) if head.sequence > last.sequence => Err(ChainError::TailCut {
            head_sequence: head.sequence,
            last_sequence: Some(last.sequence),
        }),
        Some(last) if head.sequence != last.sequence || head.event_hash != last.event_hash => {
            Err(ChainError::HeadMismatch {
                head_sequence: head.sequence,
                last_sequence: last.sequence,
            })
        }
        Some(_) => Ok(()),
    }
}
