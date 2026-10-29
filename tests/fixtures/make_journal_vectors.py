"""Write the journal format 3 test vectors that the Rust and Python suites share.

    python3 tests/fixtures/make_journal_vectors.py [tests/fixtures/journal_format3_vectors.json]

The Python vault (``kibisis.vault._event_hash`` and ``_head_mac``) is the reference; this script calls
those functions on the checked-out ``src/`` tree and records their output. ``tests/test_journal_vectors.py``
re-derives every vector with the same functions and ``tests/journal_vectors.rs`` recomputes them with the
crate's ``journal`` module, so the two implementations cannot drift apart without a test failing.

Vectors avoid floats inside ``metadata``: Python ``json.dumps`` writes a float as ``repr`` and other JSON
writers may format the same value differently, so a metadata float is not guaranteed to hash the same
across implementations. Timestamps are floats, but they are formatted with ``.6f`` before hashing.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
from typing import Any, Dict, List, Optional

SRC = os.path.join(os.path.dirname(os.path.abspath(__file__)), os.pardir, os.pardir, "src")
sys.path.insert(0, os.path.normpath(SRC))

from kibisis.vault import JOURNAL_FORMAT, _event_hash, _head_mac  # noqa: E402

ZERO = "0" * 64
HEAD_MAC_DOMAIN = "kibisis audit head v1:"

# Test-only keys: nothing here protects a real vault.
KEY_A = bytes(range(32))
KEY_B = hashlib.sha256(b"kibisis journal vectors key B (test only)").digest()
KEY_EMPTY = b""
KEY_LONG = bytes(range(256)) * 2  # 512 bytes: longer than the HMAC block, so it is hashed first


def _canonical_metadata(metadata: Optional[Dict[str, Any]]) -> str:
    return json.dumps(metadata or {}, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _payload(fields: List[Any]) -> str:
    return json.dumps(fields, separators=(",", ":"), ensure_ascii=False)


def _event(
    name: str,
    *,
    signing_key: bytes,
    sequence: int,
    timestamp: float,
    action: str,
    category: str,
    key: str,
    scope: str,
    value_sha256: str,
    prev_hash: str,
    author_id: Optional[str],
    metadata: Optional[Dict[str, Any]],
    note: str = "",
) -> Dict[str, Any]:
    event_hash = _event_hash(
        sequence, timestamp, action, category, key, scope, value_sha256, prev_hash, author_id, metadata,
        fmt=JOURNAL_FORMAT,
    )
    meta_canonical = _canonical_metadata(metadata)
    meta_digest = hashlib.sha256(meta_canonical.encode("utf-8")).hexdigest()
    payload = _payload(
        [int(sequence), f"{timestamp:.6f}", action, category, key, scope, value_sha256, prev_hash, author_id or "",
         meta_digest]
    )
    assert hashlib.sha256(payload.encode("utf-8")).hexdigest() == event_hash, name
    return {
        "name": name,
        "note": note,
        "signing_key_hex": signing_key.hex(),
        "sequence": sequence,
        "timestamp": timestamp,
        "action": action,
        "category": category,
        "key": key,
        "scope": scope,
        "value_sha256": value_sha256,
        "prev_hash": prev_hash,
        "author_id": author_id,
        "metadata": metadata,
        # Intermediate values, for debugging a mismatch; the expected outputs are the two below them.
        "metadata_canonical": meta_canonical,
        "payload": payload,
        "event_hash": event_hash,
        "head_mac": _head_mac(signing_key, sequence, event_hash),
    }


def _value_hash(content: str) -> str:
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def single_events() -> List[Dict[str, Any]]:
    return [
        _event(
            "first_event_no_author_no_metadata",
            signing_key=KEY_A, sequence=1, timestamp=1761700000.0, action="put", category="agent_state",
            key="step_4", scope="default", value_sha256=_value_hash("Compiled unit test binary"), prev_hash=ZERO,
            author_id=None, metadata=None,
            note="None metadata hashes as {}; None author hashes as the empty string.",
        ),
        _event(
            "author_and_fractional_timestamp",
            signing_key=KEY_A, sequence=2, timestamp=1761700000.123456, action="update", category="agent_state",
            key="step_4", scope="default", value_sha256=_value_hash("Linked unit test binary"),
            prev_hash="a" * 64, author_id="worker_alpha", metadata={},
        ),
        _event(
            "timestamp_rounds_to_six_places",
            signing_key=KEY_B, sequence=3, timestamp=1761700000.98765432, action="archive", category="c", key="k",
            scope="s", value_sha256="", prev_hash="b" * 64, author_id=None, metadata=None,
            note="The timestamp is formatted with .6f from the exact binary value; both sides must round alike.",
        ),
        _event(
            "timestamp_given_as_integer",
            signing_key=KEY_B, sequence=4, timestamp=1700000000, action="put", category="c", key="k", scope="s",
            value_sha256=_value_hash("x"), prev_hash="c" * 64, author_id="", metadata=None,
            note="An integer timestamp formats as 1700000000.000000; an empty author equals a missing one.",
        ),
        _event(
            "small_timestamp_near_rounding_boundary",
            signing_key=KEY_A, sequence=5, timestamp=1.0000005, action="put", category="c", key="k", scope="s",
            value_sha256=_value_hash("y"), prev_hash="d" * 64, author_id=None, metadata=None,
            note="1.0000005 is not exactly representable; .6f rounds the stored double, not the literal.",
        ),
        _event(
            "metadata_sorted_nested_mixed_scalars",
            signing_key=KEY_A, sequence=6, timestamp=1761700001.5, action="state_transition", category="c",
            key="k1", scope="default", value_sha256=_value_hash("value 1"), prev_hash="e" * 64, author_id="alice",
            metadata={
                "verdict": "disputed",
                "from": "verified",
                "reviewer": "alice",
                "nested": {"z": 1, "a": [1, 2, {"y": False, "x": None}], "m": True},
                "count": 3,
                "big": 9007199254740993,
                "negative": -42,
                "empty_list": [],
                "empty_obj": {},
            },
            note="Keys sort by code point at every level; ints, bools, null, lists and nested objects.",
        ),
        _event(
            "metadata_key_order_by_code_point",
            signing_key=KEY_B, sequence=7, timestamp=1761700002.0, action="put", category="c", key="k", scope="s",
            value_sha256=_value_hash("z"), prev_hash="f" * 64, author_id=None,
            metadata={"b": 1, "a": 2, "B": 3, "A": 4, "_": 5, "~": 6, "é": 7, "日": 8, "0": 9, "aa": 10, "a0": 11},
            note="ASCII upper before lower, digits before letters, non-ASCII last: byte order equals code point order.",
        ),
        _event(
            "unicode_bmp_in_every_field",
            signing_key=KEY_A, sequence=8, timestamp=1761700003.0, action="put", category="café",
            key="naïve/ключ", scope="日本語", value_sha256=_value_hash("héllo"), prev_hash="1" * 64,
            author_id="Zoë", metadata={"ünïcödé": "ẞtraße", "greek": "αβγ"},
            note="ensure_ascii=False: non-ASCII is written raw, not as \\uXXXX escapes.",
        ),
        _event(
            "unicode_non_bmp_emoji",
            signing_key=KEY_B, sequence=9, timestamp=1761700004.0, action="put", category="emoji",
            key="🔑 key 🗝️", scope="default", value_sha256=_value_hash("🚀"), prev_hash="2" * 64, author_id="🤖",
            metadata={"mood": "😀", "flag": "🇺🇸", "math": "𝔘𝔫𝔦𝔠𝔬𝔡𝔢"},
            note="Characters above U+FFFF are written as raw UTF-8, never as surrogate pairs.",
        ),
        _event(
            "json_escapes_quotes_backslash_control_del_slash",
            signing_key=KEY_A, sequence=10, timestamp=1761700005.0, action='act"ion', category="cat\\egory",
            key="line1\nline2\ttab\rcr\bbs\fff", scope="nul\x00soh\x01esc\x1b/slash\x7fdel",
            value_sha256=_value_hash("q"), prev_hash="3" * 64, author_id='"\\',
            metadata={"ctl\x1f": "\x00\x01\x1f", "q\"uote": "a\\b/c\x7f"},
            note="Only \", \\ and U+0000..U+001F are escaped (\\b \\f \\n \\r \\t or \\u00xx, lowercase hex); / and DEL stay raw.",
        ),
        _event(
            "all_strings_empty",
            signing_key=KEY_EMPTY, sequence=11, timestamp=0.0, action="", category="", key="", scope="",
            value_sha256="", prev_hash=ZERO, author_id="", metadata={},
            note="An empty HMAC key is padded to the block size with zeros.",
        ),
        _event(
            "u64_max_sequence_and_long_key",
            signing_key=KEY_LONG, sequence=18446744073709551615, timestamp=4102444800.999999, action="purge",
            category="c", key="k", scope="*", value_sha256=_value_hash("gone"), prev_hash="4" * 64,
            author_id="janitor", metadata={"reason": "tombstone sweep"},
            note="Sequence is written as a bare JSON integer, so u64::MAX must not go through a float.",
        ),
        _event(
            "colon_fields_are_unambiguous",
            signing_key=KEY_A, sequence=12, timestamp=1.0, action="put", category="a:b", key="c", scope="s",
            value_sha256="", prev_hash=ZERO, author_id=None, metadata=None,
            note="Pairs with colon_fields_are_unambiguous_shifted: same ':'-join, different hash.",
        ),
        _event(
            "colon_fields_are_unambiguous_shifted",
            signing_key=KEY_A, sequence=12, timestamp=1.0, action="put", category="a", key="b:c", scope="s",
            value_sha256="", prev_hash=ZERO, author_id=None, metadata=None,
        ),
    ]


def chain() -> Dict[str, Any]:
    """A linked five-event journal with its signed head, for the tail-cut and mid-chain-edit tests.

    Timestamps are whole seconds because the crate's ``AuditEvent.timestamp`` is a ``u64``; fractional
    timestamps are covered by the single-event vectors.
    """
    signing_key = KEY_B
    specs = [
        ("put", "c", "k0", "default", _value_hash("value 0"), None, None),
        ("put", "c", "k1", "default", _value_hash("value 1"), None, None),
        ("state_transition", "c", "k1", "default", _value_hash("value 1"), "alice",
         {"from": "verified", "to": "disputed", "reviewer": "alice"}),
        ("archive", "c", "k0", "default", "", None, None),
        ("tombstone", "c", "k1", "default", _value_hash("value 1"), "bob", {"reason": "retracted"}),
    ]
    events: List[Dict[str, Any]] = []
    prev = ZERO
    for i, (action, category, key, scope, value_sha256, author_id, metadata) in enumerate(specs, start=1):
        ts = 1761700100.0 + i  # whole seconds: the crate's AuditEvent keeps its timestamp as u64
        h = _event_hash(i, ts, action, category, key, scope, value_sha256, prev, author_id, metadata, fmt=JOURNAL_FORMAT)
        events.append({
            "sequence": i,
            "timestamp": ts,
            "action": action,
            "category": category,
            "key": key,
            "scope": scope,
            "value_sha256": value_sha256,
            "prev_hash": prev,
            "event_hash": h,
            "author_id": author_id,
            "metadata": metadata,
            "metadata_canonical": _canonical_metadata(metadata),
            "format": JOURNAL_FORMAT,
        })
        prev = h
    last = events[-1]
    return {
        "signing_key_hex": signing_key.hex(),
        "events": events,
        "head": {
            "sequence": last["sequence"],
            "event_hash": last["event_hash"],
            "mac": _head_mac(signing_key, last["sequence"], last["event_hash"]),
        },
    }


def build() -> Dict[str, Any]:
    return {
        "description": "kibisis audit journal format 3 vectors; generated by tests/fixtures/make_journal_vectors.py "
                       "from kibisis.vault._event_hash and _head_mac. Keys are test-only.",
        "journal_format": JOURNAL_FORMAT,
        "head_mac_domain": HEAD_MAC_DOMAIN,
        "events": single_events(),
        "chain": chain(),
    }


def main(out: str) -> None:
    assert JOURNAL_FORMAT == 3, JOURNAL_FORMAT
    data = build()
    with open(out, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
        f.write("\n")
    print(f"wrote {len(data['events'])} event vectors and a {len(data['chain']['events'])}-event chain to {out}")


if __name__ == "__main__":
    default = os.path.join(os.path.dirname(os.path.abspath(__file__)), "journal_format3_vectors.json")
    main(sys.argv[1] if len(sys.argv) > 1 else default)
