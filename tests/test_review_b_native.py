"""Review B: the PyO3 boundary (kibisis_native) and Python-vs-Rust agreement on the format-3 journal hash.

Python has no second implementation of format 3 (``_event_hash`` calls the crate), so 'agreement' is checked
against a pure-Python reference written from the layout documented in src/journal.rs:7-17.

``test_control_*`` assert the SECURE/consistent behaviour (failing = bug); ``test_attack_*`` demonstrate a
problem (passing = bug).
"""

import fcntl
import hashlib
import json
import threading
import unicodedata

import pytest

import kibisis_native as native
from kibisis._vault_audit import _event_hash, _head_mac


def _ref_hash(seq, ts, action, category, key, scope, value_sha256, prev_hash, author_id, metadata):
    canonical = json.dumps(metadata or {}, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    md = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    payload = "[" + str(seq) + "".join(
        "," + json.dumps(s, ensure_ascii=False)
        for s in (f"{ts:.6f}", action, category, key, scope, value_sha256, prev_hash, author_id or "", md)
    ) + "]"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


EDGE_STRINGS = [
    "", "plain", "ünïcödé ✓ 日本語", "emoji 🧪", "\x00nul inside", "ctrl \x01\x1f \x7f del", "quote\" back\\slash /slash",
    "line\nbreak\ttab\r\x08\x0c", "\u2028 line sep \u2029", unicodedata.normalize("NFC", "é"),
    unicodedata.normalize("NFD", "é"), "a:b:c", "trailing space ", " ",
]


@pytest.mark.parametrize("s", EDGE_STRINGS)
def test_control_event_hash_matches_reference_for_edge_strings(s):
    """Asserts consistency: crate hash == documented layout for empty/non-ASCII/NFC-NFD/control/null strings."""
    got = _event_hash(7, 1700000000.123456, s, s, s, s, "ab" * 32, "0" * 64, s, {"k": s, s: [1, 2]}, fmt=3)
    assert got == _ref_hash(7, 1700000000.123456, s, s, s, s, "ab" * 32, "0" * 64, s, {"k": s, s: [1, 2]})


def test_control_nfc_nfd_are_distinct_events():
    a = _event_hash(1, 0.0, unicodedata.normalize("NFC", "é"), "", "", "", "", "0" * 64, None, {}, fmt=3)
    b = _event_hash(1, 0.0, unicodedata.normalize("NFD", "é"), "", "", "", "", "0" * 64, None, {}, fmt=3)
    assert a != b


@pytest.mark.parametrize("ts", [0.0, -0.0, 1e-7, 0.0000005, 0.0000015, 2.5e-6, 1700000000.9999995, 1e15 + 0.3,
                                4102444800.0000001, 123456789.0000005])
def test_control_timestamp_6f_rounding_agrees(ts):
    """Asserts consistency of the '.6f' rendering (Rust {:.6} vs Python f'{:.6f}') at rounding edges."""
    assert _event_hash(1, ts, "a", "b", "c", "d", "", "0" * 64, None, {}, fmt=3) == \
        _ref_hash(1, ts, "a", "b", "c", "d", "", "0" * 64, None, {})


@pytest.mark.parametrize("meta", [
    {"b": 1, "a": {"z": 1, "y": [3, {"q": None}]}},            # nested key ordering
    {"n": 2 ** 200, "neg": -(2 ** 70)},                         # very large ints
    {"f": 0.1, "g": 1e300, "h": -0.0, "i": 1.0},                # floats (repr)
    {"nul": "\x00", "u": "\u00e9", "esc": "\"\\"},
    {"1": "digit key", "A": "upper before lower", "a": 1, "é": 2},
    {},
])
def test_control_metadata_digest_agrees(meta):
    """Asserts consistency: the crate digests the canonical metadata string Python hands it; the reference
    canonicalises the same way (sort_keys, compact, ensure_ascii=False)."""
    assert _event_hash(3, 1.5, "a", "b", "c", "d", "", "0" * 64, "x", meta, fmt=3) == \
        _ref_hash(3, 1.5, "a", "b", "c", "d", "", "0" * 64, "x", meta)
    canonical = json.dumps(meta, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    assert native.metadata_digest(canonical) == hashlib.sha256(canonical.encode()).hexdigest()


def test_control_lone_surrogate_is_rejected_not_mishashed():
    """Asserts: a str with a lone surrogate (possible from json.loads of '\\ud800') cannot cross into Rust;
    PyO3 raises UnicodeEncodeError instead of hashing a replacement character."""
    with pytest.raises(UnicodeEncodeError):
        _event_hash(1, 0.0, "\ud800", "", "", "", "", "0" * 64, None, {}, fmt=3)


def test_control_head_mac_matches_reference_and_rejects_key_change():
    import hmac
    key = b"\x07" * 32
    msg = b"kibisis audit head v1:" + b"[42," + json.dumps("ab" * 32).encode() + b"]"
    assert _head_mac(key, 42, "ab" * 32) == hmac.new(key, msg, hashlib.sha256).hexdigest()
    assert _head_mac(b"\x08" * 32, 42, "ab" * 32) != _head_mac(key, 42, "ab" * 32)
    # a 65-byte key exercises the > block-size path of the crate's own HMAC
    k2 = bytes(range(65))
    assert _head_mac(k2, 1, "0" * 64) == hmac.new(k2, b"kibisis audit head v1:[1,\"" + b"0" * 64 + b"\"]",
                                                  hashlib.sha256).hexdigest()


@pytest.mark.parametrize("bad", [-1, 2 ** 64])
def test_control_sequence_out_of_u64_raises_overflow(bad):
    with pytest.raises(OverflowError):
        native.event_hash_v3(bad, 0.0, "a", "b", "c", "d", "", "0" * 64, None, None)


def test_attack_native_ttl_overflow_is_a_value_error(tmp_path):
    """L6: a ttl that overflows Duration is refused with ValueError (Duration::try_from_secs_f64), never a
    PanicException; the rejection for non-finite and non-positive values stays."""
    coord = native.FileLeaseCoordinator(str(tmp_path / "leases"))
    for bad in (1e300, float("inf"), float("nan"), 0.0, -1.0, 1.9e19):
        with pytest.raises(ValueError):
            coord.acquire("r", "h", bad)
    lease = coord.acquire("r", "h", 5.0)
    with pytest.raises(ValueError):
        coord.renew(lease, 1e300)
    assert coord.renew(lease, 5.0) is True


def test_attack_native_coordinator_concurrent_calls_wait_instead_of_raising(tmp_path):
    """L6: the coordinator sits behind a mutex and every method takes &self, so a second thread calling
    acquire while the first blocks on the OS file lock waits its turn; nobody sees 'Already borrowed'.
    The first thread wins the lease, the second gets a LeaseConflict, in that order."""
    d = tmp_path / "leases"
    coord = native.FileLeaseCoordinator(str(d))
    lock_path = d / (hashlib.sha256(b"res").hexdigest() + ".lock")
    coord.get_lease("res")  # creates the lock file
    holder = open(lock_path, "r+b")
    fcntl.flock(holder, fcntl.LOCK_EX)  # hold the OS lock so thread A blocks inside acquire
    started = threading.Event()
    result = {}

    def worker():
        started.set()
        try:
            result["a"] = coord.acquire("res", "A", 5.0).fencing_token
        except BaseException as exc:
            result["a"] = repr(exc)

    t = threading.Thread(target=worker)
    t.start()
    started.wait()
    import time
    time.sleep(0.3)  # let thread A enter py.detach and block on flock

    def second():
        try:
            coord.acquire("res", "B", 5.0)
            result["b"] = "ok"
        except BaseException as exc:
            result["b"] = f"{type(exc).__name__}: {exc}"

    t2 = threading.Thread(target=second)
    t2.start()
    t2.join(0.5)
    assert t2.is_alive(), "the second call must wait, not return while the first still blocks"
    assert "b" not in result
    fcntl.flock(holder, fcntl.LOCK_UN)
    holder.close()
    t.join(5)
    t2.join(5)
    assert result["a"] == 1
    assert result["b"].startswith("LeaseConflict")
    assert "Already" not in result["b"]
