"""Fixed-subset YAML frontmatter for OKF documents (P13). Stdlib only.

kibisis declares no YAML dependency, so OKF frontmatter is written and read here.

The emitter is canonical. A top-level scalar or mapping takes one line (mappings in flow form),
a non-empty list is a block sequence of flow items, and every string is double-quoted. Equal
documents therefore render to equal bytes.

The parser reads that output plus the hand-written forms the OKF v0.2 spec uses: block mappings
and sequences (including ``- key: value`` items), flow ``[...]`` and ``{...}`` on one line, plain,
single- and double-quoted scalars, and full-line and trailing comments. It refuses what it does not
read, rather than guessing: anchors, aliases, tags, block scalars, multi-line flow or quoted
scalars, tabs in indentation, duplicate keys and non-finite numbers. Plain scalars resolve as in
the YAML 1.2 core schema (null, booleans, decimal integers and floats). Timestamps stay strings.
"""
from __future__ import annotations

import math
import re
from typing import Any, Dict, List, Optional, Tuple

__all__ = ["FrontmatterError", "dump_frontmatter", "parse_frontmatter", "render_document", "split_document"]


class FrontmatterError(ValueError):
    """Frontmatter text, or a value to emit, is outside the fixed subset this module handles."""


# ------------------------------------------------------------------------------------------ emitter

_PLAIN_KEY = re.compile(r"[A-Za-z_][A-Za-z0-9_.-]*\Z")
#: Keys that a YAML 1.1 or 1.2 reader would resolve to a non-string; they are always quoted.
_RESOLVING_WORDS = frozenset({"true", "false", "null", "yes", "no", "on", "off", "y", "n", "~"})
_ESCAPES = {"\\": "\\\\", '"': '\\"', "\n": "\\n", "\r": "\\r", "\t": "\\t"}


def _needs_escape(cp: int) -> bool:
    return (
        cp < 0x20
        or cp == 0x7F
        or 0x80 <= cp <= 0x9F
        or cp in (0x2028, 0x2029, 0xFEFF, 0xFFFE, 0xFFFF)
        or 0xD800 <= cp <= 0xDFFF
    )


def _quote(text: str) -> str:
    out = ['"']
    for ch in text:
        esc = _ESCAPES.get(ch)
        if esc is not None:
            out.append(esc)
        elif _needs_escape(ord(ch)):
            out.append("\\u%04x" % ord(ch))
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _key(key: Any) -> str:
    if not isinstance(key, str):
        raise FrontmatterError(f"frontmatter keys are strings, got {type(key).__name__}")
    if _PLAIN_KEY.match(key) and key.lower() not in _RESOLVING_WORDS:
        return key
    return _quote(key)


def _scalar(value: Any) -> str:
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, int):
        return str(int(value))
    if isinstance(value, float):
        if not math.isfinite(value):
            raise FrontmatterError("non-finite numbers are outside the frontmatter subset")
        return repr(float(value))
    if isinstance(value, str):
        return _quote(str(value))
    raise FrontmatterError(f"cannot emit a {type(value).__name__} in frontmatter")


def _flow(value: Any) -> str:
    if isinstance(value, dict):
        if not value:
            return "{}"
        return "{" + ", ".join(_key(k) + ": " + _flow(v) for k, v in value.items()) + "}"
    if isinstance(value, list):
        return "[" + ", ".join(_flow(v) for v in value) + "]"
    return _scalar(value)


def dump_frontmatter(doc: Dict[str, Any]) -> str:
    """Canonical frontmatter text (without the ``---`` lines) for a mapping of supported values."""
    if not isinstance(doc, dict):
        raise FrontmatterError("frontmatter is a mapping")
    lines: List[str] = []
    for key, value in doc.items():
        k = _key(key)
        if isinstance(value, list) and value:
            lines.append(k + ":")
            lines.extend("  - " + _flow(item) for item in value)
        else:
            lines.append(k + ": " + _flow(value))
    return "".join(line + "\n" for line in lines)


def render_document(frontmatter: Dict[str, Any], body: str) -> str:
    """``---``, the canonical frontmatter, ``---``, then ``body`` exactly as given."""
    if not isinstance(body, str):
        raise FrontmatterError("a document body is a string")
    return "---\n" + dump_frontmatter(frontmatter) + "---\n" + body


def split_document(text: str) -> Tuple[Optional[str], str]:
    """Split a markdown document into (frontmatter text or None, body).

    The body is returned byte-for-byte. A leading BOM and CRLF line ends from other producers are
    accepted. An opening ``---`` line without a closing ``---`` (or ``...``) line is an error.
    """
    if text.startswith("\ufeff"):
        text = text[1:]
    first_nl = text.find("\n")
    first = text if first_nl < 0 else text[:first_nl]
    if first.rstrip("\r").rstrip(" \t") != "---":
        return None, text
    if first_nl < 0:
        raise FrontmatterError("the frontmatter opens with --- but has no closing --- line")
    pos = first_nl + 1
    while pos <= len(text):
        nl = text.find("\n", pos)
        line = text[pos:] if nl < 0 else text[pos:nl]
        if line.rstrip("\r").rstrip(" \t") in ("---", "..."):
            return text[first_nl + 1:pos], ("" if nl < 0 else text[nl + 1:])
        if nl < 0:
            break
        pos = nl + 1
    raise FrontmatterError("the frontmatter opens with --- but has no closing --- line")


# ------------------------------------------------------------------------------------------- parser

_INT = re.compile(r"[-+]?[0-9]+\Z")
_FLOAT = re.compile(r"[-+]?(\.[0-9]+|[0-9]+(\.[0-9]*)?)([eE][-+]?[0-9]+)?\Z")
_NON_FINITE = frozenset({".inf", "+.inf", "-.inf", ".nan"})
_BAD_START = frozenset("&*!|>%@`")
_KEY_BAD_START = frozenset("-?:,[]{}#&*!|>%@`")
_COMMENT = re.compile(r"[ \t]#")
_SIMPLE_ESCAPES = {
    "0": "\x00", "a": "\x07", "b": "\x08", "t": "\t", "\t": "\t", "n": "\n", "v": "\x0b", "f": "\x0c",
    "r": "\r", "e": "\x1b", " ": " ", '"': '"', "/": "/", "\\": "\\", "N": "\x85", "_": "\xa0",
    "L": "\u2028", "P": "\u2029",
}
_HEX_ESCAPES = {"x": 2, "u": 4, "U": 8}
_NO_VALUE = object()


def _fail(lineno: int, message: str) -> FrontmatterError:
    return FrontmatterError(f"frontmatter line {lineno}: {message}")


def _resolve_plain(text: str, lineno: int) -> Any:
    if text in ("~", "null", "Null", "NULL"):
        return None
    if text in ("true", "True", "TRUE"):
        return True
    if text in ("false", "False", "FALSE"):
        return False
    if text.lower() in _NON_FINITE:
        raise _fail(lineno, "non-finite numbers are outside the subset")
    try:
        if _INT.match(text):
            return int(text)
        if _FLOAT.match(text):
            return float(text)
    except ValueError as exc:
        raise _fail(lineno, f"number {text[:40]!r} does not convert: {exc}") from None
    return text


def _double(s: str, p: int, lineno: int) -> Tuple[str, int]:
    """Parse a double-quoted scalar starting at ``s[p] == '"'``; return (value, index after it)."""
    out: List[str] = []
    i = p + 1
    while i < len(s):
        ch = s[i]
        if ch == '"':
            return "".join(out), i + 1
        if ch == "\\":
            if i + 1 >= len(s):
                break
            esc = s[i + 1]
            if esc in _SIMPLE_ESCAPES:
                out.append(_SIMPLE_ESCAPES[esc])
                i += 2
                continue
            width = _HEX_ESCAPES.get(esc)
            if width is None:
                raise _fail(lineno, f"unknown escape \\{esc} in a double-quoted string")
            digits = s[i + 2:i + 2 + width]
            if len(digits) != width or not all(c in "0123456789abcdefABCDEF" for c in digits):
                raise _fail(lineno, f"escape \\{esc} needs {width} hex digits")
            cp = int(digits, 16)
            if cp > 0x10FFFF:
                raise _fail(lineno, f"escape \\{esc}{digits} is outside Unicode")
            out.append(chr(cp))
            i += 2 + width
            continue
        out.append(ch)
        i += 1
    raise _fail(lineno, "unterminated double-quoted string (multi-line quoted scalars are outside the subset)")


def _single(s: str, p: int, lineno: int) -> Tuple[str, int]:
    """Parse a single-quoted scalar starting at ``s[p] == "'"``; ``''`` is one quote."""
    out: List[str] = []
    i = p + 1
    while i < len(s):
        ch = s[i]
        if ch == "'":
            if i + 1 < len(s) and s[i + 1] == "'":
                out.append("'")
                i += 2
                continue
            return "".join(out), i + 1
        out.append(ch)
        i += 1
    raise _fail(lineno, "unterminated single-quoted string (multi-line quoted scalars are outside the subset)")


def _expect_end(s: str, p: int, lineno: int) -> None:
    rest = s[p:]
    if rest.strip(" \t") and not re.match(r"[ \t]+#", rest):
        raise _fail(lineno, f"unexpected text after the value: {rest.strip()[:40]!r}")


class _Flow:
    """One-line flow collections: ``[a, b]`` and ``{k: v}``, nested freely."""

    def __init__(self, s: str, lineno: int) -> None:
        self.s = s
        self.p = 0
        self.lineno = lineno

    def peek(self) -> str:
        return self.s[self.p] if self.p < len(self.s) else ""

    def ws(self) -> None:
        while self.p < len(self.s) and self.s[self.p] in " \t":
            self.p += 1

    def value(self) -> Any:
        self.ws()
        c = self.peek()
        if not c:
            raise _fail(self.lineno, "unterminated flow collection (multi-line flow is outside the subset)")
        if c == "[":
            return self.seq()
        if c == "{":
            return self.map()
        if c == '"':
            v, self.p = _double(self.s, self.p, self.lineno)
            return v
        if c == "'":
            v, self.p = _single(self.s, self.p, self.lineno)
            return v
        if c in _BAD_START:
            raise _fail(self.lineno, f"{c!r} (anchor, alias, tag or block scalar) is outside the subset")
        return self.plain()

    def plain(self) -> Any:
        start = self.p
        while self.p < len(self.s):
            c = self.s[self.p]
            if c in ",[]{}":
                break
            if c == ":" and (self.p + 1 >= len(self.s) or self.s[self.p + 1] in " \t,[]{}"):
                raise _fail(self.lineno, "a plain flow value holds ': '; quote it")
            if c == "#" and self.p > start and self.s[self.p - 1] in " \t":
                raise _fail(self.lineno, "a comment inside a flow collection")
            self.p += 1
        text = self.s[start:self.p].strip(" \t")
        if not text:
            raise _fail(self.lineno, "an empty entry in a flow collection")
        return _resolve_plain(text, self.lineno)

    def key(self) -> str:
        self.ws()
        c = self.peek()
        if c == '"':
            k, self.p = _double(self.s, self.p, self.lineno)
            return k
        if c == "'":
            k, self.p = _single(self.s, self.p, self.lineno)
            return k
        start = self.p
        while self.p < len(self.s):
            c = self.s[self.p]
            if c in ",[]{}":
                break
            if c == ":" and (self.p + 1 >= len(self.s) or self.s[self.p + 1] in " \t,[]{}"):
                break
            self.p += 1
        text = self.s[start:self.p].strip(" \t")
        if not text or text[0] in _KEY_BAD_START:
            raise _fail(self.lineno, "a flow mapping entry needs a plain or quoted key")
        return text

    def seq(self) -> List[Any]:
        self.p += 1
        out: List[Any] = []
        self.ws()
        if self.peek() == "]":
            self.p += 1
            return out
        while True:
            out.append(self.value())
            self.ws()
            c = self.peek()
            if c == ",":
                self.p += 1
                self.ws()
                if self.peek() == "]":
                    self.p += 1
                    return out
                continue
            if c == "]":
                self.p += 1
                return out
            raise _fail(self.lineno, "expected ',' or ']' in a flow sequence (multi-line flow is outside the subset)")

    def map(self) -> Dict[str, Any]:
        self.p += 1
        out: Dict[str, Any] = {}
        self.ws()
        if self.peek() == "}":
            self.p += 1
            return out
        while True:
            k = self.key()
            self.ws()
            if self.peek() != ":":
                raise _fail(self.lineno, f"expected ':' after flow key {k[:40]!r}")
            self.p += 1
            self.ws()
            v = None if self.peek() in (",", "}") else self.value()
            if k in out:
                raise _fail(self.lineno, f"duplicate key {k[:40]!r}")
            out[k] = v
            self.ws()
            c = self.peek()
            if c == ",":
                self.p += 1
                self.ws()
                if self.peek() == "}":
                    self.p += 1
                    return out
                continue
            if c == "}":
                self.p += 1
                return out
            raise _fail(self.lineno, "expected ',' or '}' in a flow mapping (multi-line flow is outside the subset)")


def _inline(rest: str, lineno: int) -> Any:
    """The value written on the same line as its key or dash, or ``_NO_VALUE`` when there is none."""
    s = rest.lstrip(" \t")
    if not s or s.startswith("#"):
        return _NO_VALUE
    c = s[0]
    if c in "[{":
        flow = _Flow(s, lineno)
        value = flow.value()
        _expect_end(s, flow.p, lineno)
        return value
    if c == '"':
        value, p = _double(s, 0, lineno)
        _expect_end(s, p, lineno)
        return value
    if c == "'":
        value, p = _single(s, 0, lineno)
        _expect_end(s, p, lineno)
        return value
    if c in _BAD_START:
        raise _fail(lineno, f"{c!r} (anchor, alias, tag, block scalar or directive) is outside the subset")
    if s == "-" or s.startswith("- ") or s == "?" or s.startswith("? "):
        raise _fail(lineno, "a block sequence or complex key on the same line as its key")
    m = _COMMENT.search(s)
    text = (s[:m.start()] if m else s).rstrip(" \t")
    if ": " in text or text.endswith(":"):
        raise _fail(lineno, "a plain value holds ': '; quote it")
    return _resolve_plain(text, lineno)


def _map_entry(text: str, lineno: int) -> Optional[Tuple[str, str]]:
    """``(key, rest)`` when ``text`` is a ``key: value`` entry, else None."""
    if not text or text[0] in "[{":
        return None
    if text[0] in "\"'":
        key, p = (_double if text[0] == '"' else _single)(text, 0, lineno)
        while p < len(text) and text[p] in " \t":
            p += 1
        if p < len(text) and text[p] == ":" and (p + 1 == len(text) or text[p + 1] in " \t"):
            return key, text[p + 1:]
        return None
    for i, ch in enumerate(text):
        if ch == "#" and i > 0 and text[i - 1] in " \t":
            return None
        if ch == ":" and (i + 1 == len(text) or text[i + 1] in " \t"):
            key = text[:i].rstrip(" \t")
            if not key or key[0] in _KEY_BAD_START:
                raise _fail(lineno, f"key {key[:40]!r} is outside the subset")
            return key, text[i + 1:]
    return None


def _is_seq_item(text: str) -> bool:
    return text == "-" or text.startswith("- ") or text.startswith("-\t")


class _Block:
    def __init__(self, lines: List[List[Any]]) -> None:
        self.lines = lines
        self.i = 0

    def node(self, indent: int) -> Any:
        return self.seq(indent) if _is_seq_item(self.lines[self.i][2]) else self.map(indent)

    def _nested(self, indent: int, allow_compact_seq: bool) -> Any:
        """The block value on the lines after a key or dash with no inline value (None if absent)."""
        if self.i < len(self.lines):
            _, nind, ntext = self.lines[self.i]
            if nind > indent:
                return self.node(nind)
            if allow_compact_seq and nind == indent and _is_seq_item(ntext):
                return self.seq(indent)
        return None

    def map(self, indent: int) -> Dict[str, Any]:
        out: Dict[str, Any] = {}
        while self.i < len(self.lines):
            lineno, ind, text = self.lines[self.i]
            if ind < indent:
                break
            if ind > indent:
                raise _fail(lineno, "unexpected indentation")
            if _is_seq_item(text):
                raise _fail(lineno, "a sequence item where a mapping key was expected")
            entry = _map_entry(text, lineno)
            if entry is None:
                raise _fail(lineno, "expected 'key: value'")
            key, rest = entry
            if key in out:
                raise _fail(lineno, f"duplicate key {key[:40]!r}")
            self.i += 1
            value = _inline(rest, lineno)
            if value is _NO_VALUE:
                value = self._nested(indent, allow_compact_seq=True)
            elif self.i < len(self.lines) and self.lines[self.i][1] > indent:
                raise _fail(self.lines[self.i][0], "unexpected indentation (multi-line plain scalars are outside the subset)")
            out[key] = value
        return out

    def seq(self, indent: int) -> List[Any]:
        out: List[Any] = []
        while self.i < len(self.lines):
            lineno, ind, text = self.lines[self.i]
            if ind < indent:
                break
            if ind > indent:
                raise _fail(lineno, "unexpected indentation")
            if not _is_seq_item(text):
                break
            after = text[1:]
            rest = after.lstrip(" \t")
            if not rest or rest.startswith("#"):
                self.i += 1
                out.append(self._nested(indent, allow_compact_seq=False))
                continue
            child = indent + 1 + (len(after) - len(rest))
            if _is_seq_item(rest) or _map_entry(rest, lineno) is not None:
                # "- key: value" or "- - x": the rest of the line opens a block at the column it starts in.
                self.lines[self.i] = [lineno, child, rest]
                out.append(self.node(child))
                continue
            self.i += 1
            out.append(_inline(rest, lineno))
            if self.i < len(self.lines) and self.lines[self.i][1] > indent:
                raise _fail(self.lines[self.i][0], "unexpected indentation")
        return out


def _lines(text: str) -> List[List[Any]]:
    out: List[List[Any]] = []
    for lineno, raw in enumerate(text.replace("\r\n", "\n").replace("\r", "\n").split("\n"), 1):
        body = raw.lstrip(" ")
        if not body.strip(" \t"):
            continue
        if body[0] == "\t":
            raise _fail(lineno, "a tab in the indentation is outside the subset")
        if body.startswith("#"):
            continue
        out.append([lineno, len(raw) - len(body), body.rstrip(" \t")])
    return out


def parse_frontmatter(text: str) -> Dict[str, Any]:
    """Parse frontmatter text (between the ``---`` lines) into a mapping; raise FrontmatterError."""
    if not isinstance(text, str):
        raise FrontmatterError("frontmatter text is a string")
    lines = _lines(text)
    if not lines:
        return {}
    block = _Block(lines)
    first = lines[0][1]
    if _is_seq_item(lines[0][2]):
        raise _fail(lines[0][0], "the frontmatter is a mapping, not a sequence")
    result = block.map(first)
    if block.i < len(lines):
        raise _fail(lines[block.i][0], "unexpected indentation")
    return result
