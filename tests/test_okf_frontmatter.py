"""P13.1: the stdlib frontmatter emitter and fixed-subset parser (kibisis declares no YAML dependency)."""
import pytest

from kibisis.okf.frontmatter import (
    FrontmatterError,
    dump_frontmatter,
    parse_frontmatter,
    render_document,
    split_document,
)

TRICKY = [
    "plain",
    "",
    "with: colon and # hash",
    'double "quotes" and \\ backslash',
    "line one\nline two\r\nline three",
    "tab\there",
    "---",
    "- leading dash",
    "{not: a map}",
    "[not, a, list]",
    "true",
    "null",
    "0.2",
    "123",
    "  surrounding spaces  ",
    "unicode: caf\u00e9 \u4e2d\u6587 \U0001F600",
    "controls: \x00\x01\x1b\x7f \x85 \u2028 \u2029 \ufeff \ufffe",
    "'single quoted'",
    "&anchor *alias !tag | >",
]


@pytest.mark.parametrize("value", TRICKY)
def test_any_string_round_trips(value):
    doc = {"type": "Decision", "value": value, "nested": {"inner": value}, "items": [value, value]}
    assert parse_frontmatter(dump_frontmatter(doc)) == doc


def test_the_full_value_subset_round_trips_in_order():
    doc = {
        "type": "Decision",
        "count": 3,
        "negative": -7,
        "ratio": 0.25,
        "tiny": 1e-05,
        "yes": True,
        "no": False,
        "nothing": None,
        "empty_list": [],
        "empty_map": {},
        "generated": {"by": "kibisis/0.1.0", "at": "2026-10-31T00:00:00Z"},
        "verified": [{"by": "human:owner", "at": "2026-10-31T00:00:00.5Z"}],
        "deep": {"a": [1, [2, {"b": None}]], "c": {"d": {"e": "f"}}},
        "true": "a key that looks like a boolean",
        "with space": "a key that needs quotes",
        "123": "a key that looks like a number",
    }
    text = dump_frontmatter(doc)
    parsed = parse_frontmatter(text)
    assert parsed == doc
    assert list(parsed) == list(doc)
    assert dump_frontmatter(parsed) == text


def test_the_emitter_is_canonical_one_line_per_top_level_scalar_or_map():
    text = dump_frontmatter({
        "type": "Decision",
        "generated": {"by": "kibisis/0.1.0", "at": "2026-10-31T00:00:00Z"},
        "sources": [{"id": "source_ref", "resource": "session:s1/turn:3"}],
    })
    assert text == (
        'type: "Decision"\n'
        'generated: {by: "kibisis/0.1.0", at: "2026-10-31T00:00:00Z"}\n'
        "sources:\n"
        '  - {id: "source_ref", resource: "session:s1/turn:3"}\n'
    )


def test_the_emitter_refuses_values_outside_the_subset():
    for bad in (float("inf"), float("nan"), object(), b"bytes", (1, 2)):
        with pytest.raises(FrontmatterError):
            dump_frontmatter({"type": "X", "bad": bad})
    with pytest.raises(FrontmatterError):
        dump_frontmatter({1: "non-string key"})


SPEC_STYLE = """\
type: BigQuery Table
title: Customer Orders
description: One row per completed customer order across all channels.
resource: https://console.cloud.google.com/bigquery?p=acme&d=sales&t=orders
tags: [sales, orders, revenue]
generated: { by: reference_agent/gemini-2.5-pro, at: 2026-05-28T14:30:00Z }
# a full-line comment
verified: { by: human:ahormati, at: 2026-06-25T09:00:00Z }
sources:
  - id: ga4-schema
    resource: https://developers.google.com/analytics/bigquery/export-schema
    title: GA4 BigQuery Export schema   # a trailing comment
    usage_count: 5000
  - { id: rev-policy, resource: 'https://wiki.acme/finance/it''s' }
usage_window: { from: 2026-06-01T00:00:00Z, to: 2026-06-30T00:00:00Z }
parameters:
  - { name: year, type: integer, required: true }
executor:
  resource: references/skills/run-on-bq.md
  receipt: [job_id, executed_sql, result]
status: ~
okf_version: "0.2"
"""


def test_spec_style_hand_written_frontmatter_parses():
    doc = parse_frontmatter(SPEC_STYLE)
    assert doc["type"] == "BigQuery Table"
    assert doc["resource"] == "https://console.cloud.google.com/bigquery?p=acme&d=sales&t=orders"
    assert doc["tags"] == ["sales", "orders", "revenue"]
    assert doc["generated"] == {"by": "reference_agent/gemini-2.5-pro", "at": "2026-05-28T14:30:00Z"}
    assert doc["verified"] == {"by": "human:ahormati", "at": "2026-06-25T09:00:00Z"}
    assert doc["sources"] == [
        {"id": "ga4-schema", "resource": "https://developers.google.com/analytics/bigquery/export-schema",
         "title": "GA4 BigQuery Export schema", "usage_count": 5000},
        {"id": "rev-policy", "resource": "https://wiki.acme/finance/it's"},
    ]
    assert doc["usage_window"] == {"from": "2026-06-01T00:00:00Z", "to": "2026-06-30T00:00:00Z"}
    assert doc["parameters"] == [{"name": "year", "type": "integer", "required": True}]
    assert doc["executor"] == {"resource": "references/skills/run-on-bq.md", "receipt": ["job_id", "executed_sql", "result"]}
    assert doc["status"] is None
    assert doc["okf_version"] == "0.2"


@pytest.mark.parametrize(
    "text",
    [
        "type: &a Decision\n",
        "type: *a\n",
        "type: !!str Decision\n",
        "type: |\n  block\n",
        "type: >\n  folded\n",
        "type: Decision\ntype: Again\n",
        "\ttype: Decision\n",
        'type: "unterminated\n',
        "type: {by: x\n",
        "type: [a, b\n",
        "just a line without a colon\n",
        "type: Decision\n  stray: indent\n",
        "list:\n  - a\n   - misaligned\n",
        "map: {a: 1, a: 2}\n",
        "type: 'bad '' quote\n",
        "type: \"bad escape \\q\"\n",
    ],
)
def test_input_outside_the_subset_is_refused(text):
    with pytest.raises(FrontmatterError):
        parse_frontmatter(text)


def test_split_and_render_keep_the_body_exact():
    for body in ("", "x", "x\n", "x\n\n", "# H\n\n---\nnot frontmatter\n---\n", "no newline at end"):
        doc = render_document({"type": "Decision"}, body)
        assert doc.startswith('---\ntype: "Decision"\n---\n')
        fm, got = split_document(doc)
        assert parse_frontmatter(fm) == {"type": "Decision"}
        assert got == body


def test_split_document_finds_no_frontmatter_without_an_opening_line():
    assert split_document("# Title\n\nbody\n") == (None, "# Title\n\nbody\n")
    assert split_document("") == (None, "")
    with pytest.raises(FrontmatterError):
        split_document("---\ntype: Decision\nno closing line\n")


def test_split_document_accepts_crlf_and_a_bom_from_other_producers():
    fm, body = split_document("\ufeff---\r\ntype: Decision\r\n---\r\nbody\r\n")
    assert parse_frontmatter(fm) == {"type": "Decision"}
    assert body == "body\r\n"
