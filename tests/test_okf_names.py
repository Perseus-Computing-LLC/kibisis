"""P14.3: the rule that says when a turn's query names a vault row (roadmap 17.2, Pass 2).

A row is named when its key appears in the query (case-folded, not inside a longer word) or when its title's
token sequence appears among the query's tokens. The title of a vault row is its key: okf-export writes the key
as the concept's title. Rows named by one query are requested in the order the query names them.
"""
from __future__ import annotations

import pytest

from kibisis.okf import export


def _api(name: str):
    return getattr(export, name)


def test_the_naming_helpers_are_exported():
    for name in ("name_tokens", "names_at", "named_rows"):
        assert name in export.__all__
        assert callable(_api(name))


def test_name_tokens_are_case_folded_letter_and_digit_runs():
    assert _api("name_tokens")("User_Prefers-Verified work, P14.3") == ["user", "prefers", "verified", "work", "p14", "3"]
    assert _api("name_tokens")("") == []
    assert _api("name_tokens")("___ --- ...") == []


def test_a_key_in_the_query_names_the_row():
    names_at = _api("names_at")
    assert names_at("what does user_prefers_verified_work say?", "user_prefers_verified_work") == 10
    assert names_at("WHAT DOES USER_PREFERS_VERIFIED_WORK SAY?", "user_prefers_verified_work") == 10
    assert names_at("see decision/p5-roadmap.", "decision/p5-roadmap") == 4


def test_a_key_inside_a_longer_word_does_not_name_the_row():
    names_at = _api("names_at")
    assert names_at("phase p140 started", "p14") is None
    assert names_at("phase xp14 started", "p14") is None
    assert names_at("phase p14 started", "p14") == 6
    assert names_at("phase (p14) started", "p14") == 7


def test_query_and_title_share_one_tokenizer():
    # "_" separates tokens in the query as in the title, so a longer underscored name names its first token's row.
    names_at = _api("names_at")
    assert names_at("phase p14_extra started", "p14") == 6
    assert names_at("phase p14_extra started", "p14_extra") == 6
    assert names_at("phase p14_extra started", "extra_p14") is None


def test_the_title_token_sequence_names_the_row():
    names_at = _api("names_at")
    key = "user_prefers_verified_work"
    assert names_at("Does the user prefers verified work?", key) == 9
    assert names_at("Does the User-Prefers, verified WORK?", key) == 9
    # The tokens must be contiguous and in order.
    assert names_at("the user prefers fast verified work", key) is None
    assert names_at("verified work the user prefers", key) is None


def test_an_explicit_title_is_matched_by_its_tokens():
    names_at = _api("names_at")
    key = "p5_roadmap_adopted_20261030"
    assert names_at("show the roadmap adopted note", key) is None
    assert names_at("show the roadmap adopted note", key, "Roadmap adopted") == 9
    assert names_at("show p5_roadmap_adopted_20261030", key, "Roadmap adopted") == 5


def test_the_earliest_naming_wins():
    names_at = _api("names_at")
    # Title tokens at offset 4, the key itself later.
    assert names_at("the user prefers verified work: user_prefers_verified_work", "user_prefers_verified_work") == 4


def test_case_folding_is_unicode_aware():
    assert _api("names_at")("die STRASSE ist lang", "straße") == 4


def test_a_row_without_tokens_is_named_by_its_key_only():
    names_at = _api("names_at")
    assert names_at("a --- b", "---") == 2
    assert names_at("a - b", "---") is None
    assert names_at("anything at all", "") is None


def test_named_rows_are_in_request_order():
    named_rows = _api("named_rows")
    rows = ["beta", "alpha", "gamma"]
    assert named_rows("alpha then beta", rows) == [1, 0]
    assert named_rows("nothing here", rows) == []
    assert named_rows("gamma, beta and alpha", rows) == [2, 0, 1]


def test_named_rows_ties_keep_row_order_and_each_row_is_requested_once():
    named_rows = _api("named_rows")
    assert named_rows("a b", ["a_b", "a"]) == [0, 1]
    assert named_rows("a b", ["a", "a_b"]) == [0, 1]
    assert named_rows("alpha alpha alpha", ["alpha"]) == [0]
    assert named_rows("alpha", ["alpha", "alpha"]) == [0, 1]


def test_named_rows_take_key_title_pairs():
    named_rows = _api("named_rows")
    rows = [("p5_roadmap_adopted_20261030", "Roadmap adopted"), ("user_prefers_verified_work", None), "health"]
    assert named_rows("health of the roadmap adopted plan; user prefers verified work", rows) == [2, 0, 1]


@pytest.mark.parametrize("query", ["", "   ", "?!"])
def test_an_empty_query_names_nothing(query):
    assert _api("named_rows")(query, ["alpha", "beta"]) == []
