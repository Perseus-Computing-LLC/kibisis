"""P13.4: the OKF export profile (schema ``kibisis.okf_export_profile/1``) and its digest.

Synthetic profiles only. The live profile is a private file in telarch and is pinned there.
"""
import hashlib
import json

import pytest

import kibisis
from kibisis.okf.profile import (
    DEFAULT_CATEGORIES,
    SCHEMA,
    ProfileError,
    load_profile,
    parse_profile,
)

BASE = {
    "schema": "kibisis.okf_export_profile/1",
    "audience": "owner",
    "allow": {"scopes": ["default"], "categories": ["architecture", "convention", "decision", "project_state"]},
    "named": [],
    "exclude": {"keys": [], "categories": []},
}


def _copy(obj):
    return json.loads(json.dumps(obj))


def _write(tmp_path, obj, name="profile.json", **dump):
    path = tmp_path / name
    path.write_text(json.dumps(obj, **dump), encoding="utf-8")
    return path


def test_the_default_allowlist_is_owner_decision_3():
    assert SCHEMA == "kibisis.okf_export_profile/1"
    assert DEFAULT_CATEGORIES == ("architecture", "convention", "decision", "project_state")


def test_the_digest_is_sha256_of_the_canonical_json_with_the_producer_set_at_load(tmp_path):
    prof = load_profile(_write(tmp_path, BASE))
    assert prof.producer == "kibisis/" + kibisis.__version__
    canonical = prof.canonical()
    assert canonical["producer"] == prof.producer
    assert set(canonical) == {"schema", "audience", "allow", "named", "exclude", "producer"}
    blob = json.dumps(canonical, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    assert prof.canonical_bytes() == blob
    assert prof.digest == hashlib.sha256(blob).hexdigest()


def _mutations():
    def audience(p):
        p["audience"] = "reviewer"

    def scopes(p):
        p["allow"]["scopes"] = ["default", "work"]

    def categories(p):
        p["allow"]["categories"] = ["convention", "decision", "project_state"]

    def named(p):
        p["named"] = ["user_profile"]

    def exclude_keys(p):
        p["exclude"]["keys"] = ["some_key"]

    def exclude_categories(p):
        p["exclude"]["categories"] = ["decision"]

    return [audience, scopes, categories, named, exclude_keys, exclude_categories]


def test_changing_any_one_profile_field_changes_the_digest(tmp_path, monkeypatch):
    base = load_profile(_write(tmp_path, BASE)).digest
    digests = {"base": base}
    for mutate in _mutations():
        obj = _copy(BASE)
        mutate(obj)
        digests[mutate.__name__] = load_profile(_write(tmp_path, obj, name=mutate.__name__ + ".json")).digest
    # producer is the seventh field: it is set from the library at load, so a new library version is a new digest.
    monkeypatch.setattr(kibisis, "__version__", "9.9.9")
    digests["producer"] = load_profile(_write(tmp_path, BASE, name="producer.json")).digest
    assert len(set(digests.values())) == len(digests) == 8, digests


def test_key_order_whitespace_and_list_order_in_the_file_do_not_change_the_digest(tmp_path):
    base = load_profile(_write(tmp_path, BASE)).digest
    reordered = {
        "exclude": {"categories": [], "keys": []},
        "named": [],
        "allow": {"categories": ["project_state", "decision", "convention", "architecture"], "scopes": ["default"]},
        "audience": "owner",
        "schema": "kibisis.okf_export_profile/1",
    }
    assert load_profile(_write(tmp_path, reordered, name="r.json", indent=7)).digest == base
    assert load_profile(_write(tmp_path, BASE, name="c.json", separators=(",", ":"))).digest == base
    spaced = tmp_path / "s.json"
    spaced.write_text("\n\n  " + json.dumps(BASE, indent="\t") + "\n\n", encoding="utf-8")
    assert load_profile(spaced).digest == base


def test_named_opts_a_category_outside_the_default_allowlist_in():
    obj = _copy(BASE)
    obj["named"] = ["user_profile"]
    prof = parse_profile(json.dumps(obj))
    assert prof.categories == ("architecture", "convention", "decision", "project_state", "user_profile")
    assert prof.allows("default", "user_profile")
    assert not prof.allows("default", "diagnosis")
    assert not prof.allows("work", "decision")


def test_exclude_wins_over_allow():
    obj = _copy(BASE)
    obj["exclude"] = {"keys": ["skip_me"], "categories": ["architecture"]}
    prof = parse_profile(json.dumps(obj))
    assert not prof.allows("default", "architecture")
    assert prof.allows("default", "decision")
    assert prof.excludes_key("skip_me") and not prof.excludes_key("keep_me")


def _bad_profiles():
    cases = {}

    def case(name, edit):
        obj = _copy(BASE)
        edit(obj)
        cases[name] = json.dumps(obj)

    case("unknown top-level key", lambda p: p.update({"extra": 1}))
    case("unknown key in allow", lambda p: p["allow"].update({"keys": ["k"]}))
    case("unknown key in exclude", lambda p: p["exclude"].update({"scopes": ["default"]}))
    case("producer in the file", lambda p: p.update({"producer": "kibisis/0.0.1"}))
    case("wildcard scope", lambda p: p["allow"].update({"scopes": ["*"]}))
    case("glob scope", lambda p: p["allow"].update({"scopes": ["def?ult"]}))
    case("wildcard category", lambda p: p["allow"].update({"categories": ["decision", "*"]}))
    case("glob category", lambda p: p["allow"].update({"categories": ["decis*"]}))
    case("wildcard named", lambda p: p.update({"named": ["*"]}))
    case("wildcard exclude key", lambda p: p["exclude"].update({"keys": ["*"]}))
    case("no allow list", lambda p: p.pop("allow"))
    case("allow without scopes", lambda p: p["allow"].pop("scopes"))
    case("allow without categories", lambda p: p["allow"].pop("categories"))
    case("empty scopes", lambda p: p["allow"].update({"scopes": []}))
    case("empty categories", lambda p: p["allow"].update({"categories": []}))
    case("allow is not an object", lambda p: p.update({"allow": ["default"]}))
    case("a non-default category in allow", lambda p: p["allow"].update({"categories": ["decision", "user_profile"]}))
    case("a default category in named", lambda p: p.update({"named": ["decision"]}))
    case("duplicate list entry", lambda p: p["allow"].update({"scopes": ["default", "default"]}))
    case("non-string list entry", lambda p: p["allow"].update({"scopes": ["default", 1]}))
    case("missing schema", lambda p: p.pop("schema"))
    case("wrong schema", lambda p: p.update({"schema": "kibisis.okf_export_profile/2"}))
    case("missing audience", lambda p: p.pop("audience"))
    case("empty audience", lambda p: p.update({"audience": ""}))
    cases["duplicate object key"] = json.dumps(BASE)[:-1] + ', "audience": "everyone"}'
    cases["not a JSON object"] = json.dumps([BASE])
    cases["not JSON"] = "{schema: kibisis}"
    return cases


@pytest.mark.parametrize("name", sorted(_bad_profiles()))
def test_a_bad_profile_is_refused(tmp_path, name):
    text = _bad_profiles()[name]
    with pytest.raises(ProfileError):
        parse_profile(text)
    path = tmp_path / "bad.json"
    path.write_text(text, encoding="utf-8")
    with pytest.raises(ProfileError):
        load_profile(path)


def test_a_missing_profile_file_is_refused(tmp_path):
    with pytest.raises(ProfileError):
        load_profile(tmp_path / "absent.json")
