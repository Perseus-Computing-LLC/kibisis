"""K-J: default scope is per project, from the git root; ``global`` only when asked for explicitly.

Decided 2026-10-28: an MCP server started inside a git checkout serves that project's scope, derived
from the repository root so every subdirectory and every clone at the same path agree. Outside a
checkout the scope is ``default``. ``global`` is never derived; it needs ``KIBISIS_SCOPE=global``.
Wildcards and empty scopes stay refused.
"""

import os
import subprocess

import pytest

from kibisis.config import ConfigError, GLOBAL_SCOPE, project_scope_for, resolve_scope


@pytest.fixture
def repo(tmp_path):
    root = tmp_path / "proj"
    (root / "src" / "deep").mkdir(parents=True)
    subprocess.run(["git", "init", "-q", str(root)], check=True)
    return root


def test_outside_a_checkout_the_scope_is_default(tmp_path):
    plain = tmp_path / "plain"
    plain.mkdir()
    assert resolve_scope({}, cwd=str(plain)) == "default"


def test_inside_a_checkout_the_scope_is_the_project(repo):
    s = resolve_scope({}, cwd=str(repo))
    assert s.startswith("project:proj-")
    assert s == project_scope_for(str(repo))


def test_every_subdirectory_of_the_checkout_agrees(repo):
    assert resolve_scope({}, cwd=str(repo / "src" / "deep")) == resolve_scope({}, cwd=str(repo))


def test_two_checkouts_at_different_paths_get_different_scopes(tmp_path):
    a, b = tmp_path / "proj", tmp_path / "other" / "proj"
    a.mkdir(); b.mkdir(parents=True)
    subprocess.run(["git", "init", "-q", str(a)], check=True)
    subprocess.run(["git", "init", "-q", str(b)], check=True)
    assert resolve_scope({}, cwd=str(a)) != resolve_scope({}, cwd=str(b))


def test_explicit_env_scope_wins_over_the_checkout(repo):
    assert resolve_scope({"KIBISIS_SCOPE": "team-a"}, cwd=str(repo)) == "team-a"


def test_global_is_never_derived_and_requires_the_explicit_value(repo, tmp_path):
    assert resolve_scope({}, cwd=str(repo)) != GLOBAL_SCOPE
    assert resolve_scope({}, cwd=str(tmp_path)) != GLOBAL_SCOPE
    assert resolve_scope({"KIBISIS_SCOPE": "global"}, cwd=str(repo)) == GLOBAL_SCOPE


def test_wildcard_and_empty_are_still_refused(repo):
    for bad in ("*", "", " ", "a*"):
        with pytest.raises(ConfigError):
            resolve_scope({"KIBISIS_SCOPE": bad}, cwd=str(repo))


def test_project_scope_is_a_valid_scope_even_for_odd_repo_names(tmp_path):
    root = tmp_path / "My Repo (v2)!"
    root.mkdir()
    subprocess.run(["git", "init", "-q", str(root)], check=True)
    s = resolve_scope({}, cwd=str(root))
    assert " " not in s and "(" not in s and "!" not in s
    assert resolve_scope({"KIBISIS_SCOPE": s}) == s  # round-trips through validation


def test_missing_cwd_falls_back_to_default(tmp_path):
    assert resolve_scope({}, cwd=str(tmp_path / "nope")) == "default"
