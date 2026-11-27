from __future__ import annotations

import json
import re
import time
from pathlib import Path

import pytest

from decisis import codeowners, external, init, madr, semver


def _reference_regex(pattern: str) -> re.Pattern:
    segments, directory, anchored = codeowners.split_pattern(pattern)
    parts = []
    for i, s in enumerate(segments):
        last = i == len(segments) - 1
        if s == "**":
            parts.append(".*" if last else "(?:.*/)?")
        else:
            parts.append(codeowners.glob_segment(s) + ("" if last else "/"))
    tail = "/.*" if directory else ("(?:/.*)?" if codeowners.plain_name(segments[-1]) else "")
    return re.compile(("" if anchored else "(?:.*/)?") + "".join(parts) + tail)


@pytest.mark.parametrize("pattern", [
    "*",
    "**",
    "**/**",
    "a",
    "/a",
    "a/",
    "/a/",
    "a/**",
    "a/**/",
    "a/**/**",
    "a/**/**/",
    "**/a",
    "**/a/",
    "a/**/b",
    "a/**/b/",
    "*.py",
    "/a/*.py",
    "a/?/b",
    "a/f*o?r/b*",
    "*/",
    "/*/",
    "src/pay/**",
    "src/pay",
])
def test_linear_glob_pattern_matches_reference_regex_across_paths(pattern):
    got = codeowners.compile_pattern(pattern)
    ref = _reference_regex(pattern)
    samples = [
        "",
        "a",
        "a/",
        "a//",
        "a/b",
        "a/b/",
        "a/b/c",
        "a/x/b",
        "a/x/y/b/z",
        "x/a",
        "x/a/",
        "x/a/b",
        "foo.py",
        "a/foo.py",
        "a/b/foo.py",
        "a/foo.py/bar",
        "a/x/b",
        "a/xy/b",
        "a/for/b",
        "a/foor/bar",
        "a/foor/bar/baz",
        "src/pay",
        "src/pay/",
        "src/pay/charge.py",
        "x/src/pay/charge.py",
    ]
    for path in samples:
        assert bool(got.fullmatch(path)) == bool(ref.fullmatch(path)), (pattern, path)


@pytest.mark.parametrize("pattern,path", [
    ("a/" + "/".join(["**"] * 20) + "/b", "a/" + "/".join(["x"] * 40) + "/c"),
    ("*a" * 25 + "*b", "a" * 80 + "c"),
    ("a/" + "/".join(["**", "x"] * 12) + "/**/b", "a/" + "/".join(["x"] * 40) + "/c"),
])
def test_codeowners_compile_pattern_and_segment_pattern_do_not_redos(pattern, path):
    matcher = codeowners.compile_pattern(pattern)
    t0 = time.monotonic()
    assert matcher.fullmatch(path) is False
    assert time.monotonic() - t0 < 0.1
    seg = codeowners.segment_pattern("*a" * 25 + "*b")
    t1 = time.monotonic()
    assert seg.fullmatch("a" * 80 + "c") is False
    assert time.monotonic() - t1 < 0.1


@pytest.mark.parametrize("payload", [
    {"fetched_at": "2026-11-27T00:00:00Z", "queries": {"pkg:npm/a@1.0.0": "GHSA-1"}, "vulns": {}},
    {"fetched_at": "2026-11-27T00:00:00Z", "queries": {"pkg:npm/a@1.0.0": [123]}, "vulns": {}},
    {"fetched_at": "2026-11-27T00:00:00Z", "queries": {"pkg:npm/a@1.0.0": ["GHSA-1"]}, "vulns": {"GHSA-1": None}},
    {"fetched_at": "2026-11-27T00:00:00Z", "queries": {"pkg:npm/a@1.0.0": ["GHSA-1"]}, "vulns": {"GHSA-1": {"id": "GHSA-1", "database_specific": "bad"}}},
    {"fetched_at": "2026-11-27T00:00:00Z", "queries": {"pkg:npm/a@1.0.0": ["GHSA-1"]}, "vulns": {"GHSA-1": {"id": "GHSA-1", "aliases": [123]}}},
    {"fetched_at": "2026-11-27T00:00:00Z", "queries": {"pkg:npm/a@1.0.0": ["GHSA-1"]}, "vulns": {"GHSA-1": {"id": "GHSA-1", "severity": [None]}}},
    {"fetched_at": "2026-11-27T00:00:00Z", "queries": {"pkg:npm/a@1.0.0": ["GHSA-1"]}, "vulns": {"GHSA-1": {"id": "GHSA-1", "affected": [None]}}},
    {"fetched_at": "2026-11-27T00:00:00Z", "queries": {"pkg:npm/a@1.0.0": ["GHSA-1"]}, "vulns": {"GHSA-1": {"id": "GHSA-1", "affected": [{"package": "bad"}]}}},
    {"fetched_at": "2026-11-27T00:00:00Z", "queries": {"pkg:npm/a@1.0.0": ["GHSA-1"]}, "vulns": {"GHSA-1": {"id": "GHSA-1", "affected": [{"ranges": [None]}]}}},
    {"fetched_at": "2026-11-27T00:00:00Z", "queries": {"pkg:npm/a@1.0.0": ["GHSA-1"]}, "vulns": {"GHSA-1": {"id": "GHSA-1", "affected": [{"ranges": [{"events": [None]}]}]}}},
    {"fetched_at": "2026-11-27T00:00:00Z", "queries": {"pkg:npm/a@1.0.0": ["GHSA-1"]}, "vulns": {"GHSA-1": {"id": "GHSA-1", "affected": [{"ranges": [{"events": "bad"}]}]}}},
])
def test_read_osv_cache_rejects_malformed_vuln_shapes(payload):
    with pytest.raises(ValueError):
        external.read_osv_cache(json.dumps(payload))


def test_semver_handles_non_string_and_malformed_range_events_without_crashing():
    assert semver.in_range("1.0.0", [{"introduced": 123}]) is None
    assert semver.in_range("1.0.0", [None]) is None
    assert semver.in_range("1.0.0", "bad") is None
    assert semver.in_range(123, [{"introduced": "0"}]) is None
    assert semver.affects("1.0.0", "npm", "foo", [None]) is None
    assert semver.affects("1.0.0", "npm", "foo", [{"package": {"ecosystem": "npm", "name": "foo"}, "ranges": [None]}]) is None
    assert semver.affects("1.0.0", "npm", "foo", [{"package": {"ecosystem": "npm", "name": "foo"}, "ranges": [{"type": "SEMVER", "events": [{"introduced": 123}]}]}]) is None


@pytest.mark.parametrize("bad_ref", [
    "src/a.py\nrule: {}",
    "src/a.py\r\nfoo",
    "src/a\x00.py",
    "   ",
    "src/\x1b[31mred.py",
])
def test_madr_write_rejects_control_characters_in_code_ref(tmp_path, bad_ref):
    (tmp_path / "docs" / "adr").mkdir(parents=True)
    with pytest.raises(ValueError, match="--code-ref"):
        madr.write(tmp_path, "Valid title", code_refs=[bad_ref], date="2026-11-27")


def test_suggest_refs_excludes_symlinks_pointing_outside_repository(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    target = outside / "secret.py"
    target.write_text("SECRET = 1\n", encoding="utf-8")

    repo = tmp_path / "repo"
    (repo / "src").mkdir(parents=True)
    (repo / "src" / "real.py").write_text("x = 1\n", encoding="utf-8")
    (repo / "src" / "escape.py").symlink_to(target)
    (repo / "src" / "escape_dir").symlink_to(outside)
    (repo / "docs" / "adr").mkdir(parents=True)
    (repo / "docs" / "adr" / "0001-paths.md").write_text(
        "# Paths\n\nUses `src/escape.py`, `src/escape_dir/secret.py` and `src/real.py`.\n",
        encoding="utf-8",
    )

    snap = init.build(repo, "Shop", suggest_refs=True)
    refs = snap["nodes"][0]["props"].get("code_ref", [])
    assert refs == ["Shop:src/real.py"]
