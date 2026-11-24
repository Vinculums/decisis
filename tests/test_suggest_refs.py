from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from decisis import cli, init, suggest

ROOT = Path(__file__).resolve().parents[1]
SHOP = ROOT / "fixtures" / "init" / "shop"

ADR = """# Retry payment calls once

## Context

Payments time out under load. The retry lives in `src/payments/retry.py` and is configured by
config/payments.toml today. See [the client](../../src/payments/client.py) for the caller.

## Decision

All settings move under the `settings` directory. Nothing changes in `src`, nor in `README`.
Each `handler.py` keeps its own copy.

```mermaid
subgraph "Retry (package: ./src/payments)"
```
"""

STATED = """---
code_ref: [src/payments/client.py]
---
# Keep the client small

The client is in `src/payments/retry.py` too.
"""


def write(root: Path, files: dict[str, str]) -> Path:
    for name, text in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return root


def repository(tmp_path: Path, **extra: str) -> Path:
    files = {
        "docs/adr/0001-retry-once.md": ADR,
        "docs/adr/0002-small-client.md": STATED,
        "src/payments/retry.py": "",
        "src/payments/client.py": "",
        "src/app.py": "",
        "config/payments.toml": "",
        "settings/base.toml": "",
        "README": "",
        **{f"part{i}/handler.py": "" for i in range(6)},
    }
    return write(tmp_path / "repo", {**files, **extra})


def decision(snap: dict, stem: str) -> dict:
    [node] = [n for n in snap["nodes"] if n["kind"] == "decision" and n["props"]["source_file"].endswith(stem)]
    return node["props"]


def test_suggested_refs_are_the_existing_paths_the_adr_text_names_with_the_sentence_each_came_from(tmp_path):
    snap = init.build(repository(tmp_path), "Shop", suggest_refs=True)
    props = decision(snap, "0001-retry-once.md")
    assert props["code_ref_source"] == "suggested"
    assert props["code_ref"] == ["Shop:config/payments.toml", "Shop:settings/", "Shop:src/payments/", "Shop:src/payments/client.py",
                                 "Shop:src/payments/retry.py"]
    evidence = {e["code_ref"]: e["sentence"] for e in props["code_ref_evidence"]}
    assert list(evidence) == props["code_ref"]
    assert evidence["Shop:src/payments/retry.py"] == ("The retry lives in `src/payments/retry.py` and is configured by "
                                                      "config/payments.toml today.")
    assert evidence["Shop:src/payments/client.py"] == "See [the client](../../src/payments/client.py) for the caller."
    assert evidence["Shop:settings/"] == "All settings move under the `settings` directory."
    assert evidence["Shop:src/payments/"] == 'subgraph "Retry (package: ./src/payments)"'
    text = " ".join(ADR.split())
    assert all(" ".join(s.split()) in text for s in evidence.values())


def test_a_code_ref_the_adr_states_is_never_changed_and_nothing_is_suggested_without_the_flag(tmp_path):
    repo = repository(tmp_path)
    props = decision(init.build(repo, "Shop", suggest_refs=True), "0002-small-client.md")
    assert props["code_ref"] == ["Shop:src/payments/client.py"]
    assert "code_ref_source" not in props and "code_ref_evidence" not in props
    plain = init.build(repo, "Shop")
    assert "code_ref" not in decision(plain, "0001-retry-once.md")
    assert init.build(SHOP, "Shop") == init.build(SHOP, "Shop", suggest_refs=False)


def test_a_token_with_more_than_five_paths_or_a_bare_common_name_is_skipped_and_listed(tmp_path):
    snap = init.build(repository(tmp_path), "Shop", suggest_refs=True)
    refs = decision(snap, "0001-retry-once.md")["code_ref"]
    assert not any(r.endswith("handler.py") or r in ("Shop:src/", "Shop:README") for r in refs)
    notes = {p["reason"] for p in snap["meta"]["problems"] if p["action"] == init.NOT_SUGGESTED}
    assert notes == {
        "`handler.py` matches 6 paths, more than 5; it is not suggested as a code ref",
        "`src` is a bare common name; it matches 1 path; it is not suggested as a code ref",
        "`README` is a bare common name; it matches 1 path; it is not suggested as a code ref",
    }
    kept = [p for p in snap["meta"]["problems"] if p["action"] == init.KEPT]
    assert kept == []


def test_five_matches_are_all_suggested(tmp_path):
    repo = repository(tmp_path)
    shutil.rmtree(repo / "part5")
    refs = decision(init.build(repo, None, suggest_refs=True), "0001-retry-once.md")["code_ref"]
    assert [r for r in refs if r.endswith("handler.py")] == [f"part{i}/handler.py" for i in range(5)]


def test_the_search_skips_git_node_modules_vendor_and_what_gitignore_lists(tmp_path):
    adr = "# Use the logger\n\nThe logger is `log/logger.js`, and `out/build.js` is built.\n"
    repo = write(tmp_path / "repo", {"docs/adr/0001-logger.md": adr, ".gitignore": "out/\n!keep.js\n",
                                     "node_modules/x/log/logger.js": "", "vendor/log/logger.js": "", ".git/log/logger.js": "",
                                     "out/build.js": ""})
    snap = init.build(repo, None, suggest_refs=True)
    assert "code_ref" not in decision(snap, "0001-logger.md")
    assert {(p["file"], p["action"]) for p in snap["meta"]["problems"]} >= {(".gitignore", init.NOT_READ)}
    write(repo, {"src/log/logger.js": ""})
    assert decision(init.build(repo, None, suggest_refs=True), "0001-logger.md")["code_ref"] == ["src/log/logger.js"]


@pytest.mark.skipif(shutil.which("git") is None, reason="needs git")
def test_in_a_git_work_tree_git_decides_what_is_ignored(tmp_path):
    adr = "# Use the logger\n\nThe logger is `log/logger.js`, and `out/build.js` is built.\n"
    repo = write(tmp_path / "repo", {"docs/adr/0001-logger.md": adr, ".gitignore": "out/\n", "out/build.js": "",
                                     "vendor/log/logger.js": "", "src/log/logger.js": ""})
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    assert decision(init.build(repo, None, suggest_refs=True), "0001-logger.md")["code_ref"] == ["src/log/logger.js"]


def test_other_adrs_images_and_urls_are_not_code_refs(tmp_path):
    adr = ("# Pictures\n\nSee [ADR 2](0002-other.md) and ![the flow](flow.png) and ![x](../../src/app.py).\n"
           "The [client](https://github.com/acme/shop/blob/main/src/payments/client.py) is upstream; https://example.com/src/app.py is not.\n")
    repo = repository(tmp_path, **{"docs/adr/0003-pictures.md": adr, "docs/adr/flow.png": "", "docs/adr/0002-other.md": "# Other\n"})
    props = decision(init.build(repo, None, suggest_refs=True), "0003-pictures.md")
    assert props["code_ref"] == ["src/payments/client.py"]


def test_init_prints_the_skipped_tokens_in_its_notes(tmp_path, capsys):
    out = tmp_path / "snapshot.json"
    capsys.readouterr()
    assert cli.main(["init", "--repo-dir", str(repository(tmp_path)), "--suggest-refs", "--out", str(out)]) == 0
    printed = json.loads(capsys.readouterr().out)
    assert any(p["action"] == "not suggested" and p["reason"].startswith("`handler.py` matches 6 paths") for p in printed["problems"])
    assert json.loads(out.read_text(encoding="utf-8"))["meta"]["problems"] == printed["problems"]


@pytest.mark.parametrize("word, bare, expected", [
    ("(./src/a.py),", False, ("src/a.py", True)),
    ("src/a.py:12", False, ("src/a.py", True)),
    ("/api", False, ("api", False)),
    ("pkg/**/*.go", False, ("pkg", False)),
    ("src/app/api/auth/{login,logout}", True, ("src/app/api/auth", True)),
    ("cf/", False, ("cf", True)),
    ("command", True, ("command", False)),
    ("command", False, None),
    ("../outside.py", False, None),
])
def test_word_paths(word, bare, expected):
    assert suggest.word_path(word, bare) == expected


def test_the_docs_describe_suggest_refs_and_show_the_committed_score():
    model = (ROOT / "docs" / "data-model.md").read_text(encoding="utf-8")
    for name in ("--suggest-refs", "code_ref_evidence", "code_ref_source", "not suggested", ".gitignore", "node_modules", "vendor"):
        assert f"`{name}`" in model, name
    committed = (ROOT / "bench" / "holdout" / "suggest-refs.md").read_text(encoding="utf-8").split("\n\n")[0].strip()
    assert committed in (ROOT / "docs" / "benchmark.md").read_text(encoding="utf-8")
    result = json.loads((ROOT / "bench" / "holdout" / "suggest-refs.json").read_text(encoding="utf-8"))
    assert f"precision {result['total']['precision']}" in model and f"recall {result['total']['recall']}" in model
    assert "in-sample" in model and "in-sample" in (ROOT / "docs" / "benchmark.md").read_text(encoding="utf-8")
    assert result["in_sample"] in (ROOT / "bench" / "holdout" / "suggest-refs.md").read_text(encoding="utf-8")


def test_a_path_with_a_colon_is_never_suggested(tmp_path):
    repo = write(tmp_path / "repo", {"docs/adr/0001-colon.md": "# Colon\n\nSee `a:b/c.py` and `src/c.py:12`.\n", "a:b/c.py": "", "src/c.py": ""})
    assert decision(init.build(repo, "Shop", suggest_refs=True), "0001-colon.md")["code_ref"] == ["Shop:src/c.py"]


@pytest.mark.parametrize("git", [False, True])
def test_a_file_name_that_is_not_utf8_is_left_out_and_the_snapshot_is_still_written(tmp_path, capsys, git):
    if git and shutil.which("git") is None:
        pytest.skip("needs git")
    repo = write(tmp_path / "repo", {"docs/adr/0001-x.md": "# Use x\n\nWe keep `x.go` and `src/y.go` as they are.\n", "src/y.go": ""})
    odd = repo / "d\udcff"
    try:
        odd.mkdir()
    except (OSError, UnicodeEncodeError):
        pytest.skip("the file system refuses a name that is not UTF-8")
    (odd / "x.go").write_text("", encoding="utf-8")
    if git:
        subprocess.run(["git", "init", "-q", str(repo)], check=True)
    out = tmp_path / "snapshot.json"
    capsys.readouterr()
    assert cli.main(["init", "--repo-dir", str(repo), "--suggest-refs", "--out", str(out)]) == 0
    snap = json.loads(out.read_text(encoding="utf-8"))
    assert decision(snap, "0001-x.md")["code_ref"] == ["src/y.go"]
    assert {"file": ".", "reason": "1 file name is not UTF-8; --suggest-refs does not search them", "action": init.NOT_READ} in snap["meta"]["problems"]
