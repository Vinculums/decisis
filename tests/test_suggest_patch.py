from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from decisis import cli, init, patch

ROOT = Path(__file__).resolve().parents[1]
SHOP = ROOT / "fixtures" / "init" / "shop"
needs_git = pytest.mark.skipif(shutil.which("git") is None, reason="needs git")

WITH_FRONT = """---
status: accepted
date: 2026-01-01
---

# Use the client

The client is `src/payments/client.py`, and `src/payments/retry.py` is its helper.
"""

WITHOUT_FRONT = """# Retry payment calls once

## Context

Payments time out under load. The retry lives in `src/payments/retry.py` and is configured by
config/payments.toml today. See [the client](../../src/payments/client.py) for the caller.

## Decision

All settings move under the `settings` directory. Nothing changes in `src`, nor in `README`.
Each `handler.py` keeps its own copy.
"""

STATED = """---
code_ref: [src/app.py]
---
# Keep the app small

The app also uses `src/payments/retry.py`.
"""


def write(root: Path, files: dict[str, str]) -> Path:
    for name, text in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(text.encode("utf-8"))
    return root


def repository(tmp_path: Path, **extra: str) -> Path:
    files = {
        "docs/adr/0001-retry-once.md": WITHOUT_FRONT,
        "docs/adr/0002-small-client.md": WITH_FRONT,
        "docs/adr/0003-small-app.md": STATED,
        "src/payments/retry.py": "",
        "src/payments/client.py": "",
        "src/app.py": "",
        "config/payments.toml": "",
        "settings/base.toml": "",
        "README": "",
        **{f"part{i}/handler.py": "" for i in range(6)},
    }
    return write(tmp_path / "repo", {**files, **extra})


def tree_hash(root: Path) -> dict[str, str]:
    return {p.relative_to(root).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(root.rglob("*")) if p.is_file()}


def run_init(repo: Path, out: Path, *extra: str) -> int:
    return cli.main(["init", "--repo-dir", str(repo), "--repo", "Shop", "--suggest-refs", "--out", str(out), *extra])


def git_apply(repo: Path, diff: Path, *flags: str) -> subprocess.CompletedProcess:
    return subprocess.run(["git", "apply", *flags, str(diff)], cwd=repo, capture_output=True, text=True)


def decisions(snap: dict) -> dict[str, dict]:
    return {n["props"]["source_file"]: n["props"] for n in snap["nodes"] if n["kind"] == "decision"}


def hunks(text: str) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for part in text.split("\ndiff --git ")[1:]:
        name = part.split("\n", 1)[0].split(" b/")[1]
        out[name] = [line for line in part.split("\n") if line.startswith("@@")]
    return out


def made(tmp_path: Path, repo: Path, *extra: str) -> tuple[str, Path]:
    diff = tmp_path / "suggest.diff"
    assert run_init(repo, tmp_path / "snapshot.json", "--patch", str(diff), *extra) == 0
    return diff.read_text(encoding="utf-8"), diff


@needs_git
def test_an_adr_with_front_matter_gets_the_refs_before_the_closing_line_and_one_without_gets_a_new_block(tmp_path, capsys):
    repo = repository(tmp_path)
    text, diff = made(tmp_path, repo)
    assert "diff --git a/docs/adr/0002-small-client.md b/docs/adr/0002-small-client.md\n" in text
    assert ("@@ -1,6 +1,10 @@\n ---\n status: accepted\n date: 2026-01-01\n"
            "+code_ref:\n"
            "+  # suggested from: The client is `src/payments/client.py`, and `src/payments/retry.py` is its helper.\n"
            "+  - src/payments/client.py\n"
            "+  - src/payments/retry.py\n"
            " ---\n \n # Use the client\n") in text
    assert ("@@ -1,3 +1,14 @@\n"
            "+---\n"
            "+code_ref:\n"
            "+  # suggested from: The retry lives in `src/payments/retry.py` and is configured by config/payments.toml today.\n"
            "+  - config/payments.toml\n"
            "+  # suggested from: All settings move under the `settings` directory.\n"
            "+  - settings/\n"
            "+  # suggested from: See [the client](../../src/payments/client.py) for the caller.\n"
            "+  - src/payments/client.py\n"
            "+  # suggested from: The retry lives in `src/payments/retry.py` and is configured by config/payments.toml today.\n"
            "+  - src/payments/retry.py\n"
            "+---\n"
            " # Retry payment calls once\n \n ## Context\n") in text
    assert {name: len(h) for name, h in hunks(text).items()} == {"docs/adr/0001-retry-once.md": 1, "docs/adr/0002-small-client.md": 1}
    assert git_apply(repo, diff, "--check").returncode == 0


@needs_git
def test_an_adr_that_states_a_ref_is_never_touched_and_the_patch_changes_no_file(tmp_path, capsys):
    repo = repository(tmp_path)
    before = tree_hash(repo)
    text, _ = made(tmp_path, repo)
    assert "0003-small-app" not in text
    assert tree_hash(repo) == before


def test_a_code_ref_key_that_is_present_and_empty_is_replaced_not_repeated(tmp_path):
    repo = repository(tmp_path, **{"docs/adr/0004-empty.md": "---\ncode_ref: []\ntitle: Empty key\n---\n# Empty key\n\nSee `src/payments/retry.py`.\n"})
    text, diff = made(tmp_path, repo)
    assert ("@@ -1,5 +1,7 @@\n ---\n-code_ref: []\n+code_ref:\n+  # suggested from: See `src/payments/retry.py`.\n"
            "+  - src/payments/retry.py\n title: Empty key\n ---\n # Empty key\n") in text
    if shutil.which("git"):
        assert git_apply(repo, diff).returncode == 0
        assert decisions(init.build(repo, "Shop"))["docs/adr/0004-empty.md"]["code_ref"] == ["Shop:src/payments/retry.py"]


def test_the_comment_lines_are_ignored_by_init_and_the_refs_read_back_stated(tmp_path):
    repo = repository(tmp_path)
    before = init.build(repo, "Shop", suggest_refs=True)
    text, diff = made(tmp_path, repo)
    if shutil.which("git") is None:
        pytest.skip("needs git")
    assert git_apply(repo, diff).returncode == 0
    after = init.build(repo, "Shop")
    for name, props in decisions(before).items():
        if props.get("code_ref_source") != "suggested":
            assert decisions(after)[name] == props
            continue
        now = decisions(after)[name]
        assert now["code_ref"] == props["code_ref"]
        assert "code_ref_source" not in now and "code_ref_evidence" not in now
        stable = {k: v for k, v in props.items() if k not in ("code_ref", "code_ref_source", "code_ref_evidence", "content_hash")}
        assert {k: v for k, v in now.items() if k not in ("code_ref", "content_hash")} == stable
    patched = {"docs/adr/0001-retry-once.md", "docs/adr/0002-small-client.md"}
    assert [p for p in after["meta"]["problems"] if p["file"] in patched] == []
    assert init.build(repo, "Shop", suggest_refs=True)["nodes"] == after["nodes"]


@needs_git
def test_apply_then_init_on_the_shop_fixture_gives_the_same_code_refs_now_stated(tmp_path):
    repo = tmp_path / "shop"
    shutil.copytree(SHOP, repo)
    adr = repo / "docs" / "adr"
    first = adr / "0001-record-architecture-decisions.md"
    first.write_text(first.read_text(encoding="utf-8") + "\nSessions live in `src/session/store.py`.\n", encoding="utf-8")
    (adr / "0005-redact-card-numbers.md").write_text(
        "---\nstatus: accepted\ndeciders: [Ana]\n---\n# 5. Redact card numbers\n\nThe filter is `src/logging/redact.py`; the line format stays in\n"
        "src/logging/format.py. Pull requests need a [review](https://github.com/acme/shop/blob/main/src/payments/gateway.py).\n",
        encoding="utf-8")
    before = init.build(repo, "Shop", suggest_refs=True)
    suggested = {n: p for n, p in decisions(before).items() if p.get("code_ref_source") == "suggested"}
    assert sorted(suggested) == ["docs/adr/0001-record-architecture-decisions.md", "docs/adr/0005-redact-card-numbers.md"]
    stated = {n: p for n, p in decisions(before).items() if n not in suggested}
    text, diff = made(tmp_path, repo)
    assert sorted(hunks(text)) == sorted(suggested) and all(len(h) == 1 for h in hunks(text).values())
    assert git_apply(repo, diff, "--check").returncode == 0
    assert git_apply(repo, diff).returncode == 0
    after = decisions(init.build(repo, "Shop"))
    for name, props in suggested.items():
        assert after[name]["code_ref"] == props["code_ref"] != []
        assert "code_ref_source" not in after[name] and "code_ref_evidence" not in after[name]
    for name, props in stated.items():
        assert after[name] == props
    again = decisions(init.build(repo, "Shop", suggest_refs=True))
    assert all("code_ref_source" not in p for p in again.values())
    assert {n: p["code_ref"] for n, p in again.items() if "code_ref" in p} == {n: p["code_ref"] for n, p in after.items() if "code_ref" in p}


def test_skipped_tokens_are_listed_in_the_header_and_never_applied(tmp_path):
    repo = repository(tmp_path)
    text, _ = made(tmp_path, repo)
    head = text[:text.index("diff --git")]
    assert all(line.startswith("# ") for line in head.splitlines())
    for reason in ("`handler.py` matches 6 paths, more than 5; it is not suggested as a code ref",
                   "`src` is a bare common name; it matches 1 path; it is not suggested as a code ref",
                   "`README` is a bare common name; it matches 1 path; it is not suggested as a code ref"):
        assert f"#   docs/adr/0001-retry-once.md: {reason}\n" in head
    body = text[text.index("diff --git"):]
    assert "handler.py" not in body.replace("`handler.py`", "") and "  - README" not in body and "  - src\n" not in body and "  - src/\n" not in body


def test_nothing_is_written_inside_the_repository_by_decisis_and_the_patch_goes_only_to_file(tmp_path):
    repo = repository(tmp_path)
    before = tree_hash(repo)
    out = tmp_path / "elsewhere"
    out.mkdir()
    assert run_init(repo, out / "snapshot.json", "--patch", str(out / "suggest.diff")) == 0
    assert sorted(p.name for p in out.iterdir()) == ["snapshot.json", "suggest.diff"]
    assert tree_hash(repo) == before
    assert not any(p.name.endswith((".orig", ".rej", ".diff", ".patch")) for p in repo.rglob("*"))


@pytest.mark.parametrize("where", ["docs/adr/suggest.diff", "docs/decisions/suggest.diff", "adr/new/suggest.diff", "doc/adr/suggest.diff"])
def test_a_file_inside_an_adr_directory_is_refused_and_nothing_is_written(tmp_path, capsys, where):
    repo = repository(tmp_path, **{"docs/decisions/0010-x.md": "# X\n", "adr/new/keep": "", "doc/adr/keep": ""})
    before = tree_hash(repo)
    with pytest.raises(SystemExit) as e:
        run_init(repo, tmp_path / "snapshot.json", "--patch", str(repo / where))
    assert e.value.code == 2
    assert "outside the ADR directories" in capsys.readouterr().err
    assert tree_hash(repo) == before and not (tmp_path / "snapshot.json").exists()


def test_a_file_that_reaches_an_adr_directory_through_a_link_or_the_adr_dir_flag_is_refused(tmp_path, capsys):
    repo = repository(tmp_path, **{"notes/keep": ""})
    try:
        (repo / "link").symlink_to(repo / "docs" / "adr", target_is_directory=True)
    except OSError:
        pytest.skip("no symbolic links here")
    for where, flags in (("link/suggest.diff", ()), ("notes/suggest.diff", ("--adr-dir", "notes"))):
        with pytest.raises(SystemExit) as e:
            run_init(repo, tmp_path / "snapshot.json", "--patch", str(repo / where), *flags)
        assert e.value.code == 2 and "outside the ADR directories" in capsys.readouterr().err
    assert not (repo / "docs" / "adr" / "suggest.diff").exists() and not (repo / "notes" / "suggest.diff").exists()


def test_an_existing_file_is_never_overwritten_and_not_even_a_link_to_one(tmp_path, capsys):
    repo = repository(tmp_path)
    existing = tmp_path / "suggest.diff"
    existing.write_text("keep me\n", encoding="utf-8")
    with pytest.raises(SystemExit) as e:
        run_init(repo, tmp_path / "snapshot.json", "--patch", str(existing))
    assert e.value.code == 2 and "never overwrites" in capsys.readouterr().err
    assert existing.read_text(encoding="utf-8") == "keep me\n" and not (tmp_path / "snapshot.json").exists()
    link = tmp_path / "link.diff"
    try:
        link.symlink_to(tmp_path / "nowhere.diff")
    except OSError:
        pytest.skip("no symbolic links here")
    with pytest.raises(SystemExit):
        run_init(repo, tmp_path / "snapshot.json", "--patch", str(link))
    assert not (tmp_path / "nowhere.diff").exists()


def test_a_file_created_after_the_check_is_not_replaced(tmp_path):
    existing = tmp_path / "suggest.diff"
    existing.write_text("keep me\n", encoding="utf-8")
    with pytest.raises(ValueError, match="never overwrites"):
        patch.write(existing, patch.Patch(text="# x\n"))
    assert existing.read_text(encoding="utf-8") == "keep me\n"


def test_patch_needs_suggest_refs_and_a_different_file_from_out_and_a_directory_that_exists(tmp_path, capsys):
    repo = repository(tmp_path)
    for args, said in ((["--repo-dir", str(repo), "--out", str(tmp_path / "s.json"), "--patch", str(tmp_path / "p.diff")], "needs --suggest-refs"),
                       (["--repo-dir", str(repo), "--suggest-refs", "--out", str(tmp_path / "s.json"), "--patch", str(tmp_path / "s.json")],
                        "two different files"),
                       (["--repo-dir", str(repo), "--suggest-refs", "--out", str(tmp_path / "s.json"), "--patch", str(tmp_path / "no" / "p.diff")],
                        "is not a directory"),
                       (["--github", "acme/shop", "--suggest-refs", "--out", str(tmp_path / "s.json"), "--patch", str(tmp_path / "p.diff")],
                        "needs --repo-dir")):
        with pytest.raises(SystemExit) as e:
            cli.main(["init", *args])
        assert e.value.code == 2 and said in capsys.readouterr().err
    assert not (tmp_path / "s.json").exists() and not (tmp_path / "p.diff").exists()


def test_with_nothing_to_suggest_no_file_is_written_and_init_says_so(tmp_path, capsys):
    repo = write(tmp_path / "repo", {"docs/adr/0001-x.md": "# Use x\n\nNothing here names a path.\n", "docs/adr/0002-y.md": STATED, "src/app.py": ""})
    diff = tmp_path / "suggest.diff"
    capsys.readouterr()
    assert run_init(repo, tmp_path / "snapshot.json", "--patch", str(diff)) == 0
    printed = json.loads(capsys.readouterr().out)
    assert not diff.exists() and printed["patch"] == {"out": None, "adrs": 0, "code_refs": 0, "not_applied": 0, "left_out": []}


def test_init_prints_what_the_patch_holds(tmp_path, capsys):
    repo = repository(tmp_path)
    capsys.readouterr()
    text, diff = made(tmp_path, repo)
    snap = json.loads((tmp_path / "snapshot.json").read_text(encoding="utf-8"))
    assert decisions(snap)["docs/adr/0001-retry-once.md"]["code_ref_source"] == "suggested"
    assert "Adds 6 suggested code refs to 2 ADRs that state none." in text


@needs_git
def test_a_file_name_that_is_not_utf8_is_quoted_in_the_diff_and_the_snapshot_is_still_written(tmp_path, capsys):
    repo = repository(tmp_path)
    odd = os.fsencode(repo / "docs" / "adr") + b"/0009-caf\xe9.md"
    try:
        with open(odd, "wb") as f:
            f.write("# Use the app\n\nThe app is `src/app.py`.\n".encode("utf-8"))
    except (OSError, UnicodeEncodeError):
        pytest.skip("the file system refuses a name that is not UTF-8")
    diff = tmp_path / "suggest.diff"
    out = tmp_path / "snapshot.json"
    assert run_init(repo, out, "--patch", str(diff)) == 0
    raw = diff.read_bytes()
    assert b'diff --git "a/docs/adr/0009-caf\\351.md" "b/docs/adr/0009-caf\\351.md"\n--- "a/docs/adr/0009-caf\\351.md"\n' in raw
    raw.decode("utf-8")
    assert "\\udce9" in out.read_text(encoding="utf-8")
    assert json.loads(out.read_text(encoding="utf-8"))["nodes"]
    assert git_apply(repo, diff, "--check").returncode == 0
    assert git_apply(repo, diff).returncode == 0
    assert open(odd, "rb").read().startswith(b"---\ncode_ref:\n  # suggested from: The app is `src/app.py`.\n  - src/app.py\n---\n# Use the app")


@needs_git
@pytest.mark.parametrize("git", [False, True])
def test_a_code_file_name_that_is_not_utf8_is_never_in_the_patch(tmp_path, git):
    repo = write(tmp_path / "repo", {"docs/adr/0001-x.md": "# Use x\n\nWe keep `x.go` and `src/y.go` as they are.\n", "src/y.go": ""})
    odd = repo / "d\udcff"
    try:
        odd.mkdir()
    except (OSError, UnicodeEncodeError):
        pytest.skip("the file system refuses a name that is not UTF-8")
    (odd / "x.go").write_text("", encoding="utf-8")
    if git:
        subprocess.run(["git", "init", "-q", str(repo)], check=True)
    text, diff = made(tmp_path, repo)
    assert "+  - src/y.go\n" in text and "x.go\n" not in text.replace("`x.go`", "") and "d\\" not in text
    assert git_apply(repo, diff).returncode == 0


@needs_git
def test_names_with_a_space_or_a_leading_at_sign_are_quoted_so_init_reads_them_back(tmp_path):
    adr = ("# Pictures\n\nSee [the notes](../../my%20notes/plan.md) and `@types/node/index.d.ts`, and [more](../../%25odd/a.py).\n")
    repo = write(tmp_path / "repo", {"docs/adr/0001-notes best.md": adr, "my notes/plan.md": "", "@types/node/index.d.ts": "", "%odd/a.py": ""})
    before = decisions(init.build(repo, None, suggest_refs=True))["docs/adr/0001-notes best.md"]
    assert before["code_ref"] == ["%odd/a.py", "@types/node/index.d.ts", "my notes/plan.md"]
    text, diff = made(tmp_path, repo)
    assert 'diff --git "a/docs/adr/0001-notes best.md" "b/docs/adr/0001-notes best.md"\n' in text
    assert '"@types/node/index.d.ts"' in text and '"my notes/plan.md"' in text and '"%odd/a.py"' in text
    assert git_apply(repo, diff).returncode == 0
    after = decisions(init.build(repo, None))["docs/adr/0001-notes best.md"]
    assert after["code_ref"] == before["code_ref"] and "code_ref_source" not in after


@needs_git
@pytest.mark.parametrize("name, adr", [
    ("crlf front", "---\r\nstatus: accepted\r\n---\r\n# Use the app\r\n\r\nThe app is `src/app.py`.\r\n"),
    ("crlf none", "# Use the app\r\n\r\nThe app is `src/app.py`.\r\n"),
    ("bom front", "\ufeff---\nstatus: accepted\n---\n# Use the app\n\nThe app is `src/app.py`.\n"),
    ("bom none", "\ufeff# Use the app\n\nThe app is `src/app.py`.\n"),
    ("no newline", "# Use the app\n\nThe app is `src/app.py`."),
    ("front no newline", "---\nstatus: accepted\n---\n# Use the app\n\nThe app is `src/app.py`."),
    ("one line", "# `src/app.py`"),
    ("front only closes", "---\nstatus: accepted\n---\n# T `src/app.py`"),
    ("empty front", "---\n---\n# Use the app\n\nThe app is `src/app.py`.\n"),
    ("crlf empty key", "---\r\ncode_ref:\r\nstatus: accepted\r\n---\r\n# Use the app\r\n\r\nThe app is `src/app.py`.\r\n"),
    ("dots close", "---\nstatus: accepted\n...\n# Use the app\n\nThe app is `src/app.py`.\n"),
])
def test_line_endings_a_byte_order_mark_and_a_missing_final_newline_are_kept(tmp_path, name, adr):
    repo = write(tmp_path / "repo", {"src/app.py": ""})
    (repo / "docs" / "adr").mkdir(parents=True)
    (repo / "docs" / "adr" / "0001-app.md").write_bytes(adr.encode("utf-8"))
    before = decisions(init.build(repo, None, suggest_refs=True))["docs/adr/0001-app.md"]
    assert before["code_ref"] == ["src/app.py"]
    text, diff = made(tmp_path, repo)
    assert git_apply(repo, diff, "--check").returncode == 0, name
    assert git_apply(repo, diff).returncode == 0
    patched = (repo / "docs" / "adr" / "0001-app.md").read_bytes().decode("utf-8")
    assert ("\r\n" in patched) == ("\r\n" in adr) and patched.startswith("\ufeff") == adr.startswith("\ufeff")
    assert patched.endswith("\n") == adr.endswith("\n")
    after = decisions(init.build(repo, None))["docs/adr/0001-app.md"]
    assert after["code_ref"] == ["src/app.py"] and "code_ref_source" not in after
    assert {k: v for k, v in after.items() if k not in ("code_ref", "content_hash")} == {k: v for k, v in before.items() if k not in
                                                                                       ("code_ref", "code_ref_source", "code_ref_evidence", "content_hash")}


def test_a_sentence_is_one_comment_line_even_when_it_holds_line_breaks_or_runs_long(tmp_path):
    sentence = "The app is `src/app.py`\rand `src/payments/client.py`\u2028 " + "word " * 120
    repo = write(tmp_path / "repo", {"docs/adr/0001-app.md": f"# Use the app\n\n```go\n{sentence}\n```\n", "src/app.py": "", "src/payments/client.py": ""})
    props = decisions(init.build(repo, None, suggest_refs=True))["docs/adr/0001-app.md"]
    text, diff = made(tmp_path, repo)
    comments = [line for line in text.splitlines() if line.startswith("+  # ")]
    assert len(comments) == len(set(comments)) and all(len(c) <= patch.COMMENT_WIDTH + 40 for c in comments)
    assert "\r" not in text and "\u2028" not in text
    if shutil.which("git"):
        assert git_apply(repo, diff).returncode == 0
        assert decisions(init.build(repo, None))["docs/adr/0001-app.md"]["code_ref"] == props["code_ref"]


def test_an_adr_that_changed_after_init_read_it_is_left_out_and_said_so(tmp_path):
    repo = repository(tmp_path)
    snap = init.build(repo, "Shop", suggest_refs=True)
    changed = repo / "docs" / "adr" / "0002-small-client.md"
    changed.write_text(WITH_FRONT + "\nMore.\n", encoding="utf-8")
    found = patch.build(repo, snap)
    assert found.adrs == ["docs/adr/0001-retry-once.md"]
    assert found.left_out == [("docs/adr/0002-small-client.md", "it changed after init read it; run init again")]
    assert "# Left out of this patch:\n#   docs/adr/0002-small-client.md: it changed after init read it; run init again\n" in found.text


def test_the_docs_describe_the_patch():
    model = (ROOT / "docs" / "data-model.md").read_text(encoding="utf-8")
    for name in ("--patch FILE", "git apply --check", "code_ref_source", "suggested from:", "never replaced"):
        assert name in model, name
    assert "--patch FILE" in (ROOT / "docs" / "commands.md").read_text(encoding="utf-8")
    assert "--patch" in (ROOT / "README.md").read_text(encoding="utf-8")
