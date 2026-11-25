from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest

from test_action import git
from test_audit import no_network
from decisis import cli, committed, init


def adr(title: str, *front: str) -> str:
    return "\n".join(["---", f"title: {title}", "status: accepted", *front, "---", "", f"# {title}", ""])


def write(root: Path, files: dict[str, str]) -> Path:
    for rel, body in files.items():
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_text(body, encoding="utf-8")
    return root


def link(root: Path, rel: str, target: str) -> None:
    (root / rel).parent.mkdir(parents=True, exist_ok=True)
    os.symlink(target, root / rel)


def commit(root: Path) -> str:
    if not (root / ".git").exists():
        git(root, "init", "-q", "-b", "main")
    git(root, "add", "-A")
    git(root, "commit", "-q", "--allow-empty", "-m", "base")
    return subprocess.run(["git", "-C", str(root), "rev-parse", "HEAD"], capture_output=True, text=True, check=True).stdout.strip()


def view(nodes: list[dict], edges: list[dict], meta: dict) -> dict:
    return {"decisions": sorted((n["id"], n["props"]["source_file"]) for n in nodes if n["kind"] == "decision"),
            "edges": sorted((e["source"], e["type"], e["target"]) for e in edges),
            "problems": sorted((p["file"], p["action"], p["reason"], p.get("kind")) for p in meta["problems"]),
            "unread": [(u["file"], u["action"]) for u in init.unread_decisions(meta)]}


def both(root: Path) -> tuple[dict, dict]:
    sha = commit(root)
    local = init.build(root, "shop")
    base = committed.built(root, sha, "shop", [])
    return view(local["nodes"], local["edges"], local["meta"]), view(base.nodes, base.edges, base.meta)


def listed(seen: dict) -> list[tuple[str, str, str]]:
    return [(f, a, r) for f, a, r, k in seen["problems"] if k == "decision" and a in (init.IGNORED, init.SKIPPED, init.NOT_READ)]


def test_an_archive_folder_and_a_nested_twin_leave_ids_and_supersedes_edges_as_before(tmp_path):
    root = write(tmp_path / "repo", {
        "docs/adr/0007-new.md": adr("new"),
        "docs/adr/0008-c.md": adr("c", 'supersedes: ["#7"]'),
        "docs/adr/archive/0007-old.md": adr("old"),
        "docs/adr/api_v2.md": adr("top"),
        "docs/adr/api/v2.md": adr("nested"),
    })
    local, base = both(root)
    assert local == base
    assert local["decisions"] == [("decision:shop-docs-adr-0007-new", "docs/adr/0007-new.md"),
                                  ("decision:shop-docs-adr-0008-c", "docs/adr/0008-c.md"),
                                  ("decision:shop-docs-adr-api-v2", "docs/adr/api_v2.md")]
    assert local["edges"] == [("decision:shop-docs-adr-0008-c", "SUPERSEDES", "decision:shop-docs-adr-0007-new")]
    assert listed(local) == [("docs/adr/api/v2.md", "ignored", init.SUBFOLDER), ("docs/adr/archive/0007-old.md", "ignored", init.SUBFOLDER)]
    assert local["unread"] == []


def test_a_subfolder_never_fails_fail_on_unresolved(tmp_path, capsys, no_network):
    root = write(tmp_path / "repo", {"docs/adr/0001-a.md": adr("a"), "docs/adr/archive/0002-b.md": adr("b"), "src/x.py": "X = 1\n"})
    out = tmp_path / "snapshot.json"
    assert cli.main(["init", "--repo-dir", str(root), "--out", str(out)]) == 0
    capsys.readouterr()
    assert cli.main(["check", str(out), "--repo-dir", str(root), "--changed", "src/x.py", "--fail-on-unresolved"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert "unread_decisions" not in report
    problems = json.loads(out.read_text())["meta"]["problems"]
    assert {"file": "docs/adr/archive/0002-b.md", "reason": init.SUBFOLDER, "action": "ignored", "kind": "decision"} in problems


def test_a_file_below_an_adr_directory_is_not_a_decision_source_file():
    assert init.source("docs/adr/0001-a.md") and not init.source("docs/adr/archive/0001-a.md")
    assert committed.source_files(["docs/adr/archive/0001-a.md", "docs/adr/0002-b.md"], None) == ["docs/adr/0002-b.md"]


def dotted_folder_link(root: Path) -> list[tuple]:
    write(root, {"docs/adr/0001-a.md": adr("a"), "shared/v1.2/0002-b.md": adr("b")})
    link(root, "docs/adr/v1.2", "../../shared/v1.2")
    return [("docs/adr/v1.2", "ignored", init.LINKED_OTHER)]


def plain_folder_link(root: Path) -> list[tuple]:
    write(root, {"docs/adr/0001-a.md": adr("a"), "shared/area/0002-b.md": adr("b")})
    link(root, "docs/adr/area", "../../shared/area")
    return [("docs/adr/area", "ignored", init.LINKED_OTHER)]


def template_folder_link(root: Path) -> list[tuple]:
    write(root, {"docs/adr/0001-a.md": adr("a"), "shared/tpl/x.md": adr("x")})
    link(root, "docs/adr/templates", "../../shared/tpl")
    return []


def plain_file_link(root: Path) -> list[tuple]:
    write(root, {"docs/adr/0001-a.md": adr("a"), "LICENSE": "x\n"})
    link(root, "docs/adr/LICENSE", "../../LICENSE")
    return [("docs/adr/LICENSE", "ignored", init.LINKED_OTHER)]


def record_link(root: Path) -> list[tuple]:
    write(root, {"docs/adr/0001-a.md": adr("a"), "other/0002-b.md": adr("b")})
    link(root, "docs/adr/0002-b.md", "../../other/0002-b.md")
    link(root, "docs/adr/0003-gone.md", "../../missing.md")
    return [("docs/adr/0002-b.md", "skipped", init.LINKED_RECORD), ("docs/adr/0003-gone.md", "skipped", init.LINKED_RECORD)]


def nested_record_link(root: Path) -> list[tuple]:
    write(root, {"docs/adr/0001-a.md": adr("a"), "other/0002-b.md": adr("b")})
    link(root, "docs/adr/area/0002-b.md", "../../../other/0002-b.md")
    return [("docs/adr/area/0002-b.md", "ignored", init.SUBFOLDER)]


def odd_folders(root: Path) -> list[tuple]:
    write(root, {"docs/adr/0001-a.md": adr("a"), "docs/adr/0009-old.md/0010-c.md": adr("c"), "docs/adr/.hidden/0011-d.md": adr("d"),
                 "docs/adr/Templates/0012-e.md": adr("e"), "docs/adr/a/b/c/d/e/f/g/0013-deep.MD": adr("deep"),
                 "docs/adr/area/README.md": "# area\n", "docs/adr/area/diagram.png": "png"})
    return [("docs/adr/.hidden/0011-d.md", "ignored", init.SUBFOLDER), ("docs/adr/0009-old.md/0010-c.md", "ignored", init.SUBFOLDER),
            ("docs/adr/a/b/c/d/e/f/g/0013-deep.MD", "ignored", init.SUBFOLDER)]


def linked_adr_directory(root: Path) -> list[tuple]:
    write(root, {"records/0001-a.md": adr("a"), "docs/decisions/0002-b.md": adr("b")})
    link(root, "docs/adr", "../records")
    return [("docs/adr", "not read", init.DIR_LINKED)]


def submodule(root: Path) -> list[tuple]:
    sub = write(root.parent / "sub", {"0002-shared.md": adr("shared")})
    commit(sub)
    write(root, {"docs/adr/0001-a.md": adr("a")})
    git(root, "init", "-q", "-b", "main")
    git(root, "-c", "protocol.file.allow=always", "submodule", "add", "-q", str(sub), "docs/adr/shared")
    return [("docs/adr/shared", "ignored", init.SUBMODULE)]


def submodule_adr_directory(root: Path) -> list[tuple]:
    sub = write(root.parent / "sub", {"0002-shared.md": adr("shared")})
    commit(sub)
    write(root, {"src/x.py": "X = 1\n"})
    git(root, "init", "-q", "-b", "main")
    git(root, "-c", "protocol.file.allow=always", "submodule", "add", "-q", str(sub), "docs/adr")
    return [("docs/adr", "not read", init.DIR_SUBMODULE)]


@pytest.mark.parametrize("case", [dotted_folder_link, plain_folder_link, template_folder_link, plain_file_link, record_link,
                                  nested_record_link, odd_folders, linked_adr_directory, submodule, submodule_adr_directory])
def test_init_and_the_base_commit_reader_list_the_same_things_by_one_rule(tmp_path, case):
    root = tmp_path / "repo"
    root.mkdir()
    expected = case(root)
    local, base = both(root)
    assert local == base
    assert listed(local) == sorted(expected)
    assert local["unread"] == [(f, a) for f, a, _ in sorted(expected) if a in init.UNREAD]


def nested(root: Path, count: int) -> Path:
    files = {"docs/adr/0001-a.md": adr("a"), "docs/adr/0002-b.md": adr("b")}
    files |= {f"docs/adr/templates/t{i}.md": adr(f"t{i}") for i in range(6)}
    files |= {f"docs/adr/old/{i:04d}-x.md": adr(f"x{i}") for i in range(count)}
    return write(root, files)


@pytest.mark.parametrize("count,notes", [(2, 0), (3, 1)])
def test_the_listing_stops_after_max_listed_at_the_same_file_in_both_readers(tmp_path, monkeypatch, count, notes):
    monkeypatch.setattr(init, "MAX_LISTED", 2)
    local, base = both(nested(tmp_path / "repo", count))
    assert local == base
    rows = listed(local)
    assert [f for f, _, r in rows if r == init.SUBFOLDER] == ["docs/adr/old/0000-x.md", "docs/adr/old/0001-x.md"]
    assert len([f for f, _, r in rows if f == "docs/adr"]) == notes and local["unread"] == []


@pytest.mark.parametrize("count,notes", [(3, 0), (4, 1)])
def test_the_entry_cap_stops_at_the_same_entry_in_both_readers_and_skips_template_folders(tmp_path, monkeypatch, count, notes):
    monkeypatch.setattr(init, "MAX_ENTRIES", 3)
    root = nested(tmp_path / "repo", 0)
    write(root, {f"docs/adr/old/{i}.png": "png" for i in range(count - 1)} | {"docs/adr/zz/0009-z.md": adr("z")})
    local, base = both(root)
    assert local == base
    stops = [r for f, _, r in listed(local) if f == "docs/adr"]
    assert len(stops) == notes and all(r.startswith("decisis stopped looking in the subfolders of docs/adr after 3 files") for r in stops)
    assert ("docs/adr/zz/0009-z.md" in [f for f, _, _ in listed(local)]) == (notes == 0)


def counted(root: Path, adrs: int, postmortems: int) -> Path:
    files = {f"docs/adr/{i:04d}-a.md": adr(f"a{i}") for i in range(adrs)}
    files |= {f"docs/postmortems/2026-01-0{i + 1}-p.md": adr(f"p{i}") for i in range(postmortems)}
    files |= {f"docs/adr/old/{i:04d}-x.md": adr(f"x{i}") for i in range(4)}
    return write(root, files)


def test_the_record_cap_counts_adr_files_and_postmortems_apart_in_both_readers(tmp_path, monkeypatch):
    monkeypatch.setattr(init, "MAX_RECORDS", 3)
    local, base = both(counted(tmp_path / "fits", 3, 3))
    assert local == base and len(local["decisions"]) == 3
    for name, adrs, postmortems, what in (("adrs", 4, 0, "ADR"), ("postmortems", 1, 4, "postmortem")):
        root = counted(tmp_path / name, adrs, postmortems)
        sha = commit(root)
        message = f"the {what} directories hold 4 record files, more than the 3 decisis reads"
        with pytest.raises(ValueError, match=message):
            init.build(root, "shop")
        with pytest.raises(ValueError, match=message):
            committed.built(root, sha, "shop", [])


def test_a_linked_adr_directory_reaches_unread_decisions_and_fails_fail_on_unresolved(tmp_path, capsys, no_network):
    root = write(tmp_path / "repo", {"records/0001-a.md": adr("a"), "src/x.py": "X = 1\n"})
    link(root, "docs/adr", "../records")
    out = tmp_path / "snapshot.json"
    assert cli.main(["init", "--repo-dir", str(root), "--out", str(out)]) == 0
    capsys.readouterr()
    assert cli.main(["check", str(out), "--repo-dir", str(root), "--changed", "src/x.py", "--fail-on-unresolved"]) == 1
    report = json.loads(capsys.readouterr().out)
    assert report["unread_decisions"] == [{"file": "docs/adr", "reason": init.DIR_LINKED, "action": "not read"}]
