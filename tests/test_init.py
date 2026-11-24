from __future__ import annotations

import hashlib
import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

from decisis import checkout as co
from decisis import cli, impact, init

ROOT = Path(__file__).resolve().parents[1]
SHOP = ROOT / "fixtures" / "init" / "shop"
ADR = "decision:shop-docs-adr-"
MADR = "decision:shop-docs-decisions-"
PM = "record:shop-docs-postmortems-"
OWNERS = "concept:shop-codeowners-"


def run_init(tmp_path: Path, capsys, *extra: str) -> tuple[Path, dict]:
    out = tmp_path / "snapshot.json"
    capsys.readouterr()
    assert cli.main(["init", "--repo-dir", str(SHOP), "--repo", "Shop", "--out", str(out), *extra]) == 0
    return out, json.loads(capsys.readouterr().out)


def snapshot() -> dict:
    return init.build(SHOP, "Shop")


def by_id(snap: dict) -> dict:
    return {n["id"]: n for n in snap["nodes"]}


def governing(report: dict, i: int) -> list[tuple[int, str]]:
    return [(g["hops"], g["id"]) for g in report["impact"][i]["governing"]]


def owned_by(snap: dict, *owners: str) -> dict:
    [node] = [n for n in snap["nodes"] if n["kind"] == "concept" and n["props"]["owners"] == list(owners)]
    return node


def test_init_then_impact_finds_the_decisions_each_file_is_governed_by(tmp_path, capsys):
    out, printed = run_init(tmp_path, capsys)
    assert printed["nodes"] == 12 and printed["edges"] == 4
    graph = co.load(out.read_text(encoding="utf-8"))
    paths = ["src/payments/retry.py", "src/payments/gateway.py", "src/payments/refund.py", "src/logging/redact.py", "package-lock.json"]
    box = tmp_path / "box"
    box.mkdir()
    report = impact.run(graph, paths, repo="Shop", root=box)
    decisions = [sorted(i for _, i in governing(report, n) if i.startswith("decision:")) for n in range(len(paths))]
    assert decisions == [
        [f"{ADR}0003-retry-payment-calls-once"],
        [f"{ADR}0003-retry-payment-calls-once"],
        [],
        [f"{MADR}0011-card-numbers-never-reach-logs"],
        [f"{MADR}0010-no-high-advisories-in-shipped-dependencies"],
    ]
    assert (1, f"{PM}2026-05-02-card-number-in-logs") in governing(report, 3)
    assert governing(report, 2) == [(0, owned_by(snapshot(), "@shop/payments-core")["id"])]
    assert [(g["id"], g["status"], g["superseded_by"]) for g in report["impact"][0]["superseded"]] == [
        (f"{ADR}0002-retry-payment-calls-three-times", "superseded", [f"{ADR}0003-retry-payment-calls-once"])]
    assert "superseded" not in report["impact"][1]


def test_a_codeowners_concept_carries_no_governance_to_the_files_it_owns():
    snap = snapshot()
    owners = [n["id"] for n in snap["nodes"] if n["id"].startswith(OWNERS)]
    assert owners and not [e for e in snap["edges"] if e["source"] in owners or e["target"] in owners]
    assert all(n["kind"] == "concept" for n in snap["nodes"] if n["id"] in owners)


def test_running_twice_on_the_same_tree_gives_byte_identical_output(tmp_path, capsys):
    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()
    first, _ = run_init(tmp_path / "a", capsys)
    second, _ = run_init(tmp_path / "b", capsys)
    assert first.read_bytes() == second.read_bytes()
    assert first.read_text(encoding="utf-8") == init.dump(snapshot())


def test_every_node_carries_its_source_file_and_a_hash_of_what_it_was_built_from():
    for node in snapshot()["nodes"]:
        props = node["props"]
        source = SHOP / props["source_file"]
        built_from = source.read_bytes()
        assert props["content_hash"] == "sha256:" + hashlib.sha256(built_from).hexdigest(), node["id"]


def test_the_snapshot_loads_with_matching_counts():
    snap = snapshot()
    graph = co.load(init.dump(snap))
    assert (snap["meta"]["nodes"], snap["meta"]["edges"]) == (len(graph.nodes), len(graph.edges))


def test_a_nygard_adr_gives_status_date_and_supersedes_from_its_headings():
    nodes = by_id(snapshot())
    old, new = nodes[f"{ADR}0002-retry-payment-calls-three-times"], nodes[f"{ADR}0003-retry-payment-calls-once"]
    assert (old["props"]["status"], old["props"]["date"]) == ("superseded", "2026-01-20")
    assert new["props"]["status"] == "accepted" and new["props"]["deciders"] == ["Ana", "Ben"]
    assert new["props"]["code_ref"] == ["Shop:src/payments/retry.py"] and new["props"]["also_touches"] == ["Shop:src/payments/gateway.py"]
    assert new["props"]["statement"] == "A failed payment call is retried once, and every call carries an idempotency key."
    assert new["title"] == "3. Retry payment calls once, with an idempotency key"


def test_a_superseding_adr_gets_one_supersedes_edge_from_the_new_to_the_old():
    edges = [e for e in snapshot()["edges"] if e["type"] == "SUPERSEDES"]
    assert [(e["source"], e["target"]) for e in edges] == [(f"{ADR}0003-retry-payment-calls-once", f"{ADR}0002-retry-payment-calls-three-times")]


def test_madr_front_matter_and_bullets_give_status_date_deciders_and_the_rule_unchanged():
    nodes = by_id(snapshot())
    advisories = nodes[f"{MADR}0010-no-high-advisories-in-shipped-dependencies"]["props"]
    assert (advisories["status"], advisories["date"], advisories["deciders"]) == ("accepted", "2026-02-01", ["Ana", "Chen"])
    assert advisories["rule"] == {"advisory_severity_at_least": "HIGH", "dependencies": "shipped"}
    assert advisories["subject_path"] == ["Shop:package-lock.json"]
    logs = nodes[f"{MADR}0011-card-numbers-never-reach-logs"]["props"]
    assert (logs["status"], logs["date"], logs["deciders"]) == ("accepted", "2026-02-10", ["Ben", "Chen"])


def test_each_owner_set_is_one_concept_over_the_paths_github_gives_it():
    snap = snapshot()
    concepts = sorted((n["props"]["owners"], n["props"]["code_ref"], n["props"]["source_lines"]) for n in snap["nodes"] if n["kind"] == "concept")
    assert concepts == [
        (["@ana", "@shop/platform"], ["Shop:src/logging/"], [4]),
        (["@shop/docs"], ["Shop:docs/"], [5]),
        (["@shop/payments-core"], ["Shop:src/payments/"], [7]),
        (["@shop/platform"], ["Shop:.github/", "Makefile", "Shop:src/session/"], [2]),
        (["security@shop.example"], ["Shop:package-lock.json"], [8]),
    ]
    node = owned_by(snap, "@shop/payments-core")
    assert node["kind"] == "concept" and node["title"] == "Owned by @shop/payments-core"
    assert node["props"]["source_file"] == ".github/CODEOWNERS"


def test_a_postmortem_is_a_record_about_the_decisions_it_names():
    snap = snapshot()
    about = sorted((e["source"], e["target"]) for e in snap["edges"] if e["type"] == "ABOUT")
    assert about == [
        (f"{PM}2026-03-14-duplicate-charges", f"{ADR}0002-retry-payment-calls-three-times"),
        (f"{PM}2026-03-14-duplicate-charges", f"{ADR}0003-retry-payment-calls-once"),
        (f"{PM}2026-05-02-card-number-in-logs", f"{MADR}0011-card-numbers-never-reach-logs"),
    ]
    assert by_id(snap)[f"{PM}2026-03-14-duplicate-charges"]["props"]["code_ref"] == ["Shop:src/payments/retry.py"]


def test_each_unreadable_or_malformed_file_is_reported_with_its_reason_and_skipped():
    problems = [(p["file"], p["action"], p["reason"]) for p in snapshot()["meta"]["problems"]]
    assert problems == [
        (".github/CODEOWNERS", "no effect", "line 3: a later line owns every file the pattern /src/payments/ matches"),
        (".github/CODEOWNERS", "no effect", "line 6: a later line owns every file the pattern /src/payments/retry.py matches"),
        (".github/CODEOWNERS", "skipped", "line 10: the pattern /src/[ab]/ uses character ranges ([), which GitHub does not support"),
        (".github/CODEOWNERS", "skipped", "line 9: platform-team is not @user, @org/team or an email address"),
        ("docs/CODEOWNERS", "not read", "GitHub reads only the first of .github/CODEOWNERS, CODEOWNERS, docs/CODEOWNERS; this one is .github/CODEOWNERS"),
        ("docs/adr/0001-record-architecture-decisions.md", "kept without code paths",
         "it names no code paths (front matter code_ref, subject_path or also_touches)"),
        ("docs/adr/0004-cache-sessions.md", "skipped", "front matter line 3: nested mappings are not supported"),
        ("docs/postmortems/2026-05-02-card-number-in-logs.md", "kept without code paths",
         "it names no code paths (front matter code_ref, subject_path or also_touches)"),
        ("docs/postmortems/2026-05-02-card-number-in-logs.md", "no edge", "it names ADR-0099, but no ADR file matches 'ADR-0099'"),
        ("docs/postmortems/2026-06-01-refunds-failed.md", "skipped", "it is not UTF-8 text (byte 69 cannot be decoded)"),
    ]
    ids = by_id(snapshot())
    assert not [i for i in ids if "0004" in i or "refunds" in i or "template" in i or "readme" in i]


def adr_repo(tmp_path: Path, front: str, body: str = "# A decision\n") -> Path:
    (tmp_path / "docs" / "adr").mkdir(parents=True)
    (tmp_path / "docs" / "adr" / "0001-a.md").write_text(f"---\n{front}---\n{body}", encoding="utf-8")
    return tmp_path


@pytest.mark.parametrize("front,props", [
    ("code_ref: src/a.py\n", {"code_ref": ["src/a.py"]}),
    ("code_ref: 'src/it''s.py'  # a comment\n", {"code_ref": ["src/it's.py"]}),
    ('code_ref: ["src/a.py", "Other:lib/b.py"]\n', {"code_ref": ["src/a.py", "Other:lib/b.py"]}),
    ("code_ref:\n- src/a.py\n- src/b/\n", {"code_ref": ["src/a.py", "src/b/"]}),
    ("deciders: Ana, Ben\nstatus: Accepted\ncode_ref: [src/a.py, src/b.py]\n",
     {"deciders": ["Ana", "Ben"], "status": "accepted", "code_ref": ["src/a.py", "src/b.py"]}),
    ('rule: {"advisory_severity_at_least": "LOW"}\nsubject_path: "x.py"\n', {"rule": {"advisory_severity_at_least": "LOW"}, "subject_path": ["x.py"]}),
])
def test_the_front_matter_subset_reads_scalars_lists_and_inline_json(tmp_path, front, props):
    snap = init.build(adr_repo(tmp_path, front))
    got = snap["nodes"][0]["props"]
    assert {k: got[k] for k in props} == props and snap["meta"]["problems"] == []


@pytest.mark.parametrize("front,reason", [
    ("summary: |\n  text\n", "'|' starts YAML this reader does not support"),
    ("code_ref: &a src/a.py\n", "'&' starts YAML this reader does not support"),
    ("owner:\n  name: Ana\n", "nested mappings are not supported"),
    ("title: a\ntitle: b\n", "title is given twice"),
    ("rule: advisory HIGH\n", "rule must be an inline JSON object"),
    ('rule: {"advisory_severity_at_least": \n', "inline JSON does not parse"),
    ('code_ref: [["a.py"]]\n', "list items must be text or whole numbers"),
    ("code_ref: /src/a.py\n", "is not a path relative to the repository root"),
    ("code_ref: ../other/a.py\n", "is not a path relative to the repository root"),
    ("status: [a, b]\n", "status must be one line of text"),
    ("just text\n", "expected 'key: value'"),
])
def test_front_matter_outside_the_subset_skips_the_file_with_a_reason(tmp_path, front, reason):
    snap = init.build(adr_repo(tmp_path, front))
    assert snap["nodes"] == []
    [problem] = snap["meta"]["problems"]
    assert problem["file"] == "docs/adr/0001-a.md" and problem["action"] == "skipped" and reason in problem["reason"]


def test_an_adr_without_a_title_or_with_unclosed_front_matter_is_skipped(tmp_path):
    root = adr_repo(tmp_path, "code_ref: a.py\n", "no heading here\n")
    (root / "docs" / "adr" / "0002-b.md").write_text("---\ncode_ref: a.py\n# B\n", encoding="utf-8")
    reasons = [p["reason"] for p in init.build(root)["meta"]["problems"]]
    assert reasons == ["it has no title: neither a front matter title nor a '# ' heading",
                       "the front matter opens with --- on line 1 and never closes"]


def test_without_a_repo_name_code_paths_stay_as_written(tmp_path):
    snap = init.build(adr_repo(tmp_path, "code_ref: [src/a.py, Other:lib/b.py]\n"))
    assert snap["nodes"][0]["id"] == "decision:docs-adr-0001-a"
    assert snap["nodes"][0]["props"]["code_ref"] == ["src/a.py", "Other:lib/b.py"]
    snap = init.build(tmp_path, "Shop")
    assert snap["nodes"][0]["props"]["code_ref"] == ["Shop:src/a.py", "Other:lib/b.py"]


def test_an_unresolved_supersedes_keeps_the_node_and_makes_no_edge(tmp_path):
    snap = init.build(adr_repo(tmp_path, "code_ref: a.py\nsupersedes: 7\n"))
    assert len(snap["nodes"]) == 1 and snap["edges"] == []
    assert snap["meta"]["problems"] == [{"file": "docs/adr/0001-a.md", "reason": "it supersedes 7, but no ADR file matches '7'", "action": "no edge"}]


def test_adr_dir_reads_only_that_directory_and_refuses_one_outside_the_repository(tmp_path):
    root = adr_repo(tmp_path, "code_ref: a.py\n")
    (root / "arch").mkdir()
    (root / "arch" / "use-x.md").write_text("---\ncode_ref: x.py\n---\n# Use X\n", encoding="utf-8")
    assert [n["id"] for n in init.build(root, adr_dir="arch")["nodes"]] == ["decision:arch-use-x"]
    with pytest.raises(ValueError, match="outside the repository"):
        init.build(root, adr_dir="..")
    with pytest.raises(ValueError, match="must be letters"):
        init.build(root, "Shop:x")
    with pytest.raises(ValueError, match="not a directory"):
        init.build(root / "missing")


def test_a_repository_with_none_of_the_sources_gives_an_empty_snapshot_and_says_so(tmp_path):
    snap = init.build(tmp_path)
    assert (snap["nodes"], snap["edges"]) == ([], [])
    assert [p["action"] for p in snap["meta"]["problems"]] == ["not read"]


def test_build_merges_another_reader_in_the_same_shape():
    def pull_requests(tree: init.Tree) -> tuple[list[dict], list[dict]]:
        pr = {"id": "record:shop-pr-12", "kind": "record", "title": "Retry once", "props": {"source_file": "pulls/12", "content_hash": "sha256:0"}}
        return [pr], [{"source": pr["id"], "target": tree.resolve_adr("ADR-3", tree.root / "x"), "type": "ABOUT", "evidence": "the PR names ADR-3"}]
    snap = init.build(SHOP, "Shop", init.read_adrs, pull_requests)
    assert [n["id"] for n in snap["nodes"]] == sorted(n["id"] for n in snap["nodes"])
    assert {"source": "record:shop-pr-12", "target": f"{ADR}0003-retry-payment-calls-once", "type": "ABOUT",
            "evidence": "the PR names ADR-3"} in snap["edges"]
    assert not [n for n in snap["nodes"] if n["kind"] == "concept"]


def test_every_front_matter_key_the_readers_use_is_documented():
    model = (ROOT / "docs" / "data-model.md").read_text(encoding="utf-8")
    for key in (*init.TEXT_KEYS, *init.LIST_KEYS, "rule"):
        assert f"`{key}`" in model, key


def test_the_readme_quick_start_runs_init_before_impact():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    start = readme.index("## Quick start")
    quick = readme[start:readme.index("\n## ", start + 1)]
    assert re.search(r"decisis init .*--out snapshot\.json", quick)
    assert quick.index("decisis init") < quick.index("decisis impact")


def test_a_madr_status_line_that_says_superseded_by_makes_the_edge_from_the_new_adr(tmp_path):
    root = adr_repo(tmp_path, "code_ref: a.py\n", "# Old\n\n* Status: superseded by [ADR-0002](0002-new.md)\n* Date: 2026-01-01\n")
    (root / "docs" / "adr" / "0002-new.md").write_text("---\ncode_ref: a.py\nstatus: accepted\n---\n# New\n", encoding="utf-8")
    snap = init.build(root)
    assert {n["id"]: n["props"]["status"] for n in snap["nodes"]} == {"decision:docs-adr-0001-a": "superseded", "decision:docs-adr-0002-new": "accepted"}
    assert [(e["source"], e["type"], e["target"]) for e in snap["edges"]] == [("decision:docs-adr-0002-new", "SUPERSEDES", "decision:docs-adr-0001-a")]


def madr_repo(tmp_path: Path, status: str) -> Path:
    d = tmp_path / "docs" / "decisions"
    d.mkdir(parents=True)
    (d / "0001-use-mysql.md").write_text(f"---\nstatus: {status}\ncode_ref: src/db/\n---\n# Use MySQL\n", encoding="utf-8")
    (d / "0002-use-postgres.md").write_text("---\nstatus: accepted\ncode_ref: src/db/\n---\n# Use Postgres\n", encoding="utf-8")
    return tmp_path


@pytest.mark.parametrize("status", ["superseded by [ADR-0002](0002-use-postgres.md)", "superseded by ADR-0002", "Superseded by 0002-use-postgres",
                                    "Superceded by ADR-0002", "SUPERCEDED BY [ADR-0002](0002-use-postgres.md)"])
def test_a_madr_front_matter_status_that_says_superseded_by_makes_the_edge(tmp_path, status):
    snap = init.build(madr_repo(tmp_path, status))
    assert by_id(snap)["decision:docs-decisions-0001-use-mysql"]["props"]["status"] == "superseded"
    assert [(e["source"], e["type"], e["target"]) for e in snap["edges"]] == [
        ("decision:docs-decisions-0002-use-postgres", "SUPERSEDES", "decision:docs-decisions-0001-use-mysql")]


def test_a_front_matter_superseded_by_that_matches_no_adr_is_reported(tmp_path):
    snap = init.build(madr_repo(tmp_path, "superseded by ADR-0009"))
    assert snap["edges"] == []
    assert snap["meta"]["problems"][-1] == {"file": "docs/decisions/0001-use-mysql.md", "action": "no edge",
                                            "reason": "it is superseded by ADR-0009, but no ADR file matches 'ADR-0009'"}


def two_adrs(tmp_path: Path, old: str, new: str) -> dict:
    d = tmp_path / "docs" / "adr"
    d.mkdir(parents=True)
    (d / "0001-old.md").write_text(old, encoding="utf-8")
    (d / "0002-new.md").write_text(new, encoding="utf-8")
    snap = init.build(tmp_path)
    return {"status": {n["id"]: n["props"].get("status") for n in snap["nodes"]},
            "edges": [(e["source"], e["type"], e["target"]) for e in snap["edges"]]}


OLD, NEW = "decision:docs-adr-0001-old", "decision:docs-adr-0002-new"
REPLACED = [(NEW, "SUPERSEDES", OLD)]


@pytest.mark.parametrize("lines", [
    "- **Status:** Accepted\n- **Date:** 2026-09-10\n- **Deciders:** Ana, Ben\n",
    "* **Status**: Accepted\n* **Date**: 2026-09-10\n* **Deciders**: Ana, Ben\n",
    "**Status:** Accepted\n**Date:** 2026-09-10\n**Deciders:** Ana, Ben\n",
    "__Status:__ Accepted\n__Date__: 2026-09-10\n- Deciders: Ana, Ben\n",
])
def test_a_status_written_as_a_bold_list_item_or_line_is_read_like_a_plain_one(tmp_path, lines):
    root = adr_repo(tmp_path, "code_ref: a.py\n", f"# A decision\n\n{lines}\n## Context\n\n- **Status:** proposed\n")
    [node] = init.build(root)["nodes"]
    assert {k: node["props"].get(k) for k in ("status", "date", "deciders")} == {"status": "accepted", "date": "2026-09-10", "deciders": ["Ana", "Ben"]}


@pytest.mark.parametrize("old", [
    "# Old\n\n- **Status:** superseded by [ADR-0002](0002-new.md)\n- **Date:** 2026-01-01\n",
    "# Old\n\n* **Status**: Superseded by ADR-0002\n",
    "# Old\n\n**Status:** Superceded by 0002-new\n",
    "# Old\n\n**Status:** Superseded\n",
])
def test_a_bold_status_that_says_superseded_by_makes_the_edge_from_the_new_adr(tmp_path, old):
    read = two_adrs(tmp_path, old, "---\nstatus: accepted\n---\n# New\n")
    assert read["status"] == {OLD: "superseded", NEW: "accepted"}
    assert read["edges"] == (REPLACED if "by" in old else [])


@pytest.mark.parametrize("old,new", [
    ("# Old\n\n## Status\n\nSuperceded by [2. New](0002-new.md)\n", "# New\n\n## Status\n\nAccepted\n"),
    ("# Old\n\n## Status\n\nAccepted\n", "# New\n\n## Status\n\nAccepted\n\nSupercedes [1. Old](0001-old.md)\n"),
    ("# Old\n\n## Status\n\nsuperceded by [2. New](0002-new.md)\n", "# New\n\n## Status\n\nAccepted\n\nSUPERCEDES [1. Old](0001-old.md)\n"),
    ("# Old\n\nStatus: Superceded by ADR-0002\n", "---\nstatus: accepted\nsupersedes: [ADR-0001]\n---\n# New\n"),
    ("---\nstatus: superceded by 0002-new\n---\n# Old\n", "# New\n\n**Status:** accepted\n"),
])
def test_superceded_and_supercedes_read_as_superseded_and_supersedes(tmp_path, old, new):
    read = two_adrs(tmp_path, old, new)
    assert read["status"][NEW] == "accepted"
    assert read["edges"] == REPLACED
    assert read["status"][OLD] == ("accepted" if "Accepted\n" in old else "superseded")


def test_a_lone_superceded_status_reads_as_superseded_and_makes_no_edge(tmp_path):
    read = two_adrs(tmp_path, "# Old\n\n## Status\n\nSuperceded\n", "---\nstatus: SUPERCEDED\n---\n# New\n")
    assert read == {"status": {OLD: "superseded", NEW: "superseded"}, "edges": []}


def test_front_matter_status_wins_over_a_bold_line_and_a_bold_line_over_the_status_section(tmp_path):
    read = two_adrs(tmp_path, "---\nstatus: accepted\n---\n# Old\n\n- **Status:** proposed\n",
                    "# New\n\n**Status:** accepted\n\n## Status\n\nRejected\n")
    assert read["status"] == {OLD: "accepted", NEW: "accepted"}


def impact_of(tmp_path: Path, snap: dict, *paths: str, repo: str | None = None) -> dict:
    box = tmp_path / "box"
    box.mkdir(exist_ok=True)
    return impact.run(co.load(init.dump(snap)), list(paths), repo=repo, root=box)


def test_impact_lists_a_superseded_decision_apart_from_the_ones_that_govern(tmp_path):
    report = impact_of(tmp_path, init.build(madr_repo(tmp_path, "superseded by ADR-0002")), "src/db/conn.py")
    [result] = report["impact"]
    assert [(g["id"], g["status"]) for g in result["governing"]] == [("decision:docs-decisions-0002-use-postgres", "accepted")]
    assert [(g["id"], g["status"], g["superseded_by"]) for g in result["superseded"]] == [
        ("decision:docs-decisions-0001-use-mysql", "superseded", ["decision:docs-decisions-0002-use-postgres"])]
    assert impact.render(report).split("\n") == [
        "src/db/conn.py: 1 node(s) within 3 hop(s), and 1 superseded decision(s)",
        "  [0] decision decision:docs-decisions-0002-use-postgres  code_ref src/db/ (encloses)  status accepted",
        "  superseded, listed for the record:",
        "  [0] decision decision:docs-decisions-0001-use-mysql  code_ref src/db/ (encloses)  status superseded"
        "  (superseded by decision:docs-decisions-0002-use-postgres)",
    ]


def test_a_decision_is_superseded_by_its_status_alone_or_by_an_edge_alone(tmp_path):
    snap = {"nodes": [
        {"id": "decision:a", "kind": "decision", "title": "A", "props": {"code_ref": "x.py", "status": "Superseded"}},
        {"id": "decision:b", "kind": "decision", "title": "B", "props": {"code_ref": "x.py"}},
        {"id": "decision:c", "kind": "decision", "title": "C", "props": {"code_ref": "x.py", "status": "accepted"}}],
        "edges": [{"source": "decision:c", "target": "decision:b", "type": "SUPERSEDES", "evidence": ""}]}
    [result] = impact_of(tmp_path, snap, "x.py")["impact"]
    assert [g["id"] for g in result["governing"]] == ["decision:c"]
    assert [(g["id"], g["superseded_by"]) for g in result["superseded"]] == [("decision:a", []), ("decision:b", ["decision:c"])]


def test_mermaid_and_html_show_the_superseded_decision_marked(tmp_path, capsys):
    out, _ = run_init(tmp_path, capsys)
    mermaid = run_view(capsys, out, "mermaid")
    assert 'decision:shop-docs-adr-0002-retry-payment-calls-three-times<br/>2. Retry payment calls three times<br/>superseded"' in mermaid
    assert "classDef superseded" in mermaid and '-->|"SUPERSEDES"|' in mermaid
    page = run_view(capsys, out, "html")
    assert "<h3>Superseded, listed for the record</h3>" in page
    assert '<li class="item decision superseded" style="border-style:dashed">' in page and "<dt>superseded by</dt>" in page


def run_view(capsys, snap: Path, fmt: str) -> str:
    capsys.readouterr()
    assert cli.main(["impact", str(snap), "src/payments/retry.py", "--repo", "Shop", "--format", fmt]) == 0
    return capsys.readouterr().out


def owners_repo(tmp_path: Path, codeowners: str, files: list[str]) -> Path:
    for f in files + [".github/CODEOWNERS"]:
        (tmp_path / f).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / f).write_text("x\n", encoding="utf-8")
    (tmp_path / ".github" / "CODEOWNERS").write_text(codeowners, encoding="utf-8")
    return tmp_path


def owner_of(snap: dict, path: str, tmp_path: Path) -> list[list[str]]:
    by = by_id(snap)
    [result] = impact_of(tmp_path, snap, path)["impact"]
    return [by[g["id"]]["props"]["owners"] for g in result["governing"] if g["kind"] == "concept"]


GITHUB_EXAMPLE = """*       @global-owner1 @global-owner2
*.js    @js-owner
*.go    docs@example.com
*.txt   @octo-org/octocats
/build/logs/ @doctocat
docs/*  docs@example.com
apps/ @octocat
/docs/ @doctocat
/scripts/ @doctocat @octocat
**/logs @octocat
/apps/ @octocat
/apps/github
"""
GITHUB_FILES = ["README.md", "app.js", "src/main.go", "notes.txt", "build/logs/app.log", "docs/getting-started.md",
                "docs/build-app/troubleshooting.md", "lib/apps/x.py", "scripts/run.sh", "deeply/nested/logs/a.log", "apps/github/a.py", "apps/web/b.py"]


@pytest.mark.parametrize("path,owners", [
    ("README.md", [["@global-owner1", "@global-owner2"]]),
    ("app.js", [["@js-owner"]]),
    ("src/main.go", [["docs@example.com"]]),
    ("notes.txt", [["@octo-org/octocats"]]),
    ("build/logs/app.log", [["@octocat"]]),
    ("docs/getting-started.md", [["@doctocat"]]),
    ("docs/build-app/troubleshooting.md", [["@doctocat"]]),
    ("lib/apps/x.py", [["@octocat"]]),
    ("scripts/run.sh", [["@doctocat", "@octocat"]]),
    ("deeply/nested/logs/a.log", [["@octocat"]]),
    ("apps/github/a.py", []),
    ("apps/web/b.py", [["@octocat"]]),
])
def test_codeowners_follows_github_matching_and_the_last_matching_line_wins(tmp_path, path, owners):
    snap = init.build(owners_repo(tmp_path, GITHUB_EXAMPLE, GITHUB_FILES))
    assert owner_of(snap, path, tmp_path) == owners


def test_docs_star_matches_direct_files_only_and_docs_double_star_everything_below(tmp_path):
    files = ["docs/a.md", "docs/b/c.md"]
    one = init.build(owners_repo(tmp_path / "one", "docs/* @x\n", files))
    two = init.build(owners_repo(tmp_path / "two", "docs/** @x\n", files))
    assert owned_by(one, "@x")["props"]["code_ref"] == ["docs/a.md"]
    assert owned_by(two, "@x")["props"]["code_ref"] == ["docs/"]


def test_paths_that_slug_alike_keep_their_own_owners_and_ids(tmp_path):
    snap = init.build(owners_repo(tmp_path, "/api/v1/ @a/b\n/api-v1/ @a-b\n", ["api/v1/x.py", "api/readme.md", "api-v1/y.py"]))
    concepts = {n["id"]: (n["props"]["owners"], n["props"]["code_ref"]) for n in snap["nodes"]}
    assert sorted(concepts.values()) == [(["@a-b"], ["api-v1/"]), (["@a/b"], ["api/v1/"])]
    assert len(concepts) == 2


def test_one_owner_set_covers_whole_directories_and_single_files_and_nothing_else(tmp_path):
    files = ["src/a.py", "src/b/c.py", "src/b/d.py", "src/x/e.py", "src/x/f/g.py", "top.md"]
    snap = init.build(owners_repo(tmp_path, "/src/ @a\n/src/b/c.py @b\n", files))
    assert owned_by(snap, "@a")["props"]["code_ref"] == ["src/a.py", "src/b/d.py", "src/x/"]
    assert owned_by(snap, "@b")["props"]["code_ref"] == ["src/b/c.py"]
    assert owner_of(snap, "top.md", tmp_path) == []


def test_owner_concepts_have_stable_ids_and_hash_the_codeowners_file(tmp_path):
    root = owners_repo(tmp_path, "/src/ @b @a\n", ["src/a.py"])
    first, second = init.build(root), init.build(root)
    node = owned_by(first, "@a", "@b")
    assert init.dump(first) == init.dump(second)
    assert node["props"]["content_hash"] == "sha256:" + hashlib.sha256((root / ".github" / "CODEOWNERS").read_bytes()).hexdigest()
    assert re.fullmatch(r"concept:codeowners-a-b-[0-9a-f]{12}", node["id"])


@pytest.mark.parametrize("pattern,reason", [
    ("\\#notes.md", "escaping with a backslash"),
    ("!src/", "negates with !"),
    ("src/[ab].py", "character ranges"),
    ("/", "names no path below the root"),
])
def test_a_pattern_github_does_not_support_is_reported_not_guessed(tmp_path, pattern, reason):
    snap = init.build(owners_repo(tmp_path, f"{pattern} @x\n", ["src/a.py"]))
    assert snap["nodes"] == []
    [problem] = snap["meta"]["problems"][-1:]
    assert problem["action"] == "skipped" and problem["reason"].startswith("line 1: ") and reason in problem["reason"]


def test_a_codeowners_link_to_a_file_outside_the_repository_is_refused(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "CODEOWNERS").write_text("* @leak\n", encoding="utf-8")
    root = tmp_path / "repo"
    (root / ".github").mkdir(parents=True)
    (root / "a.py").write_text("x\n", encoding="utf-8")
    (root / ".github" / "CODEOWNERS").symlink_to(outside / "CODEOWNERS")
    snap = init.build(root)
    assert snap["nodes"] == []
    assert {"file": ".github/CODEOWNERS", "reason": "it is a link to a file outside the repository", "action": "skipped"} in snap["meta"]["problems"]


def test_a_tree_with_too_many_files_is_reported_and_its_owners_not_read(tmp_path, monkeypatch):
    monkeypatch.setattr(init.owners, "MAX_FILES", 2)
    snap = init.build(owners_repo(tmp_path, "* @x\n", ["a.py", "b.py"]))
    assert snap["nodes"] == []
    assert snap["meta"]["problems"][-1]["reason"] == "the repository has 3 files, more than the 2 init resolves owners for; owners are not read"


def test_in_a_git_work_tree_ignored_files_are_not_owned(tmp_path):
    root = owners_repo(tmp_path, "* @x\n", ["src/a.py", "build/out.js", ".gitignore"])
    (root / ".gitignore").write_text("build/\n", encoding="utf-8")
    subprocess.run(["git", "init", "-q", str(root)], check=True)
    assert owned_by(init.build(root), "@x")["props"]["code_ref"] == [".github/", ".gitignore", "src/"]
    shutil.rmtree(root / ".git")
    assert owned_by(init.build(root), "@x")["props"]["code_ref"] == [".github/", ".gitignore", "build/", "src/"]


@pytest.mark.skipif(shutil.which("git") is None, reason="needs git")
@pytest.mark.parametrize("key, value", [
    ("core.fsmonitor", "touch {marker}; false"),
    ("core.hooksPath", "{hooks}"),
    ("core.pager", "touch {marker}; cat"),
])
def test_init_runs_no_command_the_repository_config_names(tmp_path, key, value):
    root = owners_repo(tmp_path / "repo", "* @x\n", ["src/a.py"])
    subprocess.run(["git", "init", "-q", str(root)], check=True)
    marker = tmp_path / "RAN"
    hooks = tmp_path / "hooks"
    hooks.mkdir()
    for name in ("post-index-change", "reference-transaction", "pre-auto-gc"):
        (hooks / name).write_text(f"#!/bin/sh\ntouch {marker}\n", encoding="utf-8")
        (hooks / name).chmod(0o755)
    subprocess.run(["git", "-C", str(root), "config", key, value.format(marker=marker, hooks=hooks)], check=True)
    subprocess.run(["git", "-C", str(root), "config", "core.untrackedCache", "true"], check=True)
    assert owned_by(init.build(root), "@x")["props"]["code_ref"] == [".github/", "src/"]
    assert not marker.exists()
