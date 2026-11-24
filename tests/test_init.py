from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

import pytest

from decisis import checkout as co
from decisis import cli, impact, init

ROOT = Path(__file__).resolve().parents[1]
SHOP = ROOT / "fixtures" / "init" / "shop"
ADR = "decision:shop-docs-adr-"
MADR = "decision:shop-docs-decisions-"
PM = "record:shop-docs-postmortems-"
OWNERS = "concept:shop-github-codeowners-"


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


def test_init_then_impact_finds_the_decisions_each_file_is_governed_by(tmp_path, capsys):
    out, printed = run_init(tmp_path, capsys)
    assert printed["nodes"] == 11 and printed["edges"] == 4
    graph = co.load(out.read_text(encoding="utf-8"))
    paths = ["src/payments/retry.py", "src/payments/gateway.py", "src/payments/refund.py", "src/logging/redact.py", "package-lock.json"]
    box = tmp_path / "box"
    box.mkdir()
    report = impact.run(graph, paths, repo="Shop", root=box)
    decisions = [sorted(i for _, i in governing(report, n) if i.startswith("decision:")) for n in range(len(paths))]
    assert decisions == [
        [f"{ADR}0002-retry-payment-calls-three-times", f"{ADR}0003-retry-payment-calls-once"],
        [f"{ADR}0003-retry-payment-calls-once"],
        [],
        [f"{MADR}0011-card-numbers-never-reach-logs"],
        [f"{MADR}0010-no-high-advisories-in-shipped-dependencies"],
    ]
    assert (1, f"{PM}2026-05-02-card-number-in-logs") in governing(report, 3)
    assert governing(report, 2) == [(0, f"{OWNERS}src-payments")]


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
        if "source_line" in props:
            built_from = source.read_text(encoding="utf-8").split("\n")[props["source_line"] - 1].strip().encode("utf-8")
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


def test_a_codeowners_entry_is_a_concept_with_its_path_and_owners():
    nodes = by_id(snapshot())
    logging = nodes[f"{OWNERS}src-logging"]
    assert logging["kind"] == "concept"
    assert logging["props"]["code_ref"] == ["Shop:src/logging/"] and logging["props"]["owners"] == ["@shop/platform", "@ana"]
    assert nodes[f"{OWNERS}src-payments"]["props"]["owners"] == ["@shop/payments-core"]


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
        (".github/CODEOWNERS", "skipped", "line 2: the pattern * uses wildcards, which a code path cannot express"),
        (".github/CODEOWNERS", "skipped", "line 3: line 7 names the same path, and the later line applies"),
        (".github/CODEOWNERS", "skipped", "line 5: the pattern docs/ matches at any depth; write /docs/ to name one path from the root"),
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
