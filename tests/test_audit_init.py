from __future__ import annotations

import json
import re
import shutil
from pathlib import Path

import pytest

from test_action import FakeGitHub, osv_cache, outputs
from test_audit import advisories, lock, no_network
from test_base_decisions import env_for, repository, summary
from decisis import action, audit, cli, compact, init, render
from decisis import checkout as co

ROOT = Path(__file__).resolve().parents[1]
FIX = ROOT / "fixtures"
SHOP = FIX / "init" / "shop"
LOCK = FIX / "audit" / "demo-lockfile.json"
CACHE = FIX / "audit" / "osv-cache.json"
ADR_0010 = "decision:shop-docs-decisions-0010-no-high-advisories-in-shipped-dependencies"
SHIPPED = {("pkg:npm/lodash@4.17.15", a) for a in ("adv:GHSA-r5fr-rjxr-66jc", "adv:GHSA-p6mc-m468-83gw", "adv:GHSA-35jh-r3h4-6jhm")}
RULE = {"advisory_severity_at_least": "HIGH", "dependencies": "shipped"}
README = (ROOT / "README.md").read_text(encoding="utf-8")


def snapshot(repo: str | None = "Shop", root: Path = SHOP) -> dict:
    return json.loads(init.dump(init.build(root, repo)))


def audited(snap: dict, repo: str = "Shop") -> dict:
    return audit.run(co.load(json.dumps(snap)), lock(), repo, advisories=advisories())


def violated(report: dict, decision: str = ADR_0010) -> set[tuple[str, str]]:
    return {(f["package"], f["advisory"]) for f in report["findings"]
            for p in f["policies"] if p["decision"] == decision and p["verdict"] == "violated"}


def node(snap: dict, nid: str) -> dict:
    return next(n for n in snap["nodes"] if n["id"] == nid)


def run(capsys, *args: str) -> tuple[int, str]:
    capsys.readouterr()
    code = cli.main(list(args))
    return code, capsys.readouterr().out


def test_an_init_snapshot_governs_the_repository_it_read_and_judges_its_dependency_rule():
    report = audited(snapshot())
    assert report["governing"] == [{"decision": ADR_0010, "title": "No high advisories in shipped dependencies",
                                    "via": "docs/decisions/0010-no-high-advisories-in-shipped-dependencies.md", "link": audit.RECORDS}]
    assert report["violations"] == 3 and violated(report) == SHIPPED
    assert "not_governing" not in report
    assert report["meta"]["snapshot_repo"] == "Shop" and report["meta"]["recorded_links"] == 1
    dev = [f for f in report["findings"] if f["dev_only"]]
    assert dev and all(p["verdict"] == "not_violated" for f in dev for p in f["policies"])


def test_the_repository_name_is_compared_without_case():
    assert violated(audited(snapshot(), "shop")) == SHIPPED


def test_an_init_snapshot_with_no_repository_name_governs_the_repository_audit_names():
    snap = snapshot(None)
    unnamed = ADR_0010.replace("decision:shop-", "decision:")
    assert snap["meta"]["repo"] is None and node(snap, unnamed)
    for repo in ("Shop", "shop", "AnyName"):
        report = audited(snap, repo)
        assert violated(report, unnamed) == SHIPPED and report["meta"]["snapshot_repo"] is None
        assert f"which --repo names {repo}" in audit.recorded_links(co.load(json.dumps(snap)), repo)[0]["evidence"]


@pytest.mark.parametrize("ref", [None, "Shop:src/payments/", ["Shop:src/payments/"], "src/logging/", ["Other:lib/"]],
                         ids=["none", "string", "list", "unprefixed", "another-repository"])
def test_a_code_ref_neither_links_nor_narrows_a_dependency_rule_of_an_init_snapshot(ref):
    snap = snapshot()
    props = node(snap, ADR_0010)["props"]
    props.pop("subject_path", None)
    if ref is not None:
        props["code_ref"] = ref
    report = audited(snap)
    assert [g["decision"] for g in report["governing"]] == [ADR_0010]
    assert violated(report) == SHIPPED


def test_an_init_decision_with_only_a_check_rule_or_no_rule_does_not_govern_the_audit():
    report = audited(snapshot())
    ids = {g["decision"] for g in report["governing"]}
    snap = snapshot()
    others = [n["id"] for n in snap["nodes"] if n["kind"] == "decision" and n["id"] != ADR_0010]
    assert others and not ids & set(others)
    node(snap, others[0])["props"]["rule"] = {"review_required": {"paths": ["src/**"], "reviewers": ["@shop/team"]}}
    again = audited(snap)
    assert [g["decision"] for g in again["governing"]] == [ADR_0010] and "not_governing" not in again


def test_an_init_decision_whose_rule_cannot_be_read_governs_and_lists_the_problem():
    snap = snapshot()
    node(snap, ADR_0010)["props"]["rule"] = {"advisory_severity_at_least": "SEVERE"}
    report = audited(snap)
    assert [g["decision"] for g in report["governing"]] == [ADR_0010]
    assert [p["decision"] for p in report["rule_problems"]] == [ADR_0010]


def test_another_repositorys_init_snapshot_is_listed_as_not_governing_with_the_reason():
    report = audited(snapshot(), "Other")
    assert report["governing"] == [] and report["violations"] == 0
    assert report["not_governing"] == [{"decision": ADR_0010, "title": "No high advisories in shipped dependencies",
                                        "reason": "decisis init read it from the repository Shop, and this audit is of Other"}]
    assert report["meta"]["recorded_links"] == 0


def test_a_superseded_init_decision_is_not_judged_and_says_why():
    snap = snapshot()
    newer = next(n for n in snap["nodes"] if n["id"].endswith("0011-card-numbers-never-reach-logs"))
    snap["edges"].append({"source": newer["id"], "target": ADR_0010, "type": "SUPERSEDES", "evidence": "test"})
    snap["meta"]["edges"] += 1
    report = audited(snap)
    assert report["governing"] == [] and report["violations"] == 0
    assert report["not_governing"][0]["decision"] == ADR_0010
    assert report["not_governing"][0]["reason"] == f"it is superseded by {newer['id']}, and a superseded decision is not judged"


def test_a_hand_written_decision_with_a_rule_and_no_path_to_the_repository_is_listed_as_not_governing():
    snap = json.loads((FIX / "audit" / "vinc.json").read_text())
    snap["nodes"].append({"id": "decision:loose", "kind": "decision", "title": "Loose", "props": {"rule": RULE, "code_ref": "Demo:src/"}})
    report = audited(snap, "Demo")
    before = audited(json.loads((FIX / "audit" / "vinc.json").read_text()), "Demo")
    assert report["governing"] == before["governing"] and report["findings"] == before["findings"]
    assert "not_governing" not in before and "recorded_links" not in before["meta"]
    assert report["not_governing"] == [{"decision": "decision:loose", "title": "Loose",
                                        "reason": "nothing links it to repo:Demo: the snapshot does not come from decisis init, "
                                                  "and no edge runs repo:Demo -DESCRIBED_BY-> a node it is ABOUT"}]


def test_a_hand_written_snapshot_keeps_linking_through_about_and_described_by():
    report = audited(json.loads((FIX / "audit" / "vinc.json").read_text()), "Demo")
    assert {g["via"] for g in report["governing"]} == {"concept:demo-app"} and all("link" not in g for g in report["governing"])


def test_not_governing_shows_in_the_cli_summary_the_views_and_the_mcp_reply(tmp_path, capsys, no_network):
    snap = tmp_path / "shop.json"
    snap.write_text(init.dump(init.build(SHOP, "Shop")), encoding="utf-8")
    args = ["audit", str(snap), str(LOCK), "--repo", "Other", "--osv-cache", str(CACHE)]
    code, out = run(capsys, *args, "--out", str(tmp_path / "report.json"))
    assert code == 0 and json.loads(out)["not_governing"] == 1
    report = json.loads((tmp_path / "report.json").read_text())
    mermaid = run(capsys, *args, "--format", "mermaid")[1]
    assert f"{ADR_0010}<br/>No high advisories in shipped dependencies<br/>governs nothing here: decisis init read it" in mermaid
    page = run(capsys, *args, "--format", "html")[1]
    assert "<h2>Decisions that govern nothing in this audit, so their rules are not judged</h2>" in page
    assert f"<code>{ADR_0010}</code>" in page and "and this audit is of Other" in page
    short = compact.shape("audit", report)
    assert short["not_governing_count"] == 1 and short["not_governing"] == report["not_governing"]


def test_the_mcp_audit_of_an_init_snapshot_judges_the_rule_and_lists_what_governs_nothing(tmp_path, no_network):
    pytest.importorskip("mcp")
    pytest.importorskip("jsonschema")
    from decisis import serve
    snap = tmp_path / "shop.json"
    snap.write_text(init.dump(init.build(SHOP, "Shop")), encoding="utf-8")
    shutil.copy(LOCK, tmp_path / "package-lock.json")
    tools = serve.load_tools(snap, tmp_path, CACHE, False)
    judged = tools.call("audit", {"lockfile": "package-lock.json", "repo": "Shop"})
    assert judged["violations"] == 3 and "not_governing" not in judged
    idle = tools.call("audit", {"lockfile": "package-lock.json", "repo": "Other"})
    assert idle["violations"] == 0 and idle["not_governing_count"] == 1 and idle["not_governing"][0]["decision"] == ADR_0010


def test_the_graph_draws_the_recorded_link_from_the_repository_to_the_decision():
    g = render.audit_graph(audited(snapshot()))
    assert ("repo:Shop", audit.RECORDS, ADR_0010) in g.edges
    assert not any(label == "ABOUT" for _, label, _ in g.edges)


def test_the_readme_init_then_audit_example_prints_what_the_readme_shows(tmp_path, capsys, monkeypatch, no_network):
    shown = re.search(r"\$ decisis audit (shop\.json .*?)\n(.*?)```", README, re.S)
    assert "decisis init --repo-dir fixtures/init/shop --repo Shop --out shop.json" in README
    monkeypatch.chdir(tmp_path)
    shutil.copytree(FIX, tmp_path / "fixtures")
    assert cli.main(["init", "--repo-dir", "fixtures/init/shop", "--repo", "Shop", "--out", "shop.json"]) == 0
    code, out = run(capsys, "audit", *shown.group(1).split())
    assert code == 0 and json.loads(out) == json.loads(shown.group(2))
    assert violated(json.loads((tmp_path / "report.json").read_text())) == SHIPPED


def adr_0010() -> str:
    return (SHOP / "docs" / "decisions" / "0010-no-high-advisories-in-shipped-dependencies.md").read_text()


ACTION_ADR = "docs/decisions/0010-no-high-advisories-in-shipped-dependencies.md"


@pytest.mark.parametrize("repo", [{}, {"DECISIS_REPO": "Shop"}], ids=["repository-name", "repo-input"])
def test_the_action_with_init_and_an_inventory_judges_the_base_commits_dependency_rule(tmp_path, no_network, repo):
    root, base = repository(tmp_path, {ACTION_ADR: adr_0010(), "package-lock.json": LOCK.read_text()}, {"src/app.js": "x\n"})
    env = env_for(tmp_path, root, base, DECISIS_INVENTORY="auto", DECISIS_OSV_CACHE=str(osv_cache(tmp_path)),
                  DECISIS_FAIL_ON_VIOLATION="true", **repo)
    assert action.main(env, FakeGitHub()) == 1
    out = summary(tmp_path)
    assert outputs(tmp_path)["violations"] == "3"
    assert f"{action.text('3 violation(s) of a decision.')}" in out and "built with decisis init from the base commit" in out
    assert "govern nothing in this audit" not in out


def test_the_action_does_not_judge_a_dependency_rule_the_pull_request_adds(tmp_path, no_network):
    root, base = repository(tmp_path, {"package-lock.json": LOCK.read_text(), "docs/decisions/0001-start.md": "# Start\n"},
                            {ACTION_ADR: adr_0010()})
    env = env_for(tmp_path, root, base, DECISIS_INVENTORY="auto", DECISIS_OSV_CACHE=str(osv_cache(tmp_path)))
    assert action.main(env, FakeGitHub()) == 0
    assert outputs(tmp_path)["violations"] == "0" and "take effect once merged" in summary(tmp_path)


def test_the_action_comment_lists_a_decision_that_governs_nothing_in_the_audit(tmp_path, no_network):
    root, base = repository(tmp_path, {"decisions.json": init.dump(init.build(SHOP, "Shop")), "package-lock.json": LOCK.read_text()},
                            {"src/app.js": "x\n"})
    env = env_for(tmp_path, root, base, str(root / "decisions.json"), DECISIS_REPO="Other", DECISIS_INVENTORY="auto",
                  DECISIS_OSV_CACHE=str(osv_cache(tmp_path)))
    assert action.main(env, FakeGitHub()) == 0
    out = summary(tmp_path)
    assert "#### Decisions that govern nothing in this audit (1)" in out
    assert f"- {action.code(ADR_0010)}: {action.text('decisis init read it from the repository Shop, and this audit is of Other')}" in out


def test_propose_rederives_the_records_of_an_init_snapshot_audit_and_the_checker_accepts_them(tmp_path, capsys, no_network):
    snap = tmp_path / "shop.json"
    snap.write_text(init.dump(init.build(SHOP, "Shop")), encoding="utf-8")
    report = tmp_path / "report.json"
    code, _ = run(capsys, "audit", str(snap), str(LOCK), "--repo", "Shop", "--osv-cache", str(CACHE), "--out", str(report))
    assert code == 0
    code, out = run(capsys, "propose", str(report), str(snap), str(LOCK), "--repo", "Shop", "--space", "demo-space",
                    "--osv-cache", str(CACHE), "--out", str(tmp_path / "plan.json"))
    plan = json.loads((tmp_path / "plan.json").read_text())
    assert code == 0 and plan["held"] == [] and " 0 failed." in out
    breaking = [n for n in plan["nodes"] if ADR_0010 in n["props"]["violates"]]
    assert breaking and {n["props"]["scope"] for n in breaking} == {"shipped"}
    assert {(e["from"], e["to"]) for e in plan["edges"] if e["evidence"].startswith("violated:")} == {(n["id"], ADR_0010) for n in breaking}
