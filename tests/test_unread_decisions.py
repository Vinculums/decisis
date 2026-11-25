from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from test_action import FakeGitHub, environment, outputs, shop
from test_audit import no_network
from decisis import action, cli, compact, init

ROOT = Path(__file__).resolve().parents[1]
FIX = ROOT / "fixtures"
LOCK = FIX / "audit" / "demo-lockfile.json"
CACHE = FIX / "audit" / "osv-cache.json"
GOOD = "docs/adr/0001-ui-lives-in-src-shop-ui.md"
CUT_RULE = "docs/adr/0002-ui-does-not-import-db.md"
CUT_WAIVERS = "docs/adr/0003-payments-need-a-review.md"
ADRS = {
    GOOD: "---\ncode_ref: src/shop/ui/\n---\n# UI lives in src/shop/ui\n",
    CUT_RULE: '---\ncode_ref: src/shop/ui/\nrule: {"imports_forbidden": {"from": ["src/shop/ui/**"], "to": ["src/shop/db/**"]\n---\n'
              "# UI does not import the database\n",
    CUT_WAIVERS: '---\ncode_ref: src/payments/\nrule: {"review_required": {"paths": ["src/payments/**"], "reviewers": ["@shop/payments"]}}\n'
                 'waivers: [{"reason": "legacy", "expires": "2026-12-31", "approved_by": "@shop/security"\n---\n'
                 "# Payments need a payments review\n",
}
CUT = "inline JSON does not parse"
REASONS = {CUT_RULE: f"front matter line 3: {CUT}", CUT_WAIVERS: f"front matter line 4: {CUT}"}
CHANGED = ["src/shop/ui/view.py", "src/payments/charge.py"]


def with_adrs(root: Path) -> Path:
    for rel, body in ADRS.items():
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_text(body, encoding="utf-8")
    return root


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    shutil.copytree(FIX / "check" / "repo", root)
    shutil.copy(LOCK, root / "package-lock.json")
    return with_adrs(root)


def built(repo: Path, capsys) -> Path:
    out = repo.parent / "snapshot.json"
    capsys.readouterr()
    assert cli.main(["init", "--repo-dir", str(repo), "--repo", "Shop", "--out", str(out)]) == 0
    capsys.readouterr()
    return out


def run(capsys, *args: str) -> tuple[int, str]:
    capsys.readouterr()
    code = cli.main(list(args))
    return code, capsys.readouterr().out


def check_args(snap: Path, repo: Path, *extra: str) -> list[str]:
    return ["check", str(snap), "--repo-dir", str(repo), "--changed", *CHANGED, "--repo", "Shop", *extra]


def audit_args(snap: Path, repo: Path, *extra: str) -> list[str]:
    return ["audit", str(snap), str(repo / "package-lock.json"), "--repo", "Shop", "--osv-cache", str(CACHE), *extra]


def unread_of(entries: list[dict]) -> list[tuple[str, str]]:
    return [(u["file"], u["action"]) for u in entries]


EXPECTED = [(CUT_RULE, "skipped"), (CUT_WAIVERS, "skipped")]


def test_init_keeps_each_cut_short_rule_or_waivers_line_in_meta_problems_as_a_decision_file(repo):
    snap = init.build(repo, "Shop")
    assert [n["props"]["source_file"] for n in snap["nodes"] if n["kind"] == "decision"] == [GOOD]
    unread = [p for p in snap["meta"]["problems"] if p["action"] == "skipped"]
    assert [(p["file"], p["kind"]) for p in unread] == [(CUT_RULE, "decision"), (CUT_WAIVERS, "decision")]
    assert all(p["reason"].startswith(REASONS[p["file"]]) for p in unread)
    assert unread_of(init.unread_decisions(snap["meta"])) == EXPECTED


def test_check_lists_each_unread_decision_file_from_a_snapshot_passed_by_path(repo, capsys, no_network):
    snap = built(repo, capsys)
    code, out = run(capsys, *check_args(snap, repo))
    report = json.loads(out)
    assert code == 0 and unread_of(report["unread_decisions"]) == EXPECTED
    assert all(u["reason"].startswith(REASONS[u["file"]]) for u in report["unread_decisions"])
    assert report["violations"] == [] and report["unresolved"] == [] and report["summary"]["unresolved"] == 0


def test_check_fail_on_unresolved_counts_an_unread_decision_file(repo, capsys, no_network):
    snap = built(repo, capsys)
    assert run(capsys, *check_args(snap, repo, "--fail-on-unresolved"))[0] == 1
    whole = json.loads(snap.read_text(encoding="utf-8"))
    whole["meta"]["problems"] = [p for p in whole["meta"]["problems"] if p["action"] != "skipped"]
    snap.write_text(json.dumps(whole), encoding="utf-8")
    code, out = run(capsys, *check_args(snap, repo, "--fail-on-unresolved"))
    assert code == 0 and "unread_decisions" not in json.loads(out)


def test_check_text_mermaid_and_html_views_list_the_unread_decision_files(repo, capsys, no_network):
    snap = built(repo, capsys)
    text = run(capsys, *check_args(snap, repo, "--format", "text"))[1]
    assert "decision files not read, so their rules are not judged: 2" in text
    assert all(f"  {rel}: {why}" in text for rel, why in REASONS.items())
    mermaid = run(capsys, *check_args(snap, repo, "--format", "mermaid"))[1]
    assert f"{CUT_RULE}<br/>decision file not read: {REASONS[CUT_RULE]}" in mermaid and "classDef unread" in mermaid
    page = run(capsys, *check_args(snap, repo, "--format", "html"))[1]
    assert "<h2>Decision files not read, so their rules are not judged</h2>" in page
    assert f"<li><code>{CUT_WAIVERS}</code> (skipped): {REASONS[CUT_WAIVERS]}" in page


def test_audit_lists_the_unread_decision_files_in_the_report_and_its_views(repo, capsys, no_network):
    snap = built(repo, capsys)
    code, out = run(capsys, *audit_args(snap, repo))
    report = json.loads(out)
    assert code == 0 and unread_of(report["unread_decisions"]) == EXPECTED
    saved = repo.parent / "report.json"
    printed = json.loads(run(capsys, *audit_args(snap, repo, "--out", str(saved)))[1])
    assert printed["unread_decisions"] == 2 and json.loads(saved.read_text())["unread_decisions"] == report["unread_decisions"]
    mermaid = run(capsys, *audit_args(snap, repo, "--format", "mermaid"))[1]
    assert f"{CUT_RULE}<br/>decision file not read: {REASONS[CUT_RULE]}" in mermaid
    page = run(capsys, *audit_args(snap, repo, "--format", "html"))[1]
    assert "<h2>Decision files not read, so their rules are not judged</h2>" in page and f"<code>{CUT_RULE}</code>" in page


def test_a_snapshot_from_before_the_kind_field_still_lists_its_unread_adrs(repo):
    meta = init.build(repo, "Shop")["meta"]
    old = [{k: v for k, v in p.items() if k != "kind"} for p in meta["problems"]]
    old += [{"file": "docs/postmortems/2026-01-01-outage.md", "reason": "it is not UTF-8 text", "action": "skipped"},
            {"file": "notes/0009-elsewhere.md", "reason": "it is not UTF-8 text", "action": "skipped"},
            {"file": GOOD, "reason": "it names no code paths", "action": "kept without code paths"}]
    assert unread_of(init.unread_decisions({"problems": old})) == EXPECTED
    assert init.unread_decisions({}) == [] and init.unread_decisions({"problems": ["not a mapping", {"file": 3}]}) == []


def test_the_mcp_check_and_audit_replies_carry_unread_decisions_in_summary_and_full(repo, capsys, no_network):
    pytest.importorskip("mcp")
    pytest.importorskip("jsonschema")
    from decisis import serve
    tools = serve.load_tools(built(repo, capsys), repo, CACHE, False)
    replies = {}
    for name, args in (("check", {"changed": CHANGED}), ("audit", {"lockfile": "package-lock.json", "repo": "Shop"})):
        short = tools.call(name, args)
        full = tools.call(name, {**args, "detail": "full"})
        assert short["detail"] == "summary" and short["unread_decisions_count"] == 2
        assert unread_of(short["unread_decisions"]) == EXPECTED and unread_of(full["unread_decisions"]) == EXPECTED
        assert short["unread_decisions"] == full["unread_decisions"]
        replies[name] = full
    many = {**replies["check"], "unread_decisions": replies["check"]["unread_decisions"] * 6}
    short = compact.shape("check", many)
    assert short["unread_decisions_count"] == 12 and len(short["unread_decisions"]) == compact.FIRST


def test_the_action_comment_and_job_summary_list_them_and_fail_on_violation_does_not_count_them(tmp_path, no_network):
    root, base = shop(tmp_path)
    snap = tmp_path / "snapshot.json"
    snap.write_text(init.dump(init.build(with_adrs(root), "Shop")), encoding="utf-8")
    fake = FakeGitHub()
    env = environment(tmp_path, root, base, DECISIS_SNAPSHOT=str(snap), DECISIS_REPO="Shop", DECISIS_FAIL_ON_VIOLATION="true")
    assert action.main(env, fake) == 0
    (_, _, data), = fake.writes()
    summary = (tmp_path / "summary.md").read_text()
    assert summary == data["body"]
    assert "0 violation(s)" in summary and "2 decision file(s) not read**" in summary
    assert "#### Decision files not read (2)" in summary
    for rel, why in REASONS.items():
        assert f"- <code>{action.text(rel)}</code>: {action.text(why)}" in summary
    assert outputs(tmp_path)["violations"] == "0"
