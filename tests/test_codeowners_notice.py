from __future__ import annotations

import json
from pathlib import Path

import pytest

from test_action import FakeGitHub, outputs, pull
from test_audit import no_network
from test_base_decisions import ADR, adr, env_for, repository, summary, write
from decisis import action, check, cli, compact, init
from decisis import checkout as co

OWNERS = ".github/CODEOWNERS"
CODEOWNERS = "* @shop/platform\n/src/payments/ @shop/payments\n"
FILES = {OWNERS: CODEOWNERS, "src/payments/charge.py": "A = 1\n", "src/web/page.py": "B = 1\n", "src/web/home.py": "C = 1\n"}
CHANGED = ["src/payments/charge.py", "src/web/page.py", "src/web/home.py"]
SAYS = "decisis does not enforce CODEOWNERS"


def snapshot_of(tmp_path: Path, files: dict[str, str]) -> tuple[Path, Path]:
    root = tmp_path / "shop"
    root.mkdir()
    write(root, files)
    snap = tmp_path / "snapshot.json"
    snap.write_text(init.dump(init.build(root, "Shop")), encoding="utf-8")
    return root, snap


def without_owners(snap: Path, tmp_path: Path) -> Path:
    data = json.loads(snap.read_text(encoding="utf-8"))
    data["nodes"] = [n for n in data["nodes"] if "owners" not in (n.get("props") or {})]
    data["meta"]["nodes"] = len(data["nodes"])
    out = tmp_path / "plain.json"
    out.write_text(json.dumps(data), encoding="utf-8")
    return out


def run(capsys, snap: Path, root: Path, changed: list[str], *args: str) -> tuple[int, str]:
    capsys.readouterr()
    code = cli.main(["check", str(snap), "--repo-dir", str(root), "--changed", *changed, *args])
    return code, capsys.readouterr().out


def report(capsys, snap: Path, root: Path, changed: list[str] = CHANGED, *args: str) -> tuple[int, dict]:
    code, out = run(capsys, snap, root, changed, *args)
    return code, json.loads(out)


def listed(r: dict) -> list[str]:
    return [e["file"] for e in r.get("codeowners", {}).get("files", [])]


def test_a_codeowners_only_repository_lists_the_owners_as_information_and_exits_0(tmp_path, capsys, no_network):
    root, snap = snapshot_of(tmp_path, FILES)
    code, r = report(capsys, snap, root)
    assert code == 0 and r["violations"] == [] and r["reviewers"] == []
    owned = r["codeowners"]
    assert owned["enforced"] is False
    assert [(e["file"], e["owners"]) for e in owned["files"]] == [
        ("src/payments/charge.py", ["@shop/payments"]), ("src/web/home.py", ["@shop/platform"]), ("src/web/page.py", ["@shop/platform"])]
    assert all(e["concept"].startswith("concept:shop-codeowners-") for e in owned["files"])
    assert SAYS in owned["note"] and "Require review from Code Owners" in owned["note"] and "review_required" in owned["note"]


def test_the_text_view_lists_each_file_with_its_owners_and_says_the_owners_are_not_enforced(tmp_path, capsys, no_network):
    root, snap = snapshot_of(tmp_path, FILES)
    code, out = run(capsys, snap, root, CHANGED, "--format", "text")
    lines = out.splitlines()
    assert code == 0 and "violations: 0" in lines
    start = lines.index("CODEOWNERS owners of changed files, shown and not enforced: 3")
    assert lines[start + 1:start + 4] == ["  src/payments/charge.py  @shop/payments", "  src/web/home.py  @shop/platform",
                                          "  src/web/page.py  @shop/platform"]
    assert lines[start + 4:] == [check.CODEOWNERS_NOTE] and SAYS in check.CODEOWNERS_NOTE


def test_nothing_is_printed_when_no_changed_file_has_owners_to_show(tmp_path, capsys, no_network):
    root, snap = snapshot_of(tmp_path, {**FILES, "tools/run.sh": "echo\n", OWNERS: "/src/payments/ @shop/payments\n"})
    code, out = run(capsys, snap, root, ["tools/run.sh"], "--format", "text")
    assert code == 0 and "CODEOWNERS" not in out
    assert "codeowners" not in report(capsys, snap, root, ["tools/run.sh"])[1]
    other = tmp_path / "other.json"
    other.write_text(json.dumps({"nodes": [{"id": "concept:x", "kind": "concept", "props": {"code_ref": ["src/"]}}], "edges": []}))
    assert "codeowners" not in report(capsys, other, root)[1]


def test_a_file_a_review_required_rule_covers_is_not_listed_and_the_rule_gives_the_verdict(tmp_path, capsys, no_network):
    root, snap = snapshot_of(tmp_path, {**FILES, ADR: adr()})
    code, r = report(capsys, snap, root, CHANGED, "--reviewers", "@bob")
    assert code == 1 and [v["file"] for v in r["violations"]] == ["src/payments/charge.py"]
    assert listed(r) == ["src/web/home.py", "src/web/page.py"]
    code, r = report(capsys, snap, root, CHANGED, "--reviewers", "@shop/payments")
    assert code == 0 and r["violations"] == [] and listed(r) == ["src/web/home.py", "src/web/page.py"]
    code, out = run(capsys, snap, root, ["src/payments/charge.py"], "--reviewers", "@shop/payments", "--format", "text")
    assert code == 0 and "CODEOWNERS" not in out


def test_a_rule_that_only_a_superseded_decision_holds_does_not_stop_the_listing(tmp_path, capsys, no_network):
    older = adr().replace("status: accepted", "status: superseded by ADR-0002")
    root, snap = snapshot_of(tmp_path, {**FILES, ADR: older, "docs/adr/0002-payments.md": adr(rule=False)})
    code, r = report(capsys, snap, root, CHANGED, "--reviewers", "@bob")
    assert code == 0 and r["violations"] == [] and "src/payments/charge.py" in listed(r)


def test_the_listing_changes_no_verdict_exit_code_or_sarif_result(tmp_path, capsys, no_network):
    root, snap = snapshot_of(tmp_path, {**FILES, ADR: adr()})
    plain = without_owners(snap, tmp_path)
    for args in (["--reviewers", "@bob"], ["--reviewers", "@shop/payments"], []):
        with_code, with_owners = report(capsys, snap, root, CHANGED, *args)
        without_code, without = report(capsys, plain, root, CHANGED, *args)
        assert with_code == without_code and "codeowners" in with_owners and "codeowners" not in without
        for key in ("violations", "unresolved", "waived", "summary", "rules", "imports", "governing", "superseded", "changed", "reviewers"):
            assert with_owners[key] == without[key], key
        _, sarif_with = run(capsys, snap, root, CHANGED, "--format", "sarif", *args)
        _, sarif_without = run(capsys, plain, root, CHANGED, "--format", "sarif", *args)
        assert sarif_with == sarif_without and "CODEOWNERS" not in sarif_with


def test_the_html_view_has_its_own_section_for_the_owners(tmp_path, capsys, no_network):
    root, snap = snapshot_of(tmp_path, FILES)
    _, page = run(capsys, snap, root, CHANGED, "--format", "html")
    assert "<h2>CODEOWNERS owners of changed files, shown and not enforced</h2>" in page and SAYS in page
    assert "<td><code>src/payments/charge.py</code></td><td><code>@shop/payments</code></td>" in page
    _, page = run(capsys, snap, root, ["tools/run.sh"], "--format", "html")
    assert "CODEOWNERS owners" not in page


def outcome(tmp_path: Path, changed: list[str] = CHANGED) -> action.Outcome:
    root, snap = snapshot_of(tmp_path, FILES)
    graph = co.load(snap.read_text(encoding="utf-8"))
    return action.Outcome(check.run(graph, changed, root, []), pull(), [], "0.4.2", "snap.json")


def comment(tmp_path: Path, rows: int = 50, changed: list[str] = CHANGED) -> str:
    return action.compose(outcome(tmp_path, changed), rows, False)


def test_the_comment_has_a_section_with_each_file_its_owners_and_the_note(tmp_path, no_network):
    body = comment(tmp_path)
    assert "#### CODEOWNERS owners of changed files, not enforced (3)" in body
    assert action.text(check.CODEOWNERS_NOTE) in body
    assert "| File | Owners |" in body
    assert f"| {action.code('src/payments/charge.py')} | {action.code('@shop/payments')} |" in body
    assert f"| {action.code('src/web/page.py')} | {action.code('@shop/platform')} |" in body
    assert "<code>@⁠shop/platform</code>" in body


def test_the_comment_cuts_the_owner_list_to_the_rows_it_may_show(tmp_path, no_network):
    o = outcome(tmp_path)
    body = action.compose(o, 1, False)
    assert "(3)" in body and body.count("| <code>src/") == 1 and "2 more files not shown here" in body
    assert action.text(check.CODEOWNERS_NOTE) in action.compose(o, 0, False)


def test_the_comment_has_no_owner_section_when_there_is_nothing_to_list(tmp_path, no_network):
    assert "CODEOWNERS" not in comment(tmp_path, changed=["tools/run.sh"])


def pull_request(tmp_path: Path, base: dict[str, str]) -> tuple[Path, str]:
    return repository(tmp_path, {OWNERS: CODEOWNERS, "src/payments/charge.py": "A = 1\n", "src/web/page.py": "B = 1\n", **base},
                      {"src/payments/charge.py": "A = 2\n", "src/web/page.py": "B = 2\n"})


def test_the_comment_of_a_repository_with_only_codeowners_lists_the_owners_though_no_decision_exists(tmp_path, no_network):
    root, base = pull_request(tmp_path, {})
    fake = FakeGitHub()
    env = env_for(tmp_path, root, base, DECISIS_FAIL_ON_VIOLATION="true", DECISIS_FAIL_ON_UNRESOLVED="true", DECISIS_SARIF="true")
    env["GITHUB_WORKSPACE"] = str(root)
    assert action.main(env, fake) == 0
    out = summary(tmp_path)
    assert "No decisions exist on the base commit" in out
    assert "#### CODEOWNERS owners of changed files, not enforced (2)" in out
    assert f"| {action.code('src/payments/charge.py')} | {action.code('@shop/payments')} |" in out
    assert f"| {action.code('src/web/page.py')} | {action.code('@shop/platform')} |" in out
    assert action.text(check.CODEOWNERS_NOTE) in out
    assert outputs(tmp_path)["violations"] == "0" and outputs(tmp_path)["unresolved"] == "0"
    (_, _, data), = fake.writes()
    assert data["body"] == out
    log = json.loads((root / "decisis.sarif").read_text(encoding="utf-8"))
    assert log["runs"][0]["results"] == [] and "CODEOWNERS" not in json.dumps(log)


def test_the_comment_with_decisions_lists_only_the_files_no_review_rule_covers(tmp_path, no_network):
    root, base = pull_request(tmp_path, {ADR: adr()})
    assert action.main(env_for(tmp_path, root, base), FakeGitHub()) == 0
    out = summary(tmp_path)
    assert "#### Violations (1)" in out and "#### CODEOWNERS owners of changed files, not enforced (1)" in out
    assert f"| {action.code('src/web/page.py')} | {action.code('@shop/platform')} |" in out
    assert action.code("@shop/payments") not in out.split("#### CODEOWNERS owners")[1]


def owned_report(tmp_path: Path, count: int = 60) -> tuple[Path, Path, list[str], dict]:
    names = [f"src/web/page_{i:02}.py" for i in range(count)]
    root, snap = snapshot_of(tmp_path, {OWNERS: CODEOWNERS, **{n: "A = 1\n" for n in names}})
    return root, snap, names, check.run(co.load(snap.read_text(encoding="utf-8")), names, root, [])


def test_the_mcp_summary_keeps_the_listing_with_its_count_and_the_first_ten_files(tmp_path, no_network):
    _, _, names, full = owned_report(tmp_path)
    short = compact.shape("check", full)
    owned = short["codeowners"]
    assert owned["enforced"] is False and owned["note"] == check.CODEOWNERS_NOTE and owned["files_count"] == 60
    assert [e["file"] for e in owned["files"]] == names[:10]
    assert short["violations_count"] == 0 and short["summary"] == full["summary"]
    assert len(json.dumps(owned)) < 2500
    assert compact.shape("check", full, "full") is full


def test_the_mcp_summary_has_no_listing_when_the_report_has_none(tmp_path, capsys, no_network):
    root, snap = snapshot_of(tmp_path, FILES)
    plain = check.run(co.load(snap.read_text(encoding="utf-8")), ["tools/run.sh"], root, [])
    assert "codeowners" not in plain and "codeowners" not in compact.shape("check", plain)


def test_the_mcp_check_tool_returns_the_listing_in_summary_and_full_and_its_description_says_so(tmp_path, no_network):
    pytest.importorskip("mcp")
    pytest.importorskip("jsonschema")
    from decisis import serve
    root, snap, names, _ = owned_report(tmp_path)
    t = serve.load_tools(snap, root)
    short, full = t.call("check", {"changed": names}), t.call("check", {"changed": names, "detail": "full"})
    assert len(full["codeowners"]["files"]) == 60 and short["codeowners"]["files_count"] == 60 and len(short["codeowners"]["files"]) == 10
    assert SAYS in serve.DESCRIPTIONS["check"] and "codeowners" in serve.DESCRIPTIONS["check"]


def test_a_file_name_that_is_not_utf8_reaches_the_comment_as_escaped_text(tmp_path, no_network):
    root, snap = snapshot_of(tmp_path, FILES)
    graph = co.load(snap.read_text(encoding="utf-8"))
    odd = "src/web/caf\udce9.py"
    held = check.codeowners_notice(graph, [odd])
    assert held["codeowners"]["files"][0]["file"] == "src/web/caf\\xe9.py"
    o = action.Outcome({"changed": [odd], **held}, pull(), [], "0.4.2", "snap.json", nothing="No decisions yet.")
    body = action.body(o)
    body.encode("utf-8")
    assert "#### CODEOWNERS owners of changed files, not enforced (1)" in body
