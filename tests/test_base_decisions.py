from __future__ import annotations

import json
import shutil
import stat
import subprocess
from pathlib import Path

import pytest
import yaml

from test_action import DEMO_LOCK, HOSTILE, HOSTILE_PATH, FakeGitHub, environment, git, hostile_outcome, osv_cache, outputs
from test_audit import no_network
from decisis import action, committed, init

ROOT = Path(__file__).resolve().parents[1]
DAY = "2026-11-25"
ADR = "docs/adr/0001-payments.md"
DECISION = "decision:docs-adr-0001-payments"
RULE = {"review_required": {"paths": ["src/payments/**"], "reviewers": ["@shop/payments"]}}
SELF_WAIVER = {"reason": "waived by the change itself", "expires": "2099-12-31", "approved_by": "@mallory", "path": "src/payments/**"}


def adr(waivers=None, rule=True, statement="Payments are reviewed by the payments team.") -> str:
    lines = ["---", "title: Payment changes need a payments review", "status: accepted", "code_ref: [src/payments/]"]
    if rule:
        lines.append("rule: " + json.dumps(RULE))
    if waivers:
        lines.append("waivers: " + json.dumps(waivers))
    return "\n".join(lines + ["---", "", "# Payment changes need a payments review", "", "## Decision", "", statement, ""])


def snapshot(waivers=None) -> str:
    props = {"rule": RULE, **({"waivers": waivers} if waivers else {})}
    node = {"id": "decision:payments-review", "kind": "decision", "title": "Payment changes need a payments review", "props": props}
    return json.dumps({"meta": {"space": "synthetic"}, "nodes": [node], "edges": []})


def write(root: Path, files: dict[str, str | None]) -> None:
    for name, body in files.items():
        path = root / name
        if body is None:
            if path.is_symlink() or path.is_file():
                path.unlink()
            elif path.exists():
                shutil.rmtree(path)
            continue
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body)


def repository(tmp_path: Path, base: dict[str, str | None], head: dict[str, str | None]) -> tuple[Path, str]:
    root = tmp_path / "shop"
    root.mkdir()
    git(root, "init", "-q", "-b", "main")
    write(root, {"README.md": "shop\n", **base})
    git(root, "add", "-A")
    git(root, "commit", "-q", "-m", "base")
    sha = subprocess.run(["git", "-C", str(root), "rev-parse", "HEAD"], capture_output=True, text=True, check=True).stdout.strip()
    write(root, head)
    git(root, "add", "-A")
    git(root, "commit", "-q", "-m", "head")
    return root, sha


def env_for(tmp_path: Path, root: Path, base: str, snapshot_path: str | None = None, **extra) -> dict:
    env = environment(tmp_path, root, base, DECISIS_TODAY=DAY, **extra)
    if "DECISIS_DECISIONS_FROM" not in extra:
        del env["DECISIS_DECISIONS_FROM"]
    if snapshot_path is None:
        del env["DECISIS_SNAPSHOT"]
        env["DECISIS_INIT"] = "true"
    else:
        env["DECISIS_SNAPSHOT"] = snapshot_path
    return env


def summary(tmp_path: Path) -> str:
    return (tmp_path / "summary.md").read_text()


def self_waived(tmp_path: Path) -> tuple[Path, str]:
    return repository(tmp_path, {"src/payments/charge.py": "AMOUNT = 1\n", ADR: adr()},
                      {"src/payments/charge.py": "AMOUNT = 2\n", ADR: adr([SELF_WAIVER])})


def test_a_waiver_the_pull_request_adds_does_not_waive_its_own_violation(tmp_path, no_network):
    root, base = self_waived(tmp_path)
    fake = FakeGitHub()
    assert action.main(env_for(tmp_path, root, base, DECISIS_FAIL_ON_VIOLATION="true"), fake) == 1
    out = summary(tmp_path)
    assert outputs(tmp_path)["violations"] == "1"
    assert "#### Violations (1)" in out and "Waived, not counted" not in out
    assert "built with decisis init from the base commit" in out
    (_, _, data), = fake.writes()
    assert data["body"] == out


def test_with_decisions_from_head_the_same_waiver_waives_the_violation(tmp_path, no_network):
    root, base = self_waived(tmp_path)
    env = env_for(tmp_path, root, base, DECISIS_FAIL_ON_VIOLATION="true", DECISIS_DECISIONS_FROM="head")
    assert action.main(env, FakeGitHub()) == 0
    out = summary(tmp_path)
    assert outputs(tmp_path)["violations"] == "0" and "#### Waived, not counted as violations (1)" in out
    assert "take effect once merged" not in out


def test_the_comment_lists_the_changed_decision_files_and_names_the_added_waiver(tmp_path, no_network):
    root, base = self_waived(tmp_path)
    fake = FakeGitHub()
    action.main(env_for(tmp_path, root, base), fake)
    out = summary(tmp_path)
    assert "#### Decision changes that take effect once merged (1)" in out
    assert f"- {action.code(ADR)}" in out and "change no verdict here" in out
    assert f"| {action.code(DECISION)} | {action.code('path src/payments/**')} | added |" in out
    (_, _, data), = fake.writes()
    assert "#### Decision changes that take effect once merged (1)" in data["body"]


def test_a_pull_request_that_removes_the_rule_and_the_adr_is_still_judged_by_the_base(tmp_path, no_network):
    root, base = repository(tmp_path, {"src/payments/charge.py": "AMOUNT = 1\n", ADR: adr()},
                            {"src/payments/charge.py": "AMOUNT = 2\n", ADR: None})
    assert action.main(env_for(tmp_path, root, base, DECISIS_FAIL_ON_VIOLATION="true"), FakeGitHub()) == 1
    out = summary(tmp_path)
    assert "#### Violations (1)" in out
    assert f"| {action.code(DECISION)} |  | removed |" in out


def test_the_head_working_tree_is_not_read_for_the_decisions(tmp_path, no_network):
    root, base = self_waived(tmp_path)
    (root / ADR).write_text(adr([SELF_WAIVER], rule=False))
    (root / ".github").mkdir()
    (root / ".github" / "CODEOWNERS").write_text("src/payments/ @mallory\n")
    assert action.main(env_for(tmp_path, root, base, DECISIS_FAIL_ON_VIOLATION="true"), FakeGitHub()) == 1
    assert "#### Violations (1)" in summary(tmp_path)


def test_base_decisions_are_read_in_a_private_temporary_directory_that_is_removed(tmp_path, monkeypatch, no_network):
    root, base = self_waived(tmp_path)
    seen = []
    real = init.build

    def spy(repo_dir, *args, **kw):
        here = Path(repo_dir)
        seen.append((here, stat.S_IMODE(here.stat().st_mode), sorted(p.relative_to(here).as_posix() for p in here.rglob("*"))))
        return real(repo_dir, *args, **kw)

    monkeypatch.setattr(init, "build", spy)
    action.main(env_for(tmp_path, root, base), FakeGitHub())
    (where, mode, files), (head_where, _, _) = seen
    assert mode == 0o700 and not where.is_relative_to(root) and files == ["docs", "docs/adr", ADR]
    assert not where.exists() and not head_where.exists()


def test_codeowners_come_from_the_base_and_cover_the_heads_new_files(tmp_path):
    root, base = repository(tmp_path, {".github/CODEOWNERS": "src/payments/ @alice\n", "src/payments/charge.py": "A = 1\n"},
                            {".github/CODEOWNERS": "src/payments/ @mallory\n", "src/payments/refund.py": "B = 1\n"})
    graph = committed.built(root, base, None, action.listing(root, base))
    owners = [n for n in graph.nodes if n["kind"] == "concept"]
    assert [n["props"]["owners"] for n in owners] == [["@alice"]] and owners[0]["props"]["code_ref"] == ["src/"]
    assert "src/payments/refund.py" in action.listing(root, base) and "src/payments/charge.py" in action.listing(root, base)


def test_a_symbolic_link_in_the_base_is_listed_as_a_problem_and_not_followed(tmp_path):
    outside = tmp_path / "secret.md"
    outside.write_text("# Secret\n")
    root, base = repository(tmp_path, {ADR: adr()}, {"src/x.py": "X = 1\n"})
    (root / "docs" / "adr" / "0002-link.md").symlink_to(outside)
    git(root, "add", "-A")
    git(root, "commit", "-q", "-m", "link")
    head = subprocess.run(["git", "-C", str(root), "rev-parse", "HEAD"], capture_output=True, text=True, check=True).stdout.strip()
    graph = committed.built(root, head, None, [])
    assert [n["id"] for n in graph.nodes] == [DECISION]
    assert {"file": "docs/adr/0002-link.md", "action": "skipped",
            "reason": "it is a symbolic link in the commit, and decisions are read only from regular files"} in graph.meta["problems"]


def test_a_snapshot_file_is_read_from_the_base_commit(tmp_path, no_network):
    root, base = repository(tmp_path, {"src/payments/charge.py": "A = 1\n", "decisions.json": snapshot()},
                            {"src/payments/charge.py": "A = 2\n", "decisions.json": snapshot([SELF_WAIVER])})
    env = env_for(tmp_path, root, base, str(root / "decisions.json"), DECISIS_FAIL_ON_VIOLATION="true")
    assert action.main(env, FakeGitHub()) == 1
    out = summary(tmp_path)
    assert "#### Violations (1)" in out and "decisions.json at the base commit" in out
    assert f"- {action.code('decisions.json')}" in out
    assert f"| {action.code('decision:payments-review')} | {action.code('path src/payments/**')} | added |" in out


def test_a_snapshot_outside_the_working_directory_stops_the_step_in_base_mode(tmp_path, capsys, no_network):
    root, base = self_waived(tmp_path)
    fake = FakeGitHub()
    assert action.main(env_for(tmp_path, root, base, str(ROOT / "fixtures" / "check" / "vinc.json")), fake) == 2
    assert fake.sent == [] and "decisions-from: head" in capsys.readouterr().out


def test_what_is_judged_comes_from_the_head(tmp_path, no_network):
    fixture = ROOT / "fixtures" / "check" / "repo"
    head = {p.relative_to(fixture).as_posix(): p.read_text() for p in fixture.rglob("*") if p.is_file()}
    root, base = repository(tmp_path, {"decisions.json": (ROOT / "fixtures" / "check" / "vinc.json").read_text()}, head)
    snap = str(root / "decisions.json")
    for name, extra in (("b", {}), ("h", {"DECISIS_DECISIONS_FROM": "head"})):
        (tmp_path / name).mkdir()
        action.main(env_for(tmp_path / name, root, base, snap, **extra), FakeGitHub())
    from_base, from_head = summary(tmp_path / "b"), summary(tmp_path / "h")
    assert "src/shop/ui/view.py" in from_base and "decision\\:ui\\-does\\-not\\-import\\-db" in from_base
    strip = [line for line in from_base.splitlines() if "snapshot" not in line]
    assert strip == [line for line in from_head.splitlines() if "snapshot" not in line]


def test_inventories_come_from_the_head(tmp_path, no_network):
    root, base = repository(tmp_path, {"decisions.json": (ROOT / "fixtures" / "action" / "vinc.json").read_text()},
                            {"package-lock.json": DEMO_LOCK.read_text()})
    env = env_for(tmp_path, root, base, str(root / "decisions.json"), DECISIS_REPO="Demo", DECISIS_INVENTORY="auto",
                  DECISIS_OSV_CACHE=str(osv_cache(tmp_path)))
    action.main(env, FakeGitHub())
    out = summary(tmp_path)
    assert f"#### Audit of {action.code('package-lock.json')}" in out and int(outputs(tmp_path)["violations"]) > 0


def test_a_base_without_adrs_judges_nothing_and_does_not_fail(tmp_path, no_network):
    root, base = repository(tmp_path, {"src/payments/charge.py": "A = 1\n"}, {"src/payments/charge.py": "A = 2\n", ADR: adr()})
    fake = FakeGitHub()
    assert action.main(env_for(tmp_path, root, base, DECISIS_FAIL_ON_VIOLATION="true"), fake) == 0
    out = summary(tmp_path)
    assert "No decisions exist on the base commit" in out and "The base commit has no ADR with a decision" in out
    assert "#### Violations" not in out and outputs(tmp_path)["violations"] == "0"
    assert f"| {action.code(DECISION)} |  | added |" in out
    assert not any("/reviews" in url for _, url, _, _ in fake.sent)
    (_, _, data), = fake.writes()
    assert data["body"] == out


def test_a_base_without_the_snapshot_file_judges_nothing_and_does_not_fail(tmp_path, no_network):
    root, base = repository(tmp_path, {"src/payments/charge.py": "A = 1\n"}, {"src/payments/charge.py": "A = 2\n", "decisions.json": snapshot()})
    env = env_for(tmp_path, root, base, str(root / "decisions.json"), DECISIS_FAIL_ON_VIOLATION="true")
    assert action.main(env, FakeGitHub()) == 0
    out = summary(tmp_path)
    assert "No decisions exist on the base commit" in out and "no snapshot file at" in out
    assert f"- {action.code('decisions.json')}" in out and "cannot be read on both sides" in out


@pytest.mark.parametrize("value", ["merge", "HEAD~1", "both"])
def test_decisions_from_takes_only_base_or_head(tmp_path, value, capsys, no_network):
    root, base = self_waived(tmp_path)
    fake = FakeGitHub()
    assert action.main(env_for(tmp_path, root, base, DECISIS_DECISIONS_FROM=value), fake) == 2
    assert fake.sent == [] and "DECISIS_DECISIONS_FROM must be base or head" in capsys.readouterr().out


def test_the_action_input_defaults_to_base_and_reaches_python_through_the_environment():
    doc = yaml.safe_load((ROOT / "action.yml").read_text(encoding="utf-8"))
    assert doc["inputs"]["decisions-from"]["default"] == "base"
    check, = [s for s in doc["runs"]["steps"] if s.get("id") == "check"]
    assert check["env"]["DECISIS_DECISIONS_FROM"] == "${{ inputs.decisions-from }}"
    docs = (ROOT / "docs" / "action.md").read_text(encoding="utf-8")
    assert "## Trust model" in docs and "decisions-from" in docs


def test_the_changes_name_added_changed_and_removed_decisions_and_waivers():
    with_waiver = {"reason": "r", "expires": "2026-12-01", "approved_by": "@a", "path": "src/**"}

    def graph(nodes):
        return committed.co.load(json.dumps({"meta": {}, "nodes": nodes, "edges": []}))

    def node(nid, statement="s", waivers=None):
        return {"id": nid, "kind": "decision", "title": "t", "props": {"statement": statement, **({"waivers": waivers} if waivers else {})}}

    before = graph([node("decision:a"), node("decision:b", waivers=[with_waiver]), node("decision:c")])
    after = graph([node("decision:a", statement="changed"), node("decision:b", waivers=[{**with_waiver, "expires": "2027-01-01"}]),
                   node("decision:d", waivers=[with_waiver])])
    assert committed.changes(before, after) == [
        {"decision": "decision:a", "waiver": None, "change": "changed"},
        {"decision": "decision:b", "waiver": "path src/**", "change": "changed"},
        {"decision": "decision:c", "waiver": None, "change": "removed"},
        {"decision": "decision:d", "waiver": None, "change": "added"},
        {"decision": "decision:d", "waiver": "path src/**", "change": "added"},
    ]
    assert committed.changes(before, before) == []


def test_the_decision_changes_section_escapes_every_path_and_name(no_network):
    outcome = hostile_outcome()
    outcome = action.Outcome(outcome.report, outcome.pull, outcome.approved, outcome.version, outcome.snapshot,
                             pending=action.Pending([HOSTILE_PATH], [{"decision": HOSTILE, "waiver": HOSTILE, "change": "added"}]))
    out = "\n".join(action.pending(outcome, 50))
    for raw in ("<script", "<img", "<!--", "@everyone", "](", "**bold**", "‮", "\x00", ":shipit:", "$x$"):
        assert raw not in out
    assert all(not line.startswith("#") or line.startswith("#### ") for line in out.splitlines())


def test_this_repository_snapshot_is_tracked_so_the_self_test_reads_it_from_the_base():
    flow = yaml.safe_load((ROOT / ".github" / "workflows" / "decisis.yml").read_text(encoding="utf-8"))
    job, = flow["jobs"].values()
    used, = [s for s in job["steps"] if s.get("uses") == "./"]
    assert used["with"].get("decisions-from", "base") == "base"
    assert (ROOT / used["with"]["snapshot"]).is_file() and not (ROOT / used["with"]["snapshot"]).is_symlink()
