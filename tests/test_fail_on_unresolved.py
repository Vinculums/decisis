from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest
import yaml

from test_action import ROOT, FakeGitHub, environment, osv_cache, outputs, shop
from test_audit import no_network
from test_base_decisions import ADR, env_for, repository, self_waived, summary
from decisis import action

FAILS = "**This check fails: fail-on-unresolved is on and the run found "
DOCKER_WORKFLOW = ("on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n"
                   "      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1\n      - uses: docker://alpine:3.20\n")


def unjudgeable(tmp_path: Path) -> Path:
    snap = json.loads((ROOT / "fixtures" / "check" / "vinc.json").read_text(encoding="utf-8"))
    for node in snap["nodes"]:
        if node["id"] == "decision:ui-does-not-import-db":
            node["props"]["rule"]["imports_forbidden"]["to"] = ["nowhere/**"]
        if node["id"] == "decision:payments-need-a-payments-review":
            del node["props"]["rule"]
    path = tmp_path / "unjudgeable.json"
    path.write_text(json.dumps(snap))
    return path


def first_line(body: str) -> str:
    assert body.startswith(action.MARKER + "\n")
    return body.splitlines()[1]


def run_check(tmp_path: Path, name: str, **extra) -> tuple[int, FakeGitHub, Path]:
    if not (tmp_path / "shop").exists():
        shop(tmp_path)
    root = tmp_path / "shop"
    base = subprocess.run(["git", "-C", str(root), "rev-parse", "HEAD~1"], capture_output=True, text=True, check=True).stdout.strip()
    where = tmp_path / name
    where.mkdir()
    fake = FakeGitHub()
    code = action.main(environment(where, root, base, DECISIS_SNAPSHOT=str(unjudgeable(tmp_path)), **extra), fake)
    return code, fake, where


def audited(tmp_path: Path, files: dict[str, str], inventory: str, rule: dict, **extra) -> tuple[int, FakeGitHub]:
    root, base = shop(tmp_path)
    for name, body in files.items():
        (root / name).parent.mkdir(parents=True, exist_ok=True)
        (root / name).write_text(body)
    nodes = [{"id": "concept:demo", "kind": "concept", "title": "Demo", "props": {"code_ref": "Demo"}},
             {"id": "decision:demo", "kind": "decision", "title": "Demo rule", "props": {"rule": rule}}]
    snap = tmp_path / "audit.json"
    snap.write_text(json.dumps({"meta": {"space": "synthetic"}, "nodes": nodes,
                                "edges": [{"source": "decision:demo", "target": "concept:demo", "type": "ABOUT", "evidence": "test"}]}))
    env = environment(tmp_path, root, base, DECISIS_SNAPSHOT=str(snap), DECISIS_REPO="Demo", DECISIS_INVENTORY=str(root / inventory),
                      DECISIS_OSV_CACHE=str(osv_cache(tmp_path)), **extra)
    fake = FakeGitHub()
    return action.main(env, fake), fake


def test_the_input_defaults_to_false_reaches_python_through_the_environment_and_has_an_output():
    doc = yaml.safe_load((ROOT / "action.yml").read_text(encoding="utf-8"))
    assert doc["inputs"]["fail-on-unresolved"]["default"] == "false"
    step, = (s for s in doc["runs"]["steps"] if s.get("id") == "check")
    assert step["env"]["DECISIS_FAIL_ON_UNRESOLVED"] == "${{ inputs.fail-on-unresolved }}"
    assert "${{" not in step["run"] and "fail-on-unresolved" not in step["run"]
    assert doc["outputs"]["unresolved"]["value"] == "${{ steps.check.outputs.unresolved }}"
    assert doc["outputs"]["violations"]["value"] == "${{ steps.check.outputs.violations }}"
    flow = yaml.safe_load((ROOT / ".github" / "workflows" / "decisis.yml").read_text(encoding="utf-8"))
    job, = flow["jobs"].values()
    assert not any("fail-on-unresolved" in s.get("with", {}) for s in job["steps"])


def test_a_check_result_that_cannot_be_judged_fails_the_step_after_the_comment_and_the_summary(tmp_path, no_network):
    code, fake, where = run_check(tmp_path, "on", DECISIS_FAIL_ON_UNRESOLVED="true")
    assert code == 1
    (method, _, data), = fake.writes()
    assert method == "POST" and summary(where) == data["body"]
    count = int(outputs(where)["unresolved"])
    assert count > 0 and outputs(where)["violations"] == "0"
    assert first_line(data["body"]) == f"{FAILS}{count} check result(s) that cannot be judged.**"
    assert f"#### Cannot be judged ({count})" in data["body"]


def test_with_false_or_unset_nothing_changes_and_the_count_is_still_given(tmp_path, no_network):
    runs = [run_check(tmp_path, "unset"), run_check(tmp_path, "off", DECISIS_FAIL_ON_UNRESOLVED="false")]
    bodies = [fake.writes()[0][2]["body"] for _, fake, _ in runs]
    assert [code for code, _, _ in runs] == [0, 0]
    assert bodies[0] == bodies[1]
    for body, (_, _, where) in zip(bodies, runs):
        assert first_line(body) == "### decisis" and "This check fails" not in body and summary(where) == body
        assert int(outputs(where)["unresolved"]) > 0 and outputs(where)["violations"] == "0"


def test_violations_still_fail_as_before_and_the_unresolved_output_sits_beside_them(tmp_path, no_network):
    root, base = shop(tmp_path)
    fake = FakeGitHub()
    assert action.main(environment(tmp_path, root, base, DECISIS_FAIL_ON_VIOLATION="true"), fake) == 1
    body = fake.writes()[0][2]["body"]
    assert first_line(body) == "### decisis"
    out = (tmp_path / "output.txt").read_text().splitlines()
    assert [line.split("=")[0] for line in out] == ["violations", "unresolved", "comment-url"]
    assert int(outputs(tmp_path)["violations"]) > 0 and int(outputs(tmp_path)["unresolved"]) > 0


@pytest.mark.parametrize("files, inventory, rule, counts", [
    ({".github/workflows/ci.yml": DOCKER_WORKFLOW}, ".github/workflows/ci.yml", {"pinned_to_commit": True},
     "1 unresolved audit finding(s), 1 unresolved package(s)"),
    ({"requirements.txt": "requests==2.31.0\nclick>=8.0\n"}, "requirements.txt", {"advisory_severity_at_least": "HIGH"}, "1 unresolved package(s)"),
], ids=["finding-and-package", "package"])
def test_an_unresolved_audit_finding_or_package_fails_the_step(tmp_path, files, inventory, rule, counts, no_network):
    code, fake = audited(tmp_path, files, inventory, rule, DECISIS_FAIL_ON_UNRESOLVED="true")
    assert code == 1
    (_, _, data), = fake.writes()
    assert first_line(data["body"]) == f"{FAILS}{counts}.**" and summary(tmp_path) == data["body"]
    assert outputs(tmp_path)["unresolved"] == str(sum(int(part.split()[0]) for part in counts.split(", ")))
    assert outputs(tmp_path)["violations"] == "0"


def test_an_unresolved_audit_finding_does_not_fail_the_step_with_false(tmp_path, no_network):
    code, fake = audited(tmp_path, {".github/workflows/ci.yml": DOCKER_WORKFLOW}, ".github/workflows/ci.yml", {"pinned_to_commit": True})
    assert code == 0
    assert first_line(fake.writes()[0][2]["body"]) == "### decisis" and outputs(tmp_path)["unresolved"] == "2"


def test_a_decision_file_not_read_fails_the_step(tmp_path, no_network):
    root, base = repository(tmp_path, {ADR: "---\ntitle: [broken\n---\n# Broken\n", "src/payments/charge.py": "A = 1\n"},
                            {"src/payments/charge.py": "A = 2\n"})
    fake = FakeGitHub()
    assert action.main(env_for(tmp_path, root, base, DECISIS_FAIL_ON_UNRESOLVED="true"), fake) == 1
    (_, _, data), = fake.writes()
    assert first_line(data["body"]) == f"{FAILS}1 decision file(s) not read.**" and summary(tmp_path) == data["body"]
    assert "#### Decision files not read (1)" in data["body"] and outputs(tmp_path)["unresolved"] == "1"


def test_a_waived_result_is_not_counted(tmp_path, no_network):
    root, base = self_waived(tmp_path)
    env = env_for(tmp_path, root, base, DECISIS_FAIL_ON_UNRESOLVED="true", DECISIS_DECISIONS_FROM="head")
    fake = FakeGitHub()
    assert action.main(env, fake) == 0
    body = fake.writes()[0][2]["body"]
    assert "#### Waived, not counted as violations (1)" in body and first_line(body) == "### decisis"
    assert outputs(tmp_path) == {**outputs(tmp_path), "violations": "0", "unresolved": "0"}


def test_a_base_without_decisions_gives_zero_and_does_not_fail(tmp_path, no_network):
    root, base = repository(tmp_path, {"src/payments/charge.py": "A = 1\n"}, {"src/payments/charge.py": "A = 2\n"})
    assert action.main(env_for(tmp_path, root, base, DECISIS_FAIL_ON_UNRESOLVED="true"), FakeGitHub()) == 0
    assert outputs(tmp_path)["unresolved"] == "0" and "This check fails" not in summary(tmp_path)


def test_a_bad_value_stops_the_step_before_any_request(tmp_path, capsys, no_network):
    root, base = shop(tmp_path)
    fake = FakeGitHub()
    assert action.main(environment(tmp_path, root, base, DECISIS_FAIL_ON_UNRESOLVED="maybe"), fake) == 2
    assert fake.sent == [] and "DECISIS_FAIL_ON_UNRESOLVED must be true or false" in capsys.readouterr().out


def test_the_docs_list_the_input_and_the_output_and_say_what_counts():
    docs = (ROOT / "docs" / "action.md").read_text(encoding="utf-8")
    assert "| `fail-on-unresolved` | `false` |" in docs and "has no `fail-on-unresolved` input" not in docs
    assert "The outputs `violations`, `unresolved` and `comment-url`" in docs
    counts = docs.split("## What counts as unresolved", 1)[1].split("\n## ", 1)[0]
    for what in ("cannot be judged", "status is unresolved", "unresolved package", "Decision files not read", "waived result is never"):
        assert what in counts, what
