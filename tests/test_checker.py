from __future__ import annotations

import json
from pathlib import Path

import pytest

from test_audit import advisories, lock, no_network
from decisis import audit, checker, cli, demo
from decisis import checkout as co
from decisis import commit as wb

FIX = Path(__file__).resolve().parents[1] / "fixtures"
SNAPSHOT = FIX / "audit" / "vinc.json"


def report() -> dict:
    return audit.run(co.load(SNAPSHOT.read_text()), lock(), "Demo", advisories=advisories())


def propose(tmp_path: Path, capsys, rep: dict) -> tuple[int, dict, str]:
    (tmp_path / "report.json").write_text(json.dumps(rep), encoding="utf-8")
    capsys.readouterr()
    code = cli.main(["propose", str(tmp_path / "report.json"), str(SNAPSHOT), str(FIX / "audit" / "demo-lockfile.json"),
                     "--repo", "Demo", "--space", "demo-space", "--osv-cache", str(FIX / "audit" / "osv-cache.json"),
                     "--out", str(tmp_path / "plan.json")])
    plan = json.loads((tmp_path / "plan.json").read_text(encoding="utf-8"))
    return code, plan, capsys.readouterr().out


def made_up_path(f: dict) -> None:
    f["path"] = [f["path"][0], "pkg:npm/made-up@1.0.0", *f["path"][-2:]]


def not_a_decision(f: dict) -> None:
    f["policies"].append({"decision": "concept:demo-app", "verdict": "violated", "why": "made up"})


TAMPER = {
    "changed hash": (lambda f: f.update(content_hash="0" * 64), "the advisory hash differs from the OSV record"),
    "version out of range": (lambda f: f.update(package="pkg:npm/lodash@9.9.9"), "lodash 9.9.9 is not inside the advisory's affected ranges"),
    "made-up path": (made_up_path, "a dependency path is not in the sandbox graph: repo:Demo -> pkg:npm/made-up@1.0.0"),
    "target that is not a decision": (not_a_decision, "concept:demo-app is not a decision in the snapshot"),
    "changed severity": (lambda f: f.update(severity="CRITICAL"), "severity CRITICAL differs from the OSV record's severity"),
}


def test_an_untouched_report_passes_every_check_and_keeps_every_record(tmp_path, capsys, no_network):
    code, plan, out = propose(tmp_path, capsys, report())
    assert code == 0
    assert len(plan["nodes"]) == 7 and plan["held"] == [] and plan["digest"] == wb.digest(plan)
    assert "Re-derived 7 records with 31 checks; 0 failed." in out and f"--approve {plan['digest']}" in out


@pytest.mark.parametrize("name", sorted(TAMPER))
def test_a_tampered_record_is_held_with_its_failed_check_and_propose_exits_non_zero(tmp_path, capsys, no_network, name):
    tamper, problem = TAMPER[name]
    rep = report()
    f = next(f for f in rep["findings"] if not f["dev_only"])
    tamper(f)
    rid = wb.record_id("Demo", "lodash", "shipped", f["advisory"].split(":", 1)[1])
    code, plan, out = propose(tmp_path, capsys, rep)
    assert code == 1
    assert rid not in [n["id"] for n in plan["nodes"]] and len(plan["nodes"]) == 6
    assert all(e["from"] != rid for e in plan["edges"])
    held = [h for h in plan["held"] if h.get("record") == rid]
    assert len(held) == 1 and any(p.startswith(problem) for p in held[0]["failed"]), held
    assert [h["record"] for h in plan["held"]] == [rid]
    assert plan["digest"] == wb.digest(plan)
    assert "1 failed." in out and f"{rid}: {problem}" in out


def held(plan: dict) -> dict[str, list[str]]:
    return {h["record"]: h["failed"] for h in plan["held"]}


def test_a_version_that_is_not_in_the_lockfile_is_held(tmp_path, capsys, no_network):
    rep = report()
    for f in rep["findings"]:
        f["package"] = f["package"].replace("pkg:npm/lodash@4.17.15", "pkg:npm/lodash@4.0.0")
    code, plan, _ = propose(tmp_path, capsys, rep)
    assert code == 1
    assert all(n["props"]["scope"] == "development" for n in plan["nodes"]) and len(plan["nodes"]) == 2
    assert len(held(plan)) == 5
    for problems in held(plan).values():
        assert "lodash 4.0.0 is not a package in the lockfile" in problems
        assert any(p.startswith("a dependency path does not run from repo:Demo") for p in problems)


def test_a_path_borrowed_from_another_finding_is_held(tmp_path, capsys, no_network):
    rep = report()
    dev = next(f for f in rep["findings"] if f["dev_only"] and f["advisory"] == "adv:GHSA-r5fr-rjxr-66jc")
    target = next(f for f in rep["findings"] if not f["dev_only"] and f["advisory"] == "adv:GHSA-29mw-wpgm-hmr9")
    target["path"] = list(dev["path"])
    code, plan, _ = propose(tmp_path, capsys, rep)
    rid = wb.record_id("Demo", "lodash", "shipped", "GHSA-29mw-wpgm-hmr9")
    assert code == 1 and list(held(plan)) == [rid]
    assert held(plan)[rid] == ["no dependency path of this record reaches lodash 4.17.15",
                               "a dependency path does not run from repo:Demo to this record's package and advisory: "
                               + " -> ".join(dev["path"])]


def test_development_findings_claimed_as_shipped_and_critical_are_held(tmp_path, capsys, no_network):
    rep = report()
    for f in rep["findings"]:
        if f["dev_only"]:
            f.update(dev_only=False, severity="CRITICAL")
    code, plan, _ = propose(tmp_path, capsys, rep)
    assert code == 1
    assert sorted(held(plan)) == [wb.record_id("Demo", "lodash", "shipped", a) for a in ("GHSA-r5fr-rjxr-66jc", "GHSA-xxjr-mmjv-4gpg")]
    assert all("4.17.21" not in n["props"]["versions"] and n["props"]["scope"] == "shipped" for n in plan["nodes"])
    for problems in held(plan).values():
        assert problems == [p for p in problems if p.startswith("a dependency path does not match scope shipped: repo:Demo -> pkg:npm/test-kit@1.0.3")]


def test_the_demo_runs_the_same_checks(tmp_path, monkeypatch, no_network):
    calls = []
    real = checker.check_plan

    def spy(*args, **kw):
        calls.append(args)
        return real(*args, **kw)

    monkeypatch.setattr(checker, "check_plan", spy)
    shm = tmp_path / "shm"
    shm.mkdir()
    code, transcript = demo.run(tmp_path / "demo", FIX, sandbox_root=shm, emit=lambda *_: None)
    assert code == 0 and len(calls) == 1 and not hasattr(demo, "check_plan")
    assert transcript["steps"][5]["data"]["checks"] == 31
