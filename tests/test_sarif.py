from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
from importlib import metadata
from pathlib import Path
from urllib.parse import unquote

import pytest
import yaml

from test_action import DEMO_LOCK, FakeGitHub, WORKFLOW, audit_env, environment, outputs, shop
from test_audit import no_network
from test_base_decisions import ADR, adr, env_for, repository, snapshot
from decisis import action, cli, rules, sarif

ROOT = Path(__file__).resolve().parents[1]
FIX = ROOT / "fixtures"
GOLDEN = Path(__file__).resolve().parent / "golden"
SCHEMA_FILE = Path(__file__).resolve().parent / "sarif-schema-2.1.0.json"
SCHEMA_SOURCE = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json"
DAY = "2026-11-25"
CHANGED = ["src/shop/ui/view.py", "web/src/ui/page.ts", "src/payments/charge.py", "crates/shop/src/ui.rs"]
ADVISORY_RULE = "decision:no-high-advisories-in-shipped-dependencies"
IMPORT_RULE = "decision:ui-does-not-import-db"
REVIEW_RULE = "decision:payments-need-a-payments-review"
COMMANDS = {
    "check": ["check", str(FIX / "check" / "vinc.json"), "--repo-dir", str(FIX / "check" / "repo"), "--changed", *CHANGED, "--today", DAY],
    "audit": ["audit", str(FIX / "audit" / "vinc.json"), str(FIX / "audit" / "demo-lockfile.json"), "--repo", "Demo", "--root", str(ROOT),
              "--osv-cache", str(FIX / "audit" / "osv-cache.json"), "--today", DAY],
}
EXIT = {"check": 1, "audit": 0}
HOSTILE = 'a "quoted" <script>alert(1)</script> [click](javascript:alert(1)) ] [x]\nnext line `tick` {0} \\ & | @everyone'
LODASH = {"ecosystem": "npm", "name": "lodash"}


def validate(document) -> None:
    jsonschema = pytest.importorskip("jsonschema")
    schema = json.loads(SCHEMA_FILE.read_text(encoding="utf-8"))
    validator = jsonschema.validators.validator_for(schema)
    validator.check_schema(schema)
    errors = [f"{'/'.join(map(str, e.absolute_path))}: {e.message}" for e in validator(schema).iter_errors(document)]
    assert errors == []


def produce(capsys, kind: str, *extra: str, code: int | None = None) -> dict:
    capsys.readouterr()
    assert cli.main([*COMMANDS[kind], "--format", "sarif", *extra]) == (EXIT[kind] if code is None else code)
    return json.loads(capsys.readouterr().out)


def only(document: dict) -> dict:
    assert len(document["runs"]) == 1
    return document["runs"][0]


def with_waivers(path: Path, waivers: dict[str, list]) -> dict:
    snap = json.loads(path.read_text(encoding="utf-8"))
    for n in snap["nodes"]:
        if n["id"] in waivers:
            n["props"]["waivers"] = waivers[n["id"]]
    return snap


def waiver(expires: str = DAY, **covers) -> dict:
    return {"reason": "no patched release yet", "expires": expires, "approved_by": "@shop/security", **covers}


def waived_args(tmp_path: Path, kind: str, expires: str = DAY) -> list[str]:
    if kind == "audit":
        snap = with_waivers(FIX / "audit" / "vinc.json", {ADVISORY_RULE: [waiver(expires, package=LODASH, advisory="GHSA-p6mc-m468-83gw")]})
    else:
        snap = with_waivers(FIX / "check" / "vinc.json", {REVIEW_RULE: [waiver(expires, path="src/payments/**")],
                                                          IMPORT_RULE: [waiver(expires, path="web/**")]})
    path = tmp_path / "waived.json"
    path.write_text(json.dumps(snap), encoding="utf-8")
    args = list(COMMANDS[kind])
    args[1] = str(path)
    return args


def run_args(capsys, args: list[str], code: int) -> dict:
    capsys.readouterr()
    assert cli.main([*args, "--format", "sarif"]) == code
    return json.loads(capsys.readouterr().out)


def rule_ids(run: dict) -> list[str]:
    return [r["id"] for r in run["tool"]["driver"]["rules"]]


@pytest.mark.parametrize("kind", sorted(COMMANDS))
def test_the_output_is_one_sarif_2_1_0_log_that_validates_against_the_official_schema(kind, capsys, no_network):
    assert SCHEMA_SOURCE.endswith("sarif-schema-2.1.0.json")
    document = produce(capsys, kind)
    assert document["version"] == "2.1.0" and document["$schema"] == json.loads(SCHEMA_FILE.read_text(encoding="utf-8"))["id"]
    run = only(document)
    assert run["results"]
    validate(document)


def test_the_validation_is_not_vacuous(capsys, no_network):
    document = produce(capsys, "check")
    for broken in (lambda d: d["runs"][0]["results"][0].update(level="fatal"),
                   lambda d: d["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"].update(startLine=0),
                   lambda d: d["runs"][0]["tool"].pop("driver"),
                   lambda d: d.update(version="2.0.0")):
        bad = json.loads(json.dumps(document))
        broken(bad)
        with pytest.raises(AssertionError):
            validate(bad)


@pytest.mark.parametrize("kind", sorted(COMMANDS))
def test_the_tool_driver_is_decisis_with_its_installed_version(kind, capsys, no_network):
    try:
        installed = metadata.version("decisis")
    except metadata.PackageNotFoundError:
        pytest.skip("decisis is not installed")
    driver = only(produce(capsys, kind))["tool"]["driver"]
    assert (driver["name"], driver["version"]) == ("decisis", installed)
    assert driver["informationUri"] == "https://github.com/Vinculums/decisis"


def test_a_version_that_is_not_installed_is_left_out_not_invented(monkeypatch, capsys, no_network):
    monkeypatch.setattr(sarif, "tool_version", lambda: None)
    assert "version" not in only(produce(capsys, "audit"))["tool"]["driver"]


def test_each_rule_kind_that_judged_something_is_a_descriptor_and_no_other_is(capsys, no_network):
    run = only(produce(capsys, "check"))
    assert rule_ids(run) == ["imports_forbidden", "review_required"]
    assert all(r["shortDescription"]["text"] and r["defaultConfiguration"]["level"] == "error" for r in run["tool"]["driver"]["rules"])
    for r in run["results"]:
        assert run["tool"]["driver"]["rules"][r["ruleIndex"]]["id"] == r["ruleId"]
    capsys.readouterr()
    assert cli.main(["check", str(FIX / "check" / "vinc.json"), "--repo-dir", str(FIX / "check" / "repo"), "--changed", "src/shop/ui/view.py",
                     "--format", "sarif"]) == 1
    assert rule_ids(only(json.loads(capsys.readouterr().out))) == ["imports_forbidden"]
    assert rule_ids(only(produce(capsys, "audit"))) == ["advisory_severity_at_least"]


def test_a_rule_that_judged_findings_clear_is_still_a_descriptor_and_has_no_result(tmp_path, capsys, no_network):
    snap = json.loads((FIX / "audit" / "vinc.json").read_text(encoding="utf-8"))
    for n in snap["nodes"]:
        if n["id"] == ADVISORY_RULE:
            n["props"]["rule"] = {"advisory_severity_at_least": "CRITICAL"}
    path = tmp_path / "strict.json"
    path.write_text(json.dumps(snap), encoding="utf-8")
    args = list(COMMANDS["audit"])
    args[1] = str(path)
    run = only(run_args(capsys, args, 0))
    assert rule_ids(run) == ["advisory_severity_at_least"] and run["results"] == []
    validate({"version": "2.1.0", "runs": [run]})


def test_every_rule_kind_has_a_description():
    assert set(sarif.RULE_TEXT) == set(rules.KINDS)


def test_check_results_are_errors_for_violations_and_warnings_for_unresolved_with_the_decision_and_reason(capsys, no_network):
    run = only(produce(capsys, "check"))
    capsys.readouterr()
    cli.main(COMMANDS["check"])
    report = json.loads(capsys.readouterr().out)
    assert len(run["results"]) == len(report["violations"]) + len(report["unresolved"]) + len(report["waived"]) > 0
    assert report["unresolved"] and not report["waived"]
    levels = [r["level"] for r in run["results"]]
    assert levels == ["error"] * len(report["violations"]) + ["warning"] * len(report["unresolved"])
    for r, source in zip(run["results"], report["violations"] + report["unresolved"]):
        assert r["ruleId"] == source["rule"]
        assert source["decision"] in r["message"]["text"] and sarif.message(source["why"])["text"] in r["message"]["text"]
        assert "suppressions" not in r


def test_check_results_point_to_the_changed_file_and_the_import_line(capsys, no_network):
    run = only(produce(capsys, "check"))
    found = {}
    for r in run["results"]:
        (loc,) = r["locations"]
        physical = loc["physicalLocation"]
        found.setdefault(r["ruleId"], []).append((physical["artifactLocation"]["uri"], physical.get("region", {}).get("startLine")))
    assert ("crates/shop/src/ui.rs", 4) in found["imports_forbidden"] and ("web/src/ui/page.ts", 1) in found["imports_forbidden"]
    assert found["review_required"] == [("src/payments/charge.py", None)]
    review = next(r for r in run["results"] if r["ruleId"] == "review_required")
    assert "region" not in review["locations"][0]["physicalLocation"]


def test_check_properties_carry_the_decision_and_the_path_evidence(capsys, no_network):
    run = only(produce(capsys, "check"))
    imported = next(r for r in run["results"] if r["properties"].get("import") == "from shop.db import models")
    assert imported["properties"] == {"decision": IMPORT_RULE, "rule": "imports_forbidden", "file": "src/shop/ui/view.py",
                                      "import": "from shop.db import models", "target": "src/shop/db/models.py",
                                      "path": ["src/shop/ui/view.py", "src/shop/db/models.py"]}
    review = next(r for r in run["results"] if r["ruleId"] == "review_required")
    assert review["properties"]["decision"] == REVIEW_RULE and review["properties"]["path"] == ["src/payments/charge.py"]


def test_audit_results_are_one_per_violated_policy_and_point_to_the_inventory_file(capsys, no_network):
    run = only(produce(capsys, "audit"))
    capsys.readouterr()
    cli.main(COMMANDS["audit"])
    report = json.loads(capsys.readouterr().out)
    violated = [(f, p) for f in report["findings"] for p in f["policies"] if p["verdict"] == "violated"]
    assert len(run["results"]) == len(violated) == report["violations"] == 3
    for r, (f, p) in zip(run["results"], violated):
        assert r["level"] == "error" and r["ruleId"] == "advisory_severity_at_least"
        assert p["decision"] in r["message"]["text"] and p["why"] in r["message"]["text"] and f["package"] in r["message"]["text"]
        assert r["locations"] == [{"physicalLocation": {"artifactLocation": {"uri": "fixtures/audit/demo-lockfile.json"}}}]
        assert r["properties"] == {"decision": p["decision"], "rule": "advisory_severity_at_least", "package": f["package"],
                                   "advisory": f["advisory"], "path": f["path"]}
    assert not any("lodash@4.17.21" in r["message"]["text"] for r in run["results"])


def test_results_that_are_not_violated_are_left_out(tmp_path, capsys, no_network):
    document = run_args(capsys, waived_args(tmp_path, "audit", "2020-01-01"), 0)
    capsys.readouterr()
    cli.main([*COMMANDS["audit"]])
    full = json.loads(capsys.readouterr().out)
    clear = [p for f in full["findings"] for p in f["policies"] if p["verdict"] == "not_violated"]
    assert clear and len(only(document)["results"]) == full["violations"]
    assert all("not_violated" not in json.dumps(r) for r in only(document)["results"])


@pytest.mark.parametrize("kind", sorted(COMMANDS))
def test_a_waived_result_is_included_with_an_external_suppression_naming_the_waiver(kind, tmp_path, capsys, no_network):
    code = 1 if kind == "check" else 0
    waived = [r for r in only(run_args(capsys, waived_args(tmp_path, kind), code))["results"] if "suppressions" in r]
    assert waived and all(r["level"] == "error" for r in waived)
    for r in waived:
        (s,) = r["suppressions"]
        assert s["kind"] == "external" and s["status"] == "accepted"
        assert "no patched release yet" in s["justification"] and f"until {DAY}" in s["justification"] and "@shop/security" in s["justification"]
        assert r["properties"]["waiver"]["expires"] == DAY
    assert len(waived) == (2 if kind == "check" else 1)
    document = run_args(capsys, waived_args(tmp_path, kind), code)
    validate(document)
    total = len(only(document)["results"])
    late = only(run_args(capsys, waived_args(tmp_path, kind, "2026-11-24"), code))
    assert not [r for r in late["results"] if "suppressions" in r] and len(late["results"]) == total


def test_an_audit_waiver_suppresses_only_the_advisory_it_names(tmp_path, capsys, no_network):
    results = only(run_args(capsys, waived_args(tmp_path, "audit"), 0))["results"]
    (waived,) = [r for r in results if "suppressions" in r]
    assert waived["properties"]["advisory"] == "adv:GHSA-p6mc-m468-83gw" and waived["properties"]["package"] == "pkg:npm/lodash@4.17.15"
    assert len(results) == 3 and len([r for r in results if "suppressions" not in r]) == 2


def test_the_log_is_the_same_on_every_run(capsys, no_network):
    assert produce(capsys, "check") == produce(capsys, "check") and produce(capsys, "audit") == produce(capsys, "audit")


@pytest.mark.parametrize("kind", sorted(COMMANDS))
def test_the_fixtures_render_to_the_committed_golden_sarif(kind, capsys, monkeypatch, no_network):
    monkeypatch.setattr(sarif, "tool_version", lambda: "0.0.0")
    capsys.readouterr()
    assert cli.main([*COMMANDS[kind], "--format", "sarif"]) == EXIT[kind]
    out = capsys.readouterr().out
    golden = GOLDEN / f"{kind}.sarif"
    if os.environ.get("DECISIS_GOLDEN") == "write":
        golden.write_text(out, encoding="utf-8")
    assert out == golden.read_text(encoding="utf-8")


def test_audit_out_still_writes_the_json_report_while_the_sarif_goes_to_stdout(tmp_path, capsys, no_network):
    out = tmp_path / "report.json"
    document = produce(capsys, "audit", "--out", str(out))
    assert only(document)["results"] and json.loads(out.read_text(encoding="utf-8"))["violations"] == 3


def test_sarif_is_offered_for_check_and_audit_only(capsys):
    for command in ("impact", "paths"):
        with pytest.raises(SystemExit) as e:
            cli.main([command, "x", "y", "z", "--format", "sarif"])
        assert e.value.code == 2
    assert "invalid choice" in capsys.readouterr().err


def digest(*parts) -> str:
    return hashlib.sha256(json.dumps(list(parts), separators=(",", ":")).encode("ascii")).hexdigest()


def test_every_result_has_a_fingerprint_built_from_the_decision_rule_file_and_import_or_package(capsys, no_network):
    run = only(produce(capsys, "check"))
    prints = [r["partialFingerprints"]["decisis/v1"] for r in run["results"]]
    assert len(set(prints)) == len(prints) == len(run["results"])
    first = run["results"][0]
    assert first["partialFingerprints"] == {"decisis/v1": digest(IMPORT_RULE, "imports_forbidden", "crates/shop/src/ui.rs", "use crate::db::models::Order")}
    review = next(r for r in run["results"] if r["ruleId"] == "review_required")
    assert review["partialFingerprints"] == {"decisis/v1": digest(REVIEW_RULE, "review_required", "src/payments/charge.py", "")}
    audit = only(produce(capsys, "audit"))
    p = audit["results"][0]["properties"]
    assert audit["results"][0]["partialFingerprints"] == {"decisis/v1": digest(p["decision"], p["rule"], "fixtures/audit/demo-lockfile.json",
                                                                              p["package"], p["advisory"])}
    assert len({r["partialFingerprints"]["decisis/v1"] for r in audit["results"]}) == len(audit["results"]) == 3


def test_a_finding_keeps_its_fingerprint_when_its_line_moves_and_changes_it_when_any_part_changes(tmp_path, capsys, no_network):
    def seen(run: dict) -> dict:
        return {r["partialFingerprints"]["decisis/v1"]: (r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
                                                         r["locations"][0]["physicalLocation"].get("region", {}).get("startLine"))
                for r in run["results"]}
    before = seen(only(produce(capsys, "check")))
    repo = tmp_path / "repo"
    shutil.copytree(FIX / "check" / "repo", repo)
    view = repo / "src" / "shop" / "ui" / "view.py"
    view.write_text("\n\n\n" + view.read_text(encoding="utf-8"), encoding="utf-8")
    args = list(COMMANDS["check"])
    args[args.index("--repo-dir") + 1] = str(repo)
    after = seen(only(run_args(capsys, args, 1)))
    assert set(after) == set(before)
    moved = {k for k in before if before[k] != after[k]}
    assert moved == {k for k in before if before[k][0] == "src/shop/ui/view.py"} and len(moved) >= 2
    assert all(after[k][1] == before[k][1] + 3 for k in moved)
    base = sarif.fingerprint(["d", "r", "f", "i"], {})
    for changed in (["x", "r", "f", "i"], ["d", "x", "f", "i"], ["d", "r", "x", "i"], ["d", "r", "f", "x"]):
        assert sarif.fingerprint(changed, {}) != base
    assert sarif.fingerprint(["a", "bc"], {}) != sarif.fingerprint(["ab", "c"], {})


def test_two_identical_findings_in_one_file_get_two_fingerprints():
    one = {"file": "src/a.py", "line": 3, "decision": "decision:d", "rule": "imports_forbidden", "verdict": "violated", "why": "w",
           "import": "db", "target": "db.py"}
    run = sarif.check_run({"violations": [one, {**one, "line": 9}]}, version="1.0.0")
    first, second = (r["partialFingerprints"]["decisis/v1"] for r in run["results"])
    assert first != second and second == first + ":2"


def test_a_log_is_valid_when_the_report_has_nothing_to_show():
    run = sarif.check_run({"changed": ["a.py"]}, version="1.0.0")
    assert run["results"] == [] and run["tool"]["driver"]["rules"] == []
    validate(sarif.log([run, sarif.audit_run({}, None, "1.0.0")]))


def hostile_check() -> dict:
    ids = "decision:" + HOSTILE
    paths = ["src/" + HOSTILE, "../../etc/passwd", "/etc/passwd", "C:\\Windows\\win.ini", "a/../../b.py", "src/a b#c%d?e.py", "javascript:alert(1).py",
             "src/ünï/ファイル.py", "\\\\host\\share\\x.py", ".", "", "src/\ud800.py"]
    violations = [{"file": f, "line": 1, "decision": ids, "rule": "imports_forbidden", "verdict": "violated", "why": HOSTILE, "import": HOSTILE,
                   "target": "db/" + HOSTILE} for f in paths]
    return {"violations": violations, "unresolved": [{**violations[0], "verdict": "unresolved", "line": None, "target": None}],
            "waived": [{**violations[0], "verdict": "waived", "waiver": {"waiver": 1, "reason": HOSTILE, "expires": DAY, "approved_by": HOSTILE}}],
            "rules": [{"decision": ids, "rule": HOSTILE, "files": paths}]}


def test_hostile_text_stays_data_in_the_messages_and_the_log_validates():
    document = sarif.log([sarif.check_run(hostile_check(), version="1.0.0")])
    text = sarif.dumps(document)
    validate(document)
    assert json.loads(text) == document and text.encode("utf-8")
    for r in only(document)["results"]:
        shown = r["message"]["text"]
        assert not re.search(r"(?<!\\)[\[\]]", shown.replace("\\\\", ""))
        assert "[click](javascript:alert(1))" not in shown and "\\[click\\]" in shown
        assert "\ud800" not in shown
        assert set(r) <= {"ruleId", "ruleIndex", "level", "message", "locations", "partialFingerprints", "properties", "suppressions"}
    for d in only(document)["tool"]["driver"]["rules"]:
        assert not re.search(r"(?<!\\)[\[\]]", d["shortDescription"]["text"].replace("\\\\", ""))
    (waived,) = [r for r in only(document)["results"] if "suppressions" in r]
    assert set(waived["suppressions"][0]) == {"kind", "status", "justification"}
    assert HOSTILE in waived["suppressions"][0]["justification"]


def test_hostile_audit_text_stays_data_and_the_log_validates():
    finding = {"package": "pkg:npm/" + HOSTILE, "advisory": "adv:" + HOSTILE, "severity": "HIGH", "status": "affected", "dev_only": False,
               "path": ["repo:" + HOSTILE, "pkg:npm/" + HOSTILE, "adv:" + HOSTILE],
               "policies": [{"decision": "decision:" + HOSTILE, "verdict": "violated", "why": HOSTILE},
                            {"decision": "decision:" + HOSTILE, "verdict": "unresolved", "why": HOSTILE, "rule": "license_denied"}]}
    for inventory in ("../../x.json", "/abs/x.json", HOSTILE, "ok/package-lock.json"):
        document = sarif.log([sarif.audit_run({"findings": [finding]}, inventory, "1.0.0")])
        validate(document)
        run = only(document)
        assert [r["level"] for r in run["results"]] == ["error", "warning"] and rule_ids(run) == ["advisory_severity_at_least", "license_denied"]
        assert "../" not in run["automationDetails"]["id"] or inventory == HOSTILE
        for r in run["results"]:
            assert not re.search(r"(?<!\\)[\[\]]", r["message"]["text"].replace("\\\\", ""))


def test_a_path_that_leaves_the_repository_gets_no_location_and_the_others_are_encoded_repository_relative_uris():
    document = sarif.log([sarif.check_run(hostile_check(), version="1.0.0")])
    found = [(r["properties"].get("file"), r.get("locations")) for r in only(document)["results"][:12]]
    by_file = {f: loc for f, loc in found}
    for leaving in ("../../etc/passwd", "/etc/passwd", "C:\\Windows\\win.ini", "a/../../b.py", "\\\\host\\share\\x.py", ".", ""):
        assert leaving not in by_file or by_file[leaving] is None
    uris = [loc[0]["physicalLocation"]["artifactLocation"]["uri"] for _, loc in found if loc]
    assert uris
    for uri in uris:
        assert not uri.startswith("/") and ".." not in uri.split("/") and "://" not in uri and ":" not in uri
        assert re.fullmatch(r"[A-Za-z0-9._~%/-]+", uri), uri
    assert "src/a%20b%23c%25d%3Fe.py" in uris and "javascript%3Aalert%281%29.py" in uris
    assert unquote("src/%C3%BCn%C3%AF/%E3%83%95%E3%82%A1%E3%82%A4%E3%83%AB.py") == "src/ünï/ファイル.py"
    assert "src/%C3%BCn%C3%AF/%E3%83%95%E3%82%A1%E3%82%A4%E3%83%AB.py" in uris
    assert not any("etc/passwd" in u or "Windows" in u or "host" in u for u in uris)


def test_a_base_directory_is_put_before_the_file_and_cannot_lead_out():
    report = {"violations": [{"file": "src/a.py", "line": 2, "decision": "d", "rule": "review_required", "verdict": "violated", "why": "w"}]}
    assert only(sarif.log([sarif.check_run(report, version="1")]))["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "src/a.py"
    nested = sarif.check_run(report, version="1", base="app/web")["results"][0]
    assert nested["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "app/web/src/a.py"
    assert "locations" not in sarif.check_run(report, version="1", base="../up")["results"][0]
    assert nested["partialFingerprints"] != sarif.check_run(report, version="1")["results"][0]["partialFingerprints"]


def test_an_inventory_outside_the_repository_has_no_repository_path(tmp_path):
    repo = tmp_path / "repo"
    (repo / "sub").mkdir(parents=True)
    (repo / ".git").mkdir()
    outside = tmp_path / "elsewhere"
    outside.mkdir()
    assert sarif.inventory_path(repo / "sub" / "package-lock.json") == "sub/package-lock.json"
    assert sarif.inventory_path(repo / "sub" / "package-lock.json", repo) == "sub/package-lock.json"
    assert sarif.inventory_path(outside / "package-lock.json", repo) is None
    assert sarif.inventory_path(outside / "package-lock.json") == "package-lock.json"


def test_no_absolute_path_reaches_the_cli_output(tmp_path, capsys, no_network):
    lock = tmp_path / "work" / "package-lock.json"
    lock.parent.mkdir()
    shutil.copy(DEMO_LOCK, lock)
    args = [a if a != str(FIX / "audit" / "demo-lockfile.json") else str(lock) for a in COMMANDS["audit"]]
    args[args.index("--root") + 1] = str(tmp_path)
    capsys.readouterr()
    assert cli.main([*args, "--format", "sarif"]) == 0
    out = capsys.readouterr().out
    assert str(tmp_path) not in out and str(ROOT) not in out
    assert only(json.loads(out))["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "work/package-lock.json"
    capsys.readouterr()
    cli.main([*COMMANDS["check"], "--format", "sarif"])
    assert str(ROOT) not in capsys.readouterr().out


def sarif_env(tmp_path: Path, root: Path, base: str, **extra) -> dict:
    return environment(tmp_path, root, base, **{"GITHUB_WORKSPACE": str(root), "DECISIS_SARIF": "true", **extra})


def test_the_action_writes_no_sarif_unless_asked(tmp_path, no_network):
    root, base = shop(tmp_path)
    for n, extra in enumerate(({}, {"DECISIS_SARIF": "false"}, {"DECISIS_SARIF": ""})):
        sub = tmp_path / f"run{n}"
        sub.mkdir()
        assert action.main(environment(sub, root, base, GITHUB_WORKSPACE=str(root), **extra), FakeGitHub()) == 0
        assert "sarif-file" not in (sub / "output.txt").read_text()
    assert not (root / "decisis.sarif").exists()


def test_the_action_writes_decisis_sarif_in_the_workspace_and_sets_the_output(tmp_path, no_network):
    root, base = shop(tmp_path)
    fake = FakeGitHub()
    assert action.main(sarif_env(tmp_path, root, base), fake) == 0
    path = root / "decisis.sarif"
    assert outputs(tmp_path)["sarif-file"] == str(path)
    document = json.loads(path.read_text(encoding="utf-8"))
    validate(document)
    run = only(document)
    assert run["automationDetails"]["id"] == "decisis/check/" and rule_ids(run) == ["imports_forbidden", "review_required"]
    assert {r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] for r in run["results"]} >= {"src/shop/ui/view.py", "src/payments/charge.py"}
    assert [p for p in root.iterdir() if p.name.startswith(".decisis-")] == []


def test_the_comment_and_the_exit_code_do_not_change_with_sarif(tmp_path, no_network):
    root, base = shop(tmp_path)
    plain, withit = tmp_path / "plain", tmp_path / "sarif"
    plain.mkdir()
    withit.mkdir()
    one, two = FakeGitHub(), FakeGitHub()
    assert action.main(environment(plain, root, base, DECISIS_FAIL_ON_VIOLATION="true"), one) == 1
    assert action.main(sarif_env(withit, root, base, DECISIS_FAIL_ON_VIOLATION="true"), two) == 1
    assert one.writes()[0][2] == two.writes()[0][2]
    assert (plain / "summary.md").read_text() == (withit / "summary.md").read_text()
    kept = {k: v for k, v in outputs(withit).items() if k != "sarif-file"}
    assert kept == outputs(plain) and "sarif-file" in outputs(withit)
    assert json.loads((root / "decisis.sarif").read_text(encoding="utf-8"))["runs"][0]["results"]


def test_a_bad_sarif_value_stops_the_step_before_any_request(tmp_path, capsys, no_network):
    root, base = shop(tmp_path)
    fake = FakeGitHub()
    assert action.main(sarif_env(tmp_path, root, base, DECISIS_SARIF="maybe"), fake) == 2
    assert fake.sent == [] and "DECISIS_SARIF must be true or false" in capsys.readouterr().out
    assert not (root / "decisis.sarif").exists()


def test_a_fork_pull_request_still_gets_the_file_and_no_comment(tmp_path, no_network):
    root, base = shop(tmp_path)
    fake = FakeGitHub()
    assert action.main(sarif_env(tmp_path, root, base, fork=True), fake) == 0
    assert fake.writes() == [] and outputs(tmp_path)["sarif-file"] == str(root / "decisis.sarif")
    assert (root / "decisis.sarif").is_file()


def test_each_inventory_is_its_own_run_with_its_own_category_and_the_inventory_file_as_location(tmp_path, no_network):
    root, base = shop(tmp_path)
    shutil.copy(DEMO_LOCK, root / "package-lock.json")
    (root / ".github" / "workflows").mkdir(parents=True)
    (root / ".github" / "workflows" / "ci.yml").write_text(WORKFLOW)
    assert action.main(audit_env(tmp_path, root, base, "auto", GITHUB_WORKSPACE=str(root), DECISIS_SARIF="true"), FakeGitHub()) == 0
    document = json.loads((root / "decisis.sarif").read_text(encoding="utf-8"))
    validate(document)
    ids = [r["automationDetails"]["id"] for r in document["runs"]]
    assert ids == ["decisis/check/", "decisis/audit/package-lock.json/", "decisis/audit/.github/workflows/ci.yml/"] and len(set(ids)) == 3
    audit = document["runs"][1]
    assert audit["results"] and {r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] for r in audit["results"]} == {"package-lock.json"}
    assert document["runs"][2]["results"] == []


def test_an_inventory_outside_the_workspace_repository_is_audited_but_has_no_location(tmp_path, no_network):
    root, base = shop(tmp_path)
    assert action.main(audit_env(tmp_path, root, base, str(DEMO_LOCK), GITHUB_WORKSPACE=str(root), DECISIS_SARIF="true"), FakeGitHub()) == 0
    text = (root / "decisis.sarif").read_text(encoding="utf-8")
    audit = json.loads(text)["runs"][1]
    assert audit["results"] and all("locations" not in r for r in audit["results"])
    assert str(ROOT) not in text and str(tmp_path) not in text and audit["automationDetails"]["id"] == "decisis/audit/inventory/"


def test_a_working_directory_below_the_repository_root_is_put_before_each_file(tmp_path, no_network):
    root, base = repository(tmp_path, {"app/src/payments/charge.py": "A = 1\n"}, {"app/src/payments/charge.py": "A = 2\n"})
    snap = tmp_path / "decisions.json"
    snap.write_text(snapshot(), encoding="utf-8")
    env = environment(tmp_path, root, base, GITHUB_WORKSPACE=str(root), DECISIS_SARIF="true", DECISIS_SNAPSHOT=str(snap),
                      DECISIS_WORKING_DIRECTORY=str(root / "app"), DECISIS_TODAY=DAY)
    assert action.main(env, FakeGitHub()) == 0
    (result,) = only(json.loads((root / "decisis.sarif").read_text(encoding="utf-8")))["results"]
    assert result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "app/src/payments/charge.py"
    assert result["properties"]["file"] == "src/payments/charge.py"


def test_when_the_base_has_no_decisions_the_file_is_a_valid_log_with_no_results(tmp_path, no_network):
    root, base = repository(tmp_path, {"src/payments/charge.py": "A = 1\n"}, {"src/payments/charge.py": "A = 2\n", ADR: adr()})
    env = env_for(tmp_path, root, base, DECISIS_FAIL_ON_VIOLATION="true", GITHUB_WORKSPACE=str(root), DECISIS_SARIF="true")
    assert action.main(env, FakeGitHub()) == 0
    document = json.loads((root / "decisis.sarif").read_text(encoding="utf-8"))
    validate(document)
    assert only(document)["results"] == [] and outputs(tmp_path)["sarif-file"] == str(root / "decisis.sarif")


def test_a_symbolic_link_named_decisis_sarif_is_replaced_and_never_written_through(tmp_path, no_network):
    root, base = shop(tmp_path)
    victim = tmp_path / "victim.txt"
    victim.write_text("keep me\n")
    (root / "decisis.sarif").symlink_to(victim)
    assert action.main(sarif_env(tmp_path, root, base), FakeGitHub()) == 0
    assert victim.read_text() == "keep me\n"
    assert not (root / "decisis.sarif").is_symlink() and json.loads((root / "decisis.sarif").read_text(encoding="utf-8"))["version"] == "2.1.0"


def test_an_unwritable_workspace_stops_the_step_with_an_error(tmp_path, capsys, no_network):
    root, base = shop(tmp_path)
    assert action.main(sarif_env(tmp_path, root, base, GITHUB_WORKSPACE=str(tmp_path / "missing")), FakeGitHub()) == 2
    assert "error:" in capsys.readouterr().out


def test_the_action_has_the_input_the_output_and_a_pinned_upload_step():
    text = (ROOT / "action.yml").read_text(encoding="utf-8")
    doc = yaml.safe_load(text)
    assert doc["inputs"]["sarif"]["default"] == "false" and doc["outputs"]["sarif-file"]["value"] == "${{ steps.check.outputs.sarif-file }}"
    check, = [s for s in doc["runs"]["steps"] if s.get("id") == "check"]
    assert check["env"]["DECISIS_SARIF"] == "${{ inputs.sarif }}"
    upload, = [s for s in doc["runs"]["steps"] if s.get("uses", "").startswith("github/codeql-action/upload-sarif@")]
    assert re.fullmatch(r"github/codeql-action/upload-sarif@[0-9a-f]{40}", upload["uses"])
    assert re.search(r"uses: github/codeql-action/upload-sarif@[0-9a-f]{40} # v[34]\.\d+\.\d+\n", text)
    assert upload["with"] == {"sarif_file": "${{ steps.check.outputs.sarif-file }}"}
    assert "steps.check.outputs.sarif-file != ''" in upload["if"] and "!cancelled()" in upload["if"]
    assert "github.event.pull_request.head.repo.full_name == github.repository" in upload["if"]
    assert doc["runs"]["steps"].index(upload) > doc["runs"]["steps"].index(check)


def test_the_self_test_workflow_uploads_with_the_one_extra_permission():
    flow = yaml.safe_load((ROOT / ".github" / "workflows" / "decisis.yml").read_text(encoding="utf-8"))
    assert flow["permissions"] == {}
    job, = flow["jobs"].values()
    assert job["permissions"]["security-events"] == "write"
    assert [s["with"]["sarif"] for s in job["steps"] if s.get("uses") == "./"] == [True]


def test_the_docs_describe_the_format_the_input_the_permission_and_the_fork_limit():
    commands = (ROOT / "docs" / "commands.md").read_text(encoding="utf-8")
    action_doc = " ".join((ROOT / "docs" / "action.md").read_text(encoding="utf-8").split())
    assert "--format sarif" in commands and "SARIF 2.1.0" in commands and "partialFingerprints" in commands and "suppressions" in commands
    assert "| `sarif` | `false` |" in action_doc and "`sarif-file`" in action_doc and "decisis.sarif" in action_doc
    assert "security-events: write" in action_doc and "github/codeql-action/upload-sarif" in action_doc
    assert "Pull requests from forks cannot upload" in action_doc
