from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from test_audit import no_network
from decisis import checkout as co
from decisis import check, cli, imports, rules

ROOT = Path(__file__).resolve().parents[1]
FIX = ROOT / "fixtures" / "check"
REPO = FIX / "repo"
SNAPSHOT = FIX / "vinc.json"
GOLDEN = Path(__file__).resolve().parent / "golden"
CHANGED = ["src/shop/ui/view.py", "web/src/ui/page.ts", "web/src/ui/index.ts", "src/payments/charge.py"]
GIT = ("git", "-c", "user.name=t", "-c", "user.email=t@example.invalid", "-c", "commit.gpgsign=false", "-c", "core.hooksPath=/dev/null")


def cli_run(capsys, *args: str) -> tuple[int, str]:
    capsys.readouterr()
    code = cli.main(["check", str(SNAPSHOT), "--repo-dir", str(REPO), *args])
    return code, capsys.readouterr().out


def report(capsys, *args: str) -> tuple[int, dict]:
    code, out = cli_run(capsys, *args)
    return code, json.loads(out)


def rows(results: list[dict]) -> set[tuple]:
    return {(r["file"], r["line"], r["decision"], r["rule"]) for r in results}


def test_forbidden_imports_in_python_and_typescript_are_violations_with_file_line_decision_and_rule(capsys, no_network):
    code, r = report(capsys, "--changed", *CHANGED, "--reviewers", "@alice")
    assert code == 1
    assert rows(r["violations"]) == {
        ("src/shop/ui/view.py", 4, "decision:ui-does-not-import-db", "imports_forbidden"),
        ("src/shop/ui/view.py", 5, "decision:ui-does-not-import-db", "imports_forbidden"),
        ("web/src/ui/page.ts", 1, "decision:ui-does-not-import-db", "imports_forbidden"),
    }
    assert {(v["import"], v["target"]) for v in r["violations"]} == {
        ("from shop.db import models", "src/shop/db/models.py"), ("from ..db.session import open_session", "src/shop/db/session.py"),
        ("../db/client", "web/src/db/client.ts")}


def test_a_dynamic_import_is_unresolved_not_violated(capsys, no_network):
    _, r = report(capsys, "--changed", *CHANGED, "--reviewers", "@alice")
    assert rows(r["unresolved"]) == {("src/shop/ui/view.py", 10, "decision:ui-does-not-import-db", "imports_forbidden"),
                                     ("web/src/ui/page.ts", 9, "decision:ui-does-not-import-db", "imports_forbidden")}
    assert all("computed at run time" in u["why"] for u in r["unresolved"])
    assert r["summary"]["unresolved"] == 2


def test_comments_strings_regexes_and_templates_are_not_read_as_imports(capsys, no_network):
    _, r = report(capsys, "--changed", "web/src/ui/page.ts")
    assert [(i["line"], i["import"], i["resolution"]) for i in r["imports"]] == [
        (1, "../db/client", "repository"), (2, "react", "external"), (9, "import() with a computed specifier", "unresolved")]


def test_a_missing_reviewer_is_a_violation_and_a_present_one_is_not(capsys, no_network):
    code, r = report(capsys, "--changed", "src/payments/charge.py", "--reviewers", "bob")
    assert code == 1
    assert rows(r["violations"]) == {("src/payments/charge.py", None, "decision:payments-need-a-payments-review", "review_required")}
    for present in (["Alice"], ["@ALICE"], ["@shop/payments"]):
        code, r = report(capsys, "--changed", "src/payments/charge.py", "--reviewers", *present)
        assert code == 0 and r["violations"] == [], present


def test_a_team_handle_matches_only_exactly(capsys, no_network):
    for given in ("@Shop/Payments", "shop/payments"):
        code, r = report(capsys, "--changed", "src/payments/charge.py", "--reviewers", given)
        assert code == 1 and len(r["violations"]) == 1, given


def test_a_superseded_decision_is_listed_apart_and_never_judged(capsys, no_network):
    _, r = report(capsys, "--changed", "src/payments/charge.py", "--reviewers", "alice")
    assert [s["decision"] for s in r["superseded"]] == ["decision:payments-reviewed-by-carol"]
    assert r["superseded"][0]["superseded_by"] == ["decision:payments-need-a-payments-review"]
    assert "decision:payments-reviewed-by-carol" not in {x["decision"] for x in r["rules"]}
    assert r["violations"] == []


def test_the_report_lists_the_governing_decisions_and_keeps_its_documented_keys(capsys, no_network):
    _, r = report(capsys, "--changed", *CHANGED)
    assert set(r) == {"loaded", "hops", "repo", "base", "changed", "reviewers", "governing", "superseded", "rules", "imports",
                      "violations", "unresolved", "summary", "impact"}
    assert {g["decision"]: g["files"] for g in r["governing"]} == {
        "decision:payments-need-a-payments-review": ["src/payments/charge.py"],
        "decision:ui-does-not-import-db": ["src/shop/ui/view.py", "web/src/ui/index.ts", "web/src/ui/page.ts"]}
    assert all(set(v) == {"file", "line", "decision", "rule", "verdict", "why", "import", "target"} for v in r["violations"] + r["unresolved"])
    review = next(v for v in r["violations"] if v["rule"] == "review_required")
    assert review["line"] is None and review["import"] is None and review["target"] is None


def test_a_snapshot_with_no_rules_exits_zero_and_lists_the_governing_decisions(tmp_path, capsys, no_network):
    capsys.readouterr()
    code = cli.main(["check", str(ROOT / "fixtures" / "impact" / "vinc.json"), "--repo-dir", str(tmp_path), "--changed", "reports/export.py"])
    r = json.loads(capsys.readouterr().out)
    assert code == 0 and r["violations"] == [] and r["rules"] == []
    assert "decision:demo-report-exports-finish-in-time" in {g["decision"] for g in r["governing"]}


def test_text_output_names_each_violation(capsys, no_network):
    code, out = cli_run(capsys, "--changed", *CHANGED, "--format", "text")
    assert code == 1
    assert "src/shop/ui/view.py:4  decision:ui-does-not-import-db  imports_forbidden: src/shop/ui/** must not import src/shop/db/**" in out
    assert "violations: 4" in out and "cannot be judged: 2" in out


def git_repo(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    shutil.copytree(REPO, root)
    subprocess.run([*GIT, "init", "-q", "-b", "main", str(root)], check=True)
    subprocess.run([*GIT, "-C", str(root), "add", "-A"], check=True)
    subprocess.run([*GIT, "-C", str(root), "commit", "-q", "-m", "base"], check=True)
    (root / "src" / "shop" / "ui" / "late.py").write_text("from shop.db.models import Order\n", encoding="utf-8")
    (root / "src" / "payments" / "charge.py").write_text("def charge(amount):\n    return amount * 1\n", encoding="utf-8")
    subprocess.run([*GIT, "-C", str(root), "add", "-A"], check=True)
    subprocess.run([*GIT, "-C", str(root), "commit", "-q", "-m", "change"], check=True)
    return root


@pytest.mark.skipif(shutil.which("git") is None, reason="needs git")
def test_base_lists_the_changed_files_with_git(tmp_path, capsys, no_network):
    root = git_repo(tmp_path)
    capsys.readouterr()
    code = cli.main(["check", str(SNAPSHOT), "--repo-dir", str(root), "--base", "main~1", "--reviewers", "@shop/payments"])
    r = json.loads(capsys.readouterr().out)
    assert code == 1
    assert r["base"] == "main~1" and r["changed"] == ["src/payments/charge.py", "src/shop/ui/late.py"]
    assert rows(r["violations"]) == {("src/shop/ui/late.py", 1, "decision:ui-does-not-import-db", "imports_forbidden")}


@pytest.mark.skipif(shutil.which("git") is None, reason="needs git")
def test_base_ignores_the_repositorys_own_hooks_and_fsmonitor(tmp_path, capsys, no_network):
    root = git_repo(tmp_path)
    marker = tmp_path / "ran"
    hook = tmp_path / "monitor.sh"
    hook.write_text(f"#!/bin/sh\ntouch {marker}\n", encoding="utf-8")
    hook.chmod(0o755)
    subprocess.run(["git", "-C", str(root), "config", "core.fsmonitor", str(hook)], check=True)
    subprocess.run(["git", "-C", str(root), "config", "core.pager", f"touch {marker}"], check=True)
    capsys.readouterr()
    cli.main(["check", str(SNAPSHOT), "--repo-dir", str(root), "--base", "main~1"])
    assert not marker.exists()


@pytest.mark.parametrize("ref", ["-p", "--output=/tmp/x", " "])
def test_base_refuses_a_ref_that_looks_like_an_option(ref, capsys):
    with pytest.raises(SystemExit) as e:
        cli.main(["check", str(SNAPSHOT), "--repo-dir", str(REPO), f"--base={ref}"])
    assert e.value.code == 2
    assert "--base must name a commit" in capsys.readouterr().err


@pytest.mark.parametrize("path", ["/etc/passwd", "../outside.py", ".."])
def test_a_changed_path_outside_the_repository_is_refused(path, capsys):
    with pytest.raises(SystemExit) as e:
        cli.main(["check", str(SNAPSHOT), "--repo-dir", str(REPO), "--changed", path])
    assert e.value.code == 2


def test_repository_code_is_parsed_and_never_run(tmp_path, capsys, no_network):
    root = tmp_path / "repo"
    shutil.copytree(REPO, root)
    marker = tmp_path / "ran"
    (root / "src" / "shop" / "ui" / "boom.py").write_text(f"open({str(marker)!r}, 'w').close()\nfrom shop.db import models\n", encoding="utf-8")
    (root / "src" / "shop" / "db" / "__init__.py").write_text(f"open({str(marker)!r}, 'w').close()\n", encoding="utf-8")
    capsys.readouterr()
    code = cli.main(["check", str(SNAPSHOT), "--repo-dir", str(root), "--changed", "src/shop/ui/boom.py"])
    assert code == 1 and not marker.exists()


def test_a_symbolic_link_out_of_the_repository_is_unresolved(tmp_path, capsys, no_network):
    root = tmp_path / "repo"
    shutil.copytree(REPO, root)
    (tmp_path / "elsewhere.py").write_text("import os\n", encoding="utf-8")
    os.symlink(tmp_path / "elsewhere.py", root / "src" / "shop" / "ui" / "linked.py")
    found = imports.read(imports.Repo(root), "src/shop/ui/linked.py")
    assert [(i.resolution, i.why) for i in found] == [("unresolved", "the file lies outside the repository")]


@pytest.mark.parametrize("value,reason", [
    ({"paths": ["src/**"]}, "exactly the keys paths and reviewers"),
    ({"paths": [], "reviewers": ["@a"]}, "non-empty list of path globs"),
    ({"paths": ["src/[ab]/**"], "reviewers": ["@a"]}, "character ranges"),
    ({"paths": ["!src/**"], "reviewers": ["@a"]}, "negates"),
    ({"paths": ["src/**"], "reviewers": ["a b"]}, "handles"),
])
def test_a_malformed_review_rule_is_a_problem_not_a_rule(value, reason):
    parsed = rules.parse({"review_required": value})
    assert parsed.rules == () and parsed.problems[0].kind == "review_required" and reason in parsed.problems[0].reason


def test_a_malformed_import_rule_is_reported_and_does_not_fail_the_check(tmp_path, capsys, no_network):
    snap = json.loads(SNAPSHOT.read_text(encoding="utf-8"))
    for n in snap["nodes"]:
        if n["id"] == "decision:ui-does-not-import-db":
            n["props"]["rule"] = {"imports_forbidden": {"from": ["src/shop/ui/**"]}}
    path = tmp_path / "snap.json"
    path.write_text(json.dumps(snap), encoding="utf-8")
    capsys.readouterr()
    code = cli.main(["check", str(path), "--repo-dir", str(REPO), "--changed", "src/shop/ui/view.py"])
    r = json.loads(capsys.readouterr().out)
    assert code == 0
    assert r["rule_problems"] == [{"decision": "decision:ui-does-not-import-db", "rule": "imports_forbidden",
                                   "problem": "imports_forbidden must be a mapping with exactly the keys from and to"}]


def judge_import(tmp_path: Path, files: dict[str, str], rel: str, rule: dict) -> list[tuple]:
    for name, text in files.items():
        (tmp_path / name).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / name).write_text(text, encoding="utf-8")
    (parsed_rule,) = rules.parse({"imports_forbidden": rule}).rules
    out = []
    for i in imports.read(imports.Repo(tmp_path), rel):
        verdict, _ = rules.verdict(parsed_rule, {"file": rel, "specifier": i.specifier, "resolution": i.resolution,
                                                  "target": i.target, "why": i.why}, False)
        out.append((i.line, i.specifier, i.resolution, i.target, verdict))
    return out


def test_script_specifiers_resolve_through_extensions_index_files_and_compiled_names(tmp_path):
    files = {"a/x.ts": 'export * from "../b";\nimport "../c/thing.js";\nconst y = require(`../d`);\nimport z = require("../e/f");\n',
             "b/index.tsx": "", "c/thing.ts": "", "d.mjs": "", "e/f.json": ""}
    got = judge_import(tmp_path, files, "a/x.ts", {"from": ["a/**"], "to": ["b/**", "c/**", "d.mjs", "e/**"]})
    assert got == [(1, "../b", "repository", "b/index.tsx", "violated"), (2, "../c/thing.js", "repository", "c/thing.ts", "violated"),
                   (3, "../d", "repository", "d.mjs", "violated"), (4, "../e/f", "repository", "e/f.json", "violated")]


def test_a_bare_package_is_external_unless_a_to_glob_names_node_modules(tmp_path):
    files = {"a/x.js": 'const l = require("lodash/fp");\nimport fs from "node:fs";\n'}
    assert [g[2:] for g in judge_import(tmp_path, files, "a/x.js", {"from": ["a/**"], "to": ["lodash", "b/**"]})] == [
        ("external", "node_modules/lodash/fp", "not_violated"), ("external", "node_modules/node:fs", "not_violated")]
    assert [g[4] for g in judge_import(tmp_path, files, "a/x.js", {"from": ["a/**"], "to": ["node_modules/lodash/**"]})] == [
        "violated", "not_violated"]


def test_tsconfig_paths_and_base_url_resolve_aliases(tmp_path):
    files = {"tsconfig.json": '{\n  // comment\n  "compilerOptions": {"baseUrl": "src", "paths": {"@db/*": ["db/*"],},},\n}\n',
             "src/ui/x.ts": 'import { q } from "@db/client";\nimport { r } from "lib/thing";\n', "src/db/client.ts": "", "src/lib/thing.ts": ""}
    got = judge_import(tmp_path, files, "src/ui/x.ts", {"from": ["src/ui/**"], "to": ["src/db/**"]})
    assert got == [(1, "@db/client", "repository", "src/db/client.ts", "violated"), (2, "lib/thing", "repository", "src/lib/thing.ts", "not_violated")]


def test_a_relative_specifier_that_names_no_file_is_unresolved(tmp_path):
    got = judge_import(tmp_path, {"a/x.ts": 'import "./missing";\nimport "../../up";\n'}, "a/x.ts", {"from": ["a/**"], "to": ["b/**"]})
    assert [(g[0], g[2], g[4]) for g in got] == [(1, "unresolved", "unresolved"), (2, "unresolved", "unresolved")]


def test_python_literal_dynamic_imports_resolve_and_broken_files_are_unresolved(tmp_path):
    files = {"pkg/__init__.py": "", "pkg/db.py": "", "pkg/ui.py": 'import importlib\nimportlib.import_module("pkg.db")\n__import__(name)\n',
             "pkg/bad.py": "def (:\n", "top.py": "from ... import x\n"}
    rule = {"from": ["pkg/**", "top.py"], "to": ["pkg/db.py"]}
    assert judge_import(tmp_path, files, "pkg/ui.py", rule) == [
        (1, "import importlib", "external", None, "not_violated"), (2, "pkg.db", "repository", "pkg/db.py", "violated"),
        (3, "__import__() with a computed name", "unresolved", None, "unresolved")]
    assert [g[2:] for g in judge_import(tmp_path, {}, "pkg/bad.py", rule)] == [("unresolved", None, "unresolved")]
    assert [g[2:] for g in judge_import(tmp_path, {}, "top.py", rule)] == [("unresolved", None, "unresolved")]


def test_a_module_missing_from_a_repository_package_is_unresolved(tmp_path):
    files = {"src/pkg/__init__.py": "", "src/pkg/ui.py": "import pkg.gone\nimport requests\nimport packaging.version\nimport ns.mod\n",
             "packaging/README.md": "", "ns/mod.py": ""}
    got = judge_import(tmp_path, files, "src/pkg/ui.py", {"from": ["src/pkg/**"], "to": ["packaging/**", "ns/**"]})
    assert [(g[1], g[2], g[4]) for g in got] == [("import pkg.gone", "unresolved", "unresolved"), ("import requests", "external", "not_violated"),
                                                 ("import packaging.version", "external", "not_violated"), ("import ns.mod", "repository", "violated")]


def test_scanner_skips_regexes_after_operators_and_reads_division(tmp_path):
    text = 'const a = b / c; const r = /"/g; const s = x.import("y");\nconst t = "it\'s"; import d from "./d";\n'
    refs = imports.script_refs(imports.tokens(text))
    assert refs == [(2, "./d", "import")]


def test_audit_ignores_review_and_import_rules(tmp_path, capsys, no_network):
    snap = json.loads((ROOT / "fixtures" / "audit" / "vinc.json").read_text(encoding="utf-8"))
    for n in snap["nodes"]:
        if n["id"] == "decision:dependencies-are-pinned-by-a-lockfile":
            n["props"]["rule"] = [{"review_required": {"paths": ["**"], "reviewers": ["@a"]}},
                                  {"imports_forbidden": {"from": ["a/**"], "to": ["b/**"]}}]
    path = tmp_path / "snap.json"
    path.write_text(json.dumps(snap), encoding="utf-8")
    capsys.readouterr()
    assert cli.main(["audit", str(path), str(ROOT / "fixtures/audit/demo-lockfile.json"), "--repo", "Demo",
                     "--osv-cache", str(ROOT / "fixtures/audit/osv-cache.json")]) == 0
    assert json.loads(capsys.readouterr().out)["violations"] == 3


@pytest.mark.parametrize("fmt,suffix", [("mermaid", "md"), ("html", "html")])
def test_the_check_fixture_renders_to_the_committed_golden_output(fmt, suffix, capsys, no_network):
    _, out = cli_run(capsys, "--changed", *CHANGED, "--reviewers", "bob", "--format", fmt)
    golden = GOLDEN / f"check.{suffix}"
    if os.environ.get("DECISIS_GOLDEN") == "write":
        golden.write_text(out, encoding="utf-8")
    assert out == golden.read_text(encoding="utf-8")


def test_the_check_module_runs_without_the_cli(no_network):
    r = check.run(co.load(SNAPSHOT.read_text(encoding="utf-8")), ["./src/payments/charge.py"], REPO, ["@alice"])
    assert r["changed"] == ["src/payments/charge.py"] and r["violations"] == []
