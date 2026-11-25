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
    computed = [u for u in r["unresolved"] if "computed at run time" in u["why"]]
    assert rows(computed) == {("src/shop/ui/view.py", 10, "decision:ui-does-not-import-db", "imports_forbidden"),
                              ("web/src/ui/page.ts", 9, "decision:ui-does-not-import-db", "imports_forbidden")}
    assert r["summary"]["unresolved"] == 3


def test_comments_strings_regexes_and_templates_are_not_read_as_imports_but_a_text_search_flags_them(capsys, no_network):
    _, r = report(capsys, "--changed", "web/src/ui/page.ts")
    assert [(i["line"], i["import"], i["resolution"]) for i in r["imports"]] == [
        (1, "../db/client", "repository"), (2, "react", "external"), (3, "../db/secret", "unresolved"),
        (9, "import() with a computed specifier", "unresolved")]
    assert "the scanner and the text search disagree" in r["imports"][2]["why"]


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
                      "violations", "unresolved", "waived", "summary", "impact", "today"}
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
    assert "violations: 4" in out and "cannot be judged: 3" in out


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
                                                  "target": i.target, "why": i.why, "also": i.also}, False)
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
    _, out = cli_run(capsys, "--changed", *CHANGED, "--reviewers", "bob", "--format", fmt, "--today", "2026-11-25")
    golden = GOLDEN / f"check.{suffix}"
    if os.environ.get("DECISIS_GOLDEN") == "write":
        golden.write_text(out, encoding="utf-8")
    assert out == golden.read_text(encoding="utf-8")


def test_the_check_module_runs_without_the_cli(no_network):
    r = check.run(co.load(SNAPSHOT.read_text(encoding="utf-8")), ["./src/payments/charge.py"], REPO, ["@alice"])
    assert r["changed"] == ["src/payments/charge.py"] and r["violations"] == []


JSX_CASES = {
    "a closing tag then require": 'const el = <b>hi</b>; const c = require("../db/client");\n',
    "an import inside a JSX attribute": '<Suspense fallback={<p>Loading</p>}><Route load={() => import("../db/client")} /></Suspense>\n',
    "a glob in JSX text": '<p>Files under src/* are built</p>\nexport { q } from "../db/client";\n',
    "a fragment with expressions": 'const a = <><A b="x" c={`${y}`}>t {/* c */} {n / 2}</A></>; require("../db/client");\n',
    "a generic arrow": 'const f = <T,>(x: T) => x / 2; import "../db/client";\n',
}


@pytest.mark.parametrize("ext", [".tsx", ".jsx", ".js"])
@pytest.mark.parametrize("case", sorted(JSX_CASES))
def test_jsx_is_read_as_jsx_and_the_import_after_it_is_judged(tmp_path, case, ext):
    got = judge_import(tmp_path, {"db/client.ts": "", "a/x" + ext: JSX_CASES[case]}, "a/x" + ext, {"from": ["a/**"], "to": ["db/**"]})
    assert ("../db/client", "repository", "db/client.ts", "violated") in [g[1:] for g in got]
    assert all(g[2] != "unresolved" for g in got), got


@pytest.mark.parametrize("text", ['i++ / 2; import { q } from "../db/client";\n', 'let b = a-- / 2; import "../db/client";\n',
                                  'if (a < b && c > d) { x = y / 2 } import "../db/client";\n', 'x = (a) / 2 / b; import "../db/client";\n'])
def test_division_after_a_value_is_not_read_as_a_regex(tmp_path, text):
    got = judge_import(tmp_path, {"db/client.ts": "", "a/x.ts": text}, "a/x.ts", {"from": ["a/**"], "to": ["db/**"]})
    assert [g[1:] for g in got] == [("../db/client", "repository", "db/client.ts", "violated")]


@pytest.mark.parametrize("text,reason", [
    ("const a = `oops\nimport { q } from '../db/client';\n", "template literal"),
    ("/* oops\nimport { q } from '../db/client';\n", "comment"),
    ("const s = 'oops\nimport { q } from '../db/client';\n", "string"),
    ("const r = /oops\nimport { q } from '../db/client';\n", "regular expression"),
    ("const el = <div>\nimport { q } from '../db/client';\n", "JSX element"),
])
@pytest.mark.parametrize("ext", [".ts", ".tsx"])
def test_a_file_the_scanner_cannot_finish_is_unresolved_and_its_imports_still_count(tmp_path, text, reason, ext):
    if reason == "JSX element" and ext == ".ts":
        return
    got = judge_import(tmp_path, {"db/client.ts": "", "a/x" + ext: text}, "a/x" + ext, {"from": ["a/**"], "to": ["db/**"]})
    found = imports.read(imports.Repo(tmp_path), "a/x" + ext)
    assert any(i.line is None and "cannot be scanned to its end" in i.why and reason in i.why for i in found), found
    assert (2, "../db/client", "unresolved", "db/client.ts", "unresolved") in got


def test_a_text_search_hit_that_names_no_forbidden_file_is_not_violated(tmp_path):
    got = judge_import(tmp_path, {"b/ok.ts": "", "a/x.ts": '// import "../b/ok";\n'}, "a/x.ts", {"from": ["a/**"], "to": ["db/**"]})
    assert got == [(1, "../b/ok", "unresolved", "b/ok.ts", "not_violated")]


def test_python_imports_resolve_from_the_files_own_package_root(tmp_path):
    files = {"backend/app/__init__.py": "", "backend/app/db/__init__.py": "", "backend/app/db/models.py": "", "backend/app/ui/__init__.py": "",
             "backend/app/ui/v.py": "from app.db import models\nimport app.db.models\n", "tools/run.py": "import helper\n", "tools/helper.py": ""}
    got = judge_import(tmp_path, files, "backend/app/ui/v.py", {"from": ["backend/app/ui/**"], "to": ["backend/app/db/**"]})
    assert [g[2:] for g in got] == [("repository", "backend/app/db/models.py", "violated")] * 2
    assert [g[2:] for g in judge_import(tmp_path, {}, "tools/run.py", {"from": ["tools/**"], "to": ["tools/helper.py"]})] == [
        ("repository", "tools/helper.py", "violated")]


def test_python_imports_resolve_from_the_nearest_project_and_its_src(tmp_path):
    files = {"libs/client/pyproject.toml": "", "libs/client/src/client/__init__.py": "", "libs/client/src/client/db.py": "",
             "libs/client/tests/test_db.py": "from client import db\n"}
    got = judge_import(tmp_path, files, "libs/client/tests/test_db.py", {"from": ["libs/client/tests/**"], "to": ["libs/client/src/client/db.py"]})
    assert [g[2:] for g in got] == [("repository", "libs/client/src/client/db.py", "violated")]


def test_a_python_name_found_elsewhere_in_the_repository_is_unresolved_not_external(tmp_path):
    files = {"services/api/app/__init__.py": "", "services/api/app/db.py": "", "web/ui.py": "import app.db\nimport json\nimport requests\n",
             ".venv/lib/site-packages/requests/__init__.py": ""}
    got = judge_import(tmp_path, files, "web/ui.py", {"from": ["web/**"], "to": ["services/**"]})
    assert [(g[1], g[2], g[4]) for g in got] == [("import app.db", "unresolved", "unresolved"), ("import json", "external", "not_violated"),
                                                 ("import requests", "external", "not_violated")]


TS_RULE = {"from": ["web/src/ui/**"], "to": ["web/src/db/**"]}
TS_BASE = {"web/src/db/client.ts": "", "web/src/ui/x.ts": 'import { q } from "@db/client";\n'}


@pytest.mark.parametrize("configs", [
    {"web/tsconfig.json": '{"compilerOptions": {"baseUrl": "src", "paths": {"@db/*": ["db/*"]}}}'},
    {"web/jsconfig.json": '{"compilerOptions": {"paths": {"@db/*": ["./src/db/*"]}}}'},
    {"web/tsconfig.json": '{"extends": "../configs/base"}', "configs/base.json": '{"compilerOptions": {"baseUrl": "../web/src", "paths": {"@db/*": ["db/*"]}}}'},
    {"web/tsconfig.json": '{"extends": ["./a.json", "./b.json"]}', "web/a.json": '{"compilerOptions": {"baseUrl": "src"}}',
     "web/b.json": '{"compilerOptions": {"paths": {"@db/*": ["db/*"]}}}'},
])
def test_the_nearest_config_and_its_extends_chain_resolve_aliases(tmp_path, configs):
    got = judge_import(tmp_path, {**TS_BASE, **configs}, "web/src/ui/x.ts", TS_RULE)
    assert got == [(1, "@db/client", "repository", "web/src/db/client.ts", "violated")]


def test_a_paths_match_that_names_no_file_is_unresolved(tmp_path):
    files = {"web/src/ui/x.ts": 'import { q } from "@db/gone";\n', "web/tsconfig.json": '{"compilerOptions": {"paths": {"@db/*": ["src/db/*"]}}}'}
    assert [g[2:] for g in judge_import(tmp_path, files, "web/src/ui/x.ts", TS_RULE)] == [("unresolved", None, "unresolved")]


@pytest.mark.parametrize("configs,note", [
    ({"web/tsconfig.json": '{"extends": "@tsconfig/node20/tsconfig.json"}'}, "is not a file in the repository"),
    ({"web/tsconfig.json": '{"extends": "./a.json"}', "web/a.json": '{"extends": "./tsconfig.json"}'}, "cycle"),
    ({"web/tsconfig.json": '{"compilerOptions": '}, "cannot be read as JSON"),
])
def test_a_config_that_cannot_be_followed_is_unresolved(tmp_path, configs, note):
    got = judge_import(tmp_path, {**TS_BASE, **configs}, "web/src/ui/x.ts", TS_RULE)
    found = imports.read(imports.Repo(tmp_path), "web/src/ui/x.ts")
    assert any(i.line is None and note in i.why for i in found), found
    assert "unresolved" in [g[4] for g in got]


def test_fail_on_unresolved_turns_an_unresolved_import_into_a_failure(tmp_path, capsys, no_network):
    root = tmp_path / "repo"
    shutil.copytree(REPO, root)
    (root / "web" / "src" / "ui" / "lazy.ts").write_text("export const load = (name: string) => import(name);\n", encoding="utf-8")
    args = ["check", str(SNAPSHOT), "--repo-dir", str(root), "--changed", "web/src/ui/lazy.ts"]
    capsys.readouterr()
    assert cli.main(args) == 0
    r = json.loads(capsys.readouterr().out)
    assert r["violations"] == [] and len(r["unresolved"]) == 1
    assert cli.main([*args, "--fail-on-unresolved"]) == 1


GO_VIEW = "svc/internal/ui/view.go"
RUST_UI = "crates/shop/src/ui.rs"
FORBIDDEN = "decision:ui-does-not-import-db"


def listed(r: dict, file: str) -> list[tuple]:
    return [(i["line"], i["import"], i["resolution"], i["target"]) for i in r["imports"] if i["file"] == file]


def test_go_single_and_grouped_imports_with_alias_dot_and_blank_names_resolve_through_go_mod(capsys, no_network):
    code, r = report(capsys, "--changed", GO_VIEW)
    assert code == 1
    mod = "example.com/shop/svc/internal/"
    assert [i for i in listed(r, GO_VIEW) if i[1] != mod + "ui" and "secret" not in i[1] and "raw" not in i[1]] == [
        (4, mod + "db", "repository", "svc/internal/db/"), (7, "fmt", "external", None),
        (8, mod + "db/models", "repository", "svc/internal/db/models/"), (9, mod + "api", "repository", "svc/internal/api/"),
        (10, mod + "db/driver", "repository", "svc/internal/db/driver/"), (11, mod + "gone", "unresolved", None),
        (12, "github.com/lib/pq", "external", None)]
    assert rows(r["violations"]) == {(GO_VIEW, line, FORBIDDEN, "imports_forbidden") for line in (4, 8, 10)}
    gone = next(u for u in r["unresolved"] if u["line"] == 11)
    assert "under the module path example.com/shop/svc of svc/go.mod, but svc/internal/gone is not a directory" in gone["why"]


def test_rust_use_mod_and_workspace_crate_paths_resolve_from_the_crate_root(capsys, no_network):
    code, r = report(capsys, "--changed", RUST_UI)
    assert code == 1
    assert [i for i in listed(r, RUST_UI) if i[2] != "unresolved"] == [
        (2, "mod widgets", "repository", "crates/shop/src/ui/widgets.rs"),
        (4, "use crate::db::models::Order", "repository", "crates/shop/src/db/models.rs"),
        (5, "use super::db", "repository", "crates/shop/src/db/mod.rs"),
        (5, "use super::db::models", "repository", "crates/shop/src/db/models.rs"),
        (6, "use shop_db::pool::Pool", "repository", "crates/shop-db/src/pool.rs"),
        (7, "use std::collections::HashMap", "external", None),
        (8, "use crate::api::Client", "repository", "crates/shop/src/api.rs"),
        (18, "use crate::db::models::Total", "repository", "crates/shop/src/db/models.rs")]
    assert {(v["line"], v["import"]) for v in r["violations"]} == {
        (4, "use crate::db::models::Order"), (5, "use super::db"), (5, "use super::db::models"), (6, "use shop_db::pool::Pool"),
        (18, "use crate::db::models::Total")}


def test_go_and_rust_comments_and_strings_are_not_read_as_imports_but_a_text_search_flags_them(capsys, no_network):
    _, r = report(capsys, "--changed", GO_VIEW, RUST_UI)
    disagree = [(u["file"], u["line"], u["import"]) for u in r["unresolved"] if "the scanner and the text search disagree" in u["why"]]
    assert disagree == [(RUST_UI, 10, "use crate::db::secret"), (RUST_UI, 11, "use crate::db::raw"),
                        (GO_VIEW, 15, "example.com/shop/svc/internal/db/secret"), (GO_VIEW, 16, "example.com/shop/svc/internal/db/raw")]
    canonical = [i for i in r["imports"] if i["file"] == GO_VIEW and i["line"] == 2]
    assert [(i["resolution"], i["target"]) for i in canonical] == [("unresolved", "svc/internal/ui/")]
    assert all(v["line"] != 2 for v in r["violations"] + r["unresolved"] if v["file"] == GO_VIEW)
    assert r["summary"] == {"violated": 8, "unresolved": 5, "waived": 0, "not_violated": 7}


GO_MOD = {"go.mod": "module example.com/m // the module\n\ngo 1.22\n", "db/a.go": "package db\n", "db/sub/b.go": "package sub\n"}


def test_a_go_package_matches_by_its_directory_or_a_go_file_directly_in_it(tmp_path):
    files = {**GO_MOD, "ui/x.go": 'package ui\nimport m "example.com/m/db"\nimport . "example.com/m/db/sub"\nimport _ "example.com/m"\n'}
    got = judge_import(tmp_path, files, "ui/x.go", {"from": ["ui/**"], "to": ["db/*.go"]})
    assert got == [(2, "example.com/m/db", "repository", "db/", "violated"), (3, "example.com/m/db/sub", "repository", "db/sub/", "not_violated"),
                   (4, "example.com/m", "repository", ".", "not_violated")]
    assert [g[4] for g in judge_import(tmp_path, {}, "ui/x.go", {"from": ["ui/**"], "to": ["db"]})] == ["violated", "violated", "not_violated"]
    assert [g[4] for g in judge_import(tmp_path, {}, "ui/x.go", {"from": ["ui/**"], "to": ["db/sub/"]})] == ["not_violated", "violated", "not_violated"]


def test_a_go_import_outside_the_module_is_never_a_violation(tmp_path):
    files = {**GO_MOD, "ui/x.go": 'package ui\n\nimport (\n\t"fmt"\n\tpq "github.com/lib/pq"\n\t"example.com/mother/db"\n)\n',
             "github.com/lib/pq/pq.go": ""}
    got = judge_import(tmp_path, files, "ui/x.go", {"from": ["ui/**"], "to": ["**"]})
    assert [g[1:] for g in got] == [("fmt", "external", None, "not_violated"), ("github.com/lib/pq", "external", None, "not_violated"),
                                    ("example.com/mother/db", "external", None, "not_violated")]


@pytest.mark.parametrize("files,rel,expected", [
    ({"ui/x.go": 'package ui\nimport ("fmt"; "example.com/m/db")\n'}, "ui/x.go",
     [(2, "example.com/m/db", "unresolved"), (2, "fmt", "external")]),
    ({**GO_MOD, "ui/x.go": 'package ui\nimport "example.com/m/db/../db"\n'}, "ui/x.go", [(2, "example.com/m/db/../db", "unresolved")]),
    ({**GO_MOD, "ui/x.go": 'package ui\nimport "example.com/m/gone"\n'}, "ui/x.go", [(2, "example.com/m/gone", "unresolved")]),
    ({"go.mod": "go 1.22\n", "ui/x.go": 'package ui\nimport "example.com/m/db"\n'}, "ui/x.go", [(2, "example.com/m/db", "unresolved")]),
    ({**GO_MOD, "ui/x.go": 'package ui\nimport "example.com/m/\\x64b"\n'}, "ui/x.go",
     [(2, "example.com/m/\\x64b", "unresolved"), (2, "import with a path that cannot be read", "unresolved")]),
])
def test_a_go_import_that_cannot_be_placed_is_unresolved(tmp_path, files, rel, expected):
    got = judge_import(tmp_path, files, rel, {"from": ["ui/**"], "to": ["db/**"]})
    assert [(g[0], g[1], g[2]) for g in got] == expected
    assert all(g[4] == ("not_violated" if g[2] == "external" else "unresolved") for g in got)


@pytest.mark.parametrize("gomod", [
    "module (\n\texample.com/m\n)\n\ngo 1.22\n",
    "// the module\nmodule example.com/m // trailing\n",
    'module "example.com/m"\n',
    "module `example.com/m`\n",
])
def test_every_form_of_the_go_mod_module_directive_gives_the_module_path(tmp_path, gomod):
    files = {**GO_MOD, "go.mod": gomod, "ui/x.go": 'package ui\nimport "example.com/m/db"\n'}
    assert judge_import(tmp_path, files, "ui/x.go", {"from": ["ui/**"], "to": ["db/**"]}) == [(2, "example.com/m/db", "repository", "db/", "violated")]


@pytest.mark.parametrize("gomod", ["module (\n)\n", 'module "example.com/m//x"\n', "module (\n\texample.com/m\n", "go 1.22\n"])
def test_a_go_mod_module_directive_that_cannot_be_read_leaves_imports_unresolved_not_external(tmp_path, gomod):
    files = {**GO_MOD, "go.mod": gomod, "ui/x.go": 'package ui\nimport "example.com/m/db"\n'}
    assert judge_import(tmp_path, files, "ui/x.go", {"from": ["ui/**"], "to": ["db/**"]}) == [(2, "example.com/m/db", "unresolved", None, "unresolved")]
    assert "has no module line that can be read" in imports.read(imports.Repo(tmp_path), "ui/x.go")[0].why


@pytest.mark.parametrize("text,reason", [
    ('package ui\nimport "example.com/m/db"\nvar s = `oops\nimport "example.com/m/db/sub"\n', "raw string"),
    ('package ui\nimport "example.com/m/db"\n/* oops\nimport "example.com/m/db/sub"\n', "comment"),
    ('package ui\nimport "example.com/m/db"\nvar s = "oops\nimport "example.com/m/db/sub"\n', "string"),
])
def test_a_go_file_the_scanner_cannot_finish_is_unresolved_and_its_imports_still_count(tmp_path, text, reason):
    got = judge_import(tmp_path, {**GO_MOD, "ui/x.go": text}, "ui/x.go", {"from": ["ui/**"], "to": ["db/**"]})
    found = imports.read(imports.Repo(tmp_path), "ui/x.go")
    assert any(i.line is None and "cannot be scanned to its end" in i.why and reason in i.why for i in found), found
    assert (2, "example.com/m/db", "repository", "db/", "violated") in got
    assert (4, "example.com/m/db/sub", "unresolved", "db/sub/", "unresolved") in got


def test_a_go_text_search_hit_outside_the_module_is_not_listed(tmp_path):
    files = {**GO_MOD, "ui/x.go": 'package ui // import "example.com/m/ui"\n\n// import "fmt"\nvar s = `import "example.com/m/db"`\n', "ui/y.go": ""}
    got = judge_import(tmp_path, files, "ui/x.go", {"from": ["ui/**"], "to": ["db/**"]})
    assert got == [(1, "example.com/m/ui", "unresolved", "ui/", "not_violated"), (4, "example.com/m/db", "unresolved", "db/", "unresolved")]


CARGO = {"Cargo.toml": '[package]\nname = "app"\n\n[dependencies]\nstore = { package = "shop-db", path = "libs/db" }\nserde = "1"\n',
         "src/lib.rs": "pub mod db;\npub mod ui;\npub mod x;\nmod a {\n    mod b;\n}\npub enum Error {}\npub use db::models::Order as Ordered;\npub use x::*;\n",
         "src/db.rs": "pub mod models;\npub struct Pool;\n", "src/db/models.rs": "pub struct Order;\npub struct Total;\n", "src/a/b.rs": "pub struct Z;\n",
         "src/x.rs": "pub fn helper() {}\n", "src/ui/helpers.rs": "pub struct Button;\n", "libs/db/Cargo.toml": '[package]\nname = "shop-db"\n',
         "libs/db/src/lib.rs": "pub mod pool;\n", "libs/db/src/pool.rs": "pub struct Pool;\n", "cli/Cargo.toml": '[package]\nname = "cli"\n',
         "cli/src/main.rs": "fn main() {}\n"}
RUST_RULE = {"from": ["src/ui.rs", "src/ui/**", "tests/**"], "to": ["src/db/**", "libs/**"]}
CRATE = {"Cargo.toml": '[package]\nname = "p"\n', "src/lib.rs": "pub mod db;\npub mod ui;\n", "src/db.rs": "pub struct Pool;\n"}


def test_rust_paths_read_from_crate_self_super_child_and_inline_modules(tmp_path):
    text = ("use crate::{db::{self, models::Order}, x::*};\nuse super::db as data;\nuse self::helpers::Button;\nuse helpers::Button as B;\n"
            "mod helpers;\nmod tests {\n    use super::super::db;\n    use super::helpers;\n}\nuse crate::Error;\nuse crate::Ordered;\nuse crate::helper;\n")
    got = judge_import(tmp_path, {**CARGO, "src/ui.rs": text}, "src/ui.rs", RUST_RULE)
    assert got == [
        (1, "use crate::db", "repository", "src/db.rs", "violated"), (1, "use crate::db::models::Order", "repository", "src/db/models.rs", "violated"),
        (1, "use crate::x", "repository", "src/x.rs", "not_violated"), (2, "use super::db", "repository", "src/db.rs", "violated"),
        (3, "use self::helpers::Button", "repository", "src/ui/helpers.rs", "not_violated"),
        (4, "use helpers::Button", "repository", "src/ui/helpers.rs", "not_violated"), (5, "mod helpers", "repository", "src/ui/helpers.rs", "not_violated"),
        (7, "use super::super::db", "repository", "src/db.rs", "violated"), (8, "use super::helpers", "repository", "src/ui/helpers.rs", "not_violated"),
        (10, "use crate::Error", "repository", "src/lib.rs", "not_violated"), (11, "use crate::Ordered", "repository", "src/db/models.rs", "violated"),
        (12, "use crate::helper", "repository", "src/x.rs", "not_violated")]


def test_a_rust_module_matches_the_same_rule_in_either_layout(tmp_path):
    for db in ("src/db.rs", "src/db/mod.rs"):
        root = tmp_path / str(len(list(tmp_path.iterdir())))
        files = {"Cargo.toml": '[package]\nname = "p"\n', "src/lib.rs": "pub mod db;\npub mod ui;\n", db: "pub struct Pool;\n",
                 "src/ui.rs": "use crate::db::Pool;\n"}
        got = judge_import(root, files, "src/ui.rs", {"from": ["src/ui.rs"], "to": ["src/db/**"]})
        assert [(g[3], g[4]) for g in got] == [(db, "violated")]


def test_rust_paths_into_other_crates_of_the_repository_resolve_inside_them(tmp_path):
    text = "use ::store::pool::Pool;\nuse shop_db::pool;\nuse app::db::models;\nuse serde::Serialize;\nuse cli::run;\nextern crate shop_db;\n"
    got = judge_import(tmp_path, {**CARGO, "src/ui.rs": text}, "src/ui.rs", RUST_RULE)
    assert got == [
        (1, "use ::store::pool::Pool", "repository", "libs/db/src/pool.rs", "violated"), (2, "use shop_db::pool", "repository", "libs/db/src/pool.rs", "violated"),
        (3, "use app::db::models", "repository", "src/db/models.rs", "violated"), (4, "use serde::Serialize", "external", None, "not_violated"),
        (5, "use cli::run", "unresolved", None, "unresolved"), (6, "extern crate shop_db", "repository", "libs/db/src/lib.rs", "violated")]


def test_rust_tests_and_binaries_are_crate_roots_of_their_own(tmp_path):
    files = {**CARGO, "tests/common/mod.rs": "pub fn fixture() {}\n", "tests/it.rs": "mod common;\nuse app::db;\nuse crate::common::fixture;\n",
             "src/bin/tool.rs": "mod helper;\nuse crate::helper::x;\n", "src/bin/helper.rs": "pub fn x() {}\n"}
    assert [g[1:] for g in judge_import(tmp_path, files, "tests/it.rs", RUST_RULE)] == [
        ("mod common", "repository", "tests/common/mod.rs", "not_violated"), ("use app::db", "repository", "src/db.rs", "violated"),
        ("use crate::common::fixture", "repository", "tests/common/mod.rs", "not_violated")]
    assert [g[3] for g in judge_import(tmp_path, {}, "src/bin/tool.rs", {"from": ["src/bin/**"], "to": ["src/db/**"]})] == [
        "src/bin/helper.rs", "src/bin/helper.rs"]


@pytest.mark.parametrize("files,rel,text,why", [
    ({}, "x/y.rs", "use crate::a;\nmod z;\n", "no Cargo.toml lies above the file"),
    ({"Cargo.toml": "[workspace]\nmembers = []\n"}, "src/ui.rs", "use crate::a;\n", "has no [package]"),
    ({"Cargo.toml": "[package\n"}, "src/ui.rs", "use crate::a;\n", "cannot be read as TOML"),
    ({"Cargo.toml": '[package]\nname = "p"\n'}, "src/ui.rs", "use crate::gone::Thing;\n", "has no root file the scanner finds"),
    ({"Cargo.toml": '[package]\nname = "p"\n', "src/lib.rs": ""}, "src/lib.rs", "use super::x;\n", "goes above the crate root"),
    ({"Cargo.toml": '[package]\nname = "p"\n', "src/lib.rs": ""}, "src/orphan.rs", "use super::x;\n", "is not reached from the crate root"),
    ({"Cargo.toml": '[package]\nname = "p"\n', "src/lib.rs": "mod ui;\n"}, "src/ui.rs", "mod missing;\n",
     "none of src/ui/missing.rs, src/ui/missing/mod.rs is in the repository"),
    ({"Cargo.toml": '[package]\nname = "p"\n', "src/lib.rs": "mod ui;\n"}, "src/ui.rs", '#[path = "gone.rs"]\nmod g;\n', "mod g names no file: none of src/gone.rs"),
    ({"Cargo.toml": '[package]\nname = "p"\n', "src/lib.rs": "mod ui;\n"}, "src/ui.rs", "macro_rules! m { () => { use $x; } }\n", "cannot be read"),
    ({"Cargo.toml": '[package]\nname = "p"\n', "src/lib.rs": "mod ui;\n"}, "src/ui.rs", "use crate::dbx::models::T;\n", "dbx is no module, item or use in src/lib.rs"),
    ({"Cargo.toml": '[package]\nname = "p"\n', "src/lib.rs": "mod ui;\n"}, "src/ui.rs", "use crate::Error;\n", "Error is no module, item or use in src/lib.rs"),
    ({**CRATE}, "src/ui.rs", "use crate::db::Gone;\n", "Gone is no module, item or use in src/db.rs"),
    ({"Cargo.toml": '[package]\nname = "p"\n', "src/lib.rs": '#[cfg_attr(unix, path = "a.rs")]\n#[cfg_attr(windows, path = "b.rs")]\nmod sys;\nmod ui;\n',
      "src/a.rs": "pub struct X;\n", "src/b.rs": "pub struct Y;\n"}, "src/ui.rs", "use crate::sys::X;\n", "X is no module, item or use in src/b.rs"),
    ({"Cargo.toml": '[package]\nname = "p"\n', "src/lib.rs": "mod ui;\n"}, "src/ui.rs", "use crate::gone::*;\nuse serde::Serialize;\n", "gone is no module"),
])
def test_a_rust_path_that_cannot_be_placed_is_unresolved(tmp_path, files, rel, text, why):
    got = judge_import(tmp_path, {**files, rel: text}, rel, {"from": ["**"], "to": ["db/**"]})
    found = imports.read(imports.Repo(tmp_path), rel)
    assert got and all(g[2] == "unresolved" and g[4] == "unresolved" for g in got), got
    assert all(why in i.why for i in found), found


@pytest.mark.parametrize("attr", ['#[path = "storage/db.rs"]', '#[cfg_attr(unix, path = "storage/db.rs")]'])
def test_a_rust_module_moved_by_a_path_attribute_is_followed_from_the_crate_root(tmp_path, attr):
    files = {"Cargo.toml": '[package]\nname = "p"\n', "src/lib.rs": f"{attr}\nmod store;\nmod ui;\n",
             "src/storage/db.rs": "pub struct T;\npub mod models {\n    pub struct M;\n}\npub mod inner;\n", "src/storage/inner.rs": "pub struct I;\n",
             "src/ui.rs": "use crate::store::T;\nuse crate::store::models::M;\nuse crate::store::inner::I;\n"}
    assert judge_import(tmp_path, files, "src/ui.rs", {"from": ["src/ui.rs"], "to": ["src/storage/**"]}) == [
        (1, "use crate::store::T", "repository", "src/storage/db.rs", "violated"),
        (2, "use crate::store::models::M", "repository", "src/storage/db.rs", "violated"),
        (3, "use crate::store::inner::I", "repository", "src/storage/inner.rs", "violated")]
    assert judge_import(tmp_path, {}, "src/lib.rs", {"from": ["src/lib.rs"], "to": ["src/storage/**"]})[0] == (
        2, "mod store", "repository", "src/storage/db.rs", "violated")


def test_a_rust_module_file_that_leads_outside_the_repository_is_unresolved(tmp_path):
    root = tmp_path / "repo"
    (tmp_path / "outside.rs").write_text("pub struct Q;\n", encoding="utf-8")
    files = {"Cargo.toml": '[package]\nname = "p"\n', "src/lib.rs": "mod ui;\n", "src/ui.rs": "mod db2;\nuse crate::ui::db2::Q;\nuse self::db2::Q as R;\n"}
    for name, text in files.items():
        (root / name).parent.mkdir(parents=True, exist_ok=True)
        (root / name).write_text(text, encoding="utf-8")
    (root / "src" / "ui").mkdir()
    os.symlink(tmp_path / "outside.rs", root / "src" / "ui" / "db2.rs")
    got = judge_import(root, {}, "src/ui.rs", {"from": ["src/ui.rs"], "to": ["src/ui/db2.rs"]})
    assert [(g[1], g[2], g[4]) for g in got] == [("mod db2", "unresolved", "unresolved"), ("use crate::ui::db2::Q", "unresolved", "unresolved"),
                                                 ("use self::db2::Q", "unresolved", "unresolved")]
    assert all("leads outside the repository" in i.why for i in imports.read(imports.Repo(root), "src/ui.rs"))


def test_rust_names_bound_by_use_and_extern_crate_resolve_to_what_they_bind(tmp_path):
    text = ("use crate::db as data;\nuse data::models::Order;\nuse crate::db;\nuse db::models::Total;\nfn f() {\n    use crate::db::models as m;\n"
            "    use m::Total;\n}\n// use data::models::Total;\nextern crate shop_db as d;\nuse d::pool::Pool;\n")
    got = judge_import(tmp_path, {**CARGO, "src/ui.rs": text}, "src/ui.rs", {"from": ["src/ui.rs"], "to": ["src/db/models.rs", "libs/db/src/pool.rs"]})
    assert got == [
        (1, "use crate::db", "repository", "src/db.rs", "not_violated"), (2, "use data::models::Order", "repository", "src/db/models.rs", "violated"),
        (3, "use crate::db", "repository", "src/db.rs", "not_violated"), (4, "use db::models::Total", "repository", "src/db/models.rs", "violated"),
        (6, "use crate::db::models", "repository", "src/db/models.rs", "violated"), (7, "use m::Total", "repository", "src/db/models.rs", "violated"),
        (9, "use data::models::Total", "unresolved", "src/db/models.rs", "unresolved"),
        (10, "extern crate shop_db", "repository", "libs/db/src/lib.rs", "not_violated"), (11, "use d::pool::Pool", "repository", "libs/db/src/pool.rs", "violated")]


@pytest.mark.parametrize("manifests", [
    {"Cargo.toml": '[package]\nname = "app"\n\n[dependencies]\nstore = { workspace = true, package = "dbc" }\n'},
    {"Cargo.toml": '[package]\nname = "app"\n\n[dependencies]\nstore = { package = "dbc", version = "1" }\n'},
    {"Cargo.toml": '[package]\nname = "app"\n\n[dependencies]\nstore = { workspace = true }\n\n[workspace]\nmembers = ["dbc"]\n\n'
                   '[workspace.dependencies]\nstore = { path = "dbc" }\n'},
    {"Cargo.toml": '[package]\nname = "app"\n\n[target.\'cfg(unix)\'.dependencies]\nstore = { path = "dbc" }\n'},
])
def test_a_renamed_or_inherited_rust_dependency_resolves_into_the_repository_crate(tmp_path, manifests):
    files = {**manifests, "src/lib.rs": "mod ui;\n", "dbc/Cargo.toml": '[package]\nname = "dbc"\n', "dbc/src/lib.rs": "pub mod pool;\n",
             "dbc/src/pool.rs": "pub struct P;\n", "src/ui.rs": "use store::pool::P;\n"}
    assert judge_import(tmp_path, files, "src/ui.rs", {"from": ["src/ui.rs"], "to": ["dbc/**"]}) == [
        (1, "use store::pool::P", "repository", "dbc/src/pool.rs", "violated")]


def test_a_rust_path_attribute_names_a_file_from_the_files_own_directory(tmp_path):
    files = {"Cargo.toml": '[package]\nname = "p"\n', "src/lib.rs": '#[cfg(unix)]\n#[path = "db/unix.rs"]\npub(crate) mod sys;\n', "src/db/unix.rs": ""}
    assert judge_import(tmp_path, files, "src/lib.rs", {"from": ["src/lib.rs"], "to": ["src/db/**"]}) == [
        (3, "mod sys", "repository", "src/db/unix.rs", "violated")]


RUST_TRICKS = {
    "a raw string with hashes": 'const S: &str = r##"a "# quote and a \\ backslash"##;\n',
    "a byte string and a C string": 'const B: &[u8] = b"\\"use"; const C: &CStr = c"x\\"y";\n',
    "a quote character": "const Q: char = '\"'; const R: u8 = b'\"';\n",
    "lifetimes": "fn f<'a, 'b: 'a>(x: &'a str, y: &'b str) -> &'a str { 'outer: loop { break 'outer x; } }\n",
    "an escaped character": "const E: char = '\\''; const U: char = '\\u{1F600}';\n",
    "a nested comment": "/* a /* nested */ comment with \"quotes and 'ticks */\n",
    "a doc comment": "/// Returns \"x\" or 'y\n//! a module doc with a \" quote\n",
}


@pytest.mark.parametrize("case", sorted(RUST_TRICKS))
def test_rust_strings_characters_lifetimes_and_comments_are_skipped_and_the_use_after_them_is_judged(tmp_path, case):
    files = {**CRATE, "src/ui.rs": RUST_TRICKS[case] + "use crate::db::Pool;\n"}
    got = judge_import(tmp_path, files, "src/ui.rs", {"from": ["src/ui.rs"], "to": ["src/db.rs"]})
    assert [g[1:] for g in got] == [("use crate::db::Pool", "repository", "src/db.rs", "violated")]


@pytest.mark.parametrize("text,reason", [
    ("use crate::db;\n/* a /* nested */ comment\nuse crate::db::Pool;\n", "comment"),
    ('use crate::db;\nconst S: &str = r#"oops\nuse crate::db::Pool;\n', "raw string"),
    ('use crate::db;\nconst S: &str = "oops\nuse crate::db::Pool;\n', "string"),
])
def test_a_rust_file_the_scanner_cannot_finish_is_unresolved_and_its_uses_still_count(tmp_path, text, reason):
    got = judge_import(tmp_path, {**CRATE, "src/ui.rs": text}, "src/ui.rs", {"from": ["src/ui.rs"], "to": ["src/db.rs"]})
    found = imports.read(imports.Repo(tmp_path), "src/ui.rs")
    assert any(i.line is None and "cannot be scanned to its end" in i.why and reason in i.why for i in found), found
    assert (1, "use crate::db", "repository", "src/db.rs", "violated") in got
    assert (3, "use crate::db::Pool", "unresolved", "src/db.rs", "unresolved") in got


def test_a_rust_text_search_hit_in_a_doc_example_is_unresolved_when_it_names_a_forbidden_file(tmp_path):
    text = "/// ```\n/// use p::db::Pool;\n/// use std::io;\n/// ```\npub fn f() {}\n// mod hidden;\n"
    got = judge_import(tmp_path, {**CRATE, "src/ui/hidden.rs": "", "src/ui.rs": text}, "src/ui.rs", {"from": ["src/ui.rs"], "to": ["src/db.rs"]})
    assert got == [(2, "use p::db::Pool", "unresolved", "src/db.rs", "unresolved"), (6, "mod hidden", "unresolved", "src/ui/hidden.rs", "not_violated")]


def test_a_macro_use_of_dollar_crate_reads_from_the_crate_root_and_an_empty_group_is_unresolved(tmp_path):
    files = {**CRATE, "src/ui.rs": "macro_rules! m {\n    () => { use $crate::db::Pool; };\n}\nuse {};\n"}
    got = judge_import(tmp_path, files, "src/ui.rs", {"from": ["src/ui.rs"], "to": ["src/db.rs"]})
    assert got == [(2, "use crate::db::Pool", "repository", "src/db.rs", "violated"),
                   (4, "use declaration that cannot be read", "unresolved", None, "unresolved")]


def test_a_rust_module_with_a_file_per_cfg_is_judged_on_every_file(tmp_path):
    files = {"Cargo.toml": '[package]\nname = "p"\n', "src/lib.rs": '#[cfg_attr(unix, path = "a.rs")]\n#[cfg_attr(windows, path = "b.rs")]\nmod sys;\nmod ui;\n',
             "src/a.rs": "pub struct X;\n", "src/b.rs": "pub struct X;\n", "src/ui.rs": "use crate::sys::X;\nuse crate::sys;\n"}
    assert judge_import(tmp_path, files, "src/ui.rs", {"from": ["src/ui.rs"], "to": ["src/b.rs"]}) == [
        (1, "use crate::sys::X", "repository", "src/a.rs", "violated"), (2, "use crate::sys", "repository", "src/a.rs", "violated")]


def test_rust_items_and_modules_inside_an_item_level_macro_are_read(tmp_path):
    lib = ("cfg_if::cfg_if! {\n    if #[cfg(unix)] {\n        pub mod db;\n        pub use db::Pool;\n    } else {\n        pub mod other;\n    }\n}\nmod ui;\n"
           "glib::wrapper! {\n    pub struct Widget(Object<ffi::GtkWidget>);\n}\nmacro_rules! m {\n    () => { mod hidden; };\n}\n")
    files = {"Cargo.toml": '[package]\nname = "p"\n', "src/lib.rs": lib, "src/db.rs": "pub struct Pool;\n", "src/other.rs": "",
             "src/ui.rs": "use crate::db::Pool;\nuse crate::Pool as P;\nuse crate::Widget;\nuse std::io;\nuse crate::hidden::H;\n"}
    assert judge_import(tmp_path, files, "src/ui.rs", {"from": ["src/ui.rs"], "to": ["src/db.rs"]}) == [
        (1, "use crate::db::Pool", "repository", "src/db.rs", "violated"), (2, "use crate::Pool", "repository", "src/db.rs", "violated"),
        (3, "use crate::Widget", "repository", "src/lib.rs", "not_violated"), (4, "use std::io", "external", None, "not_violated"),
        (5, "use crate::hidden::H", "unresolved", None, "unresolved")]


def test_the_extern_prelude_stays_external_beside_a_glob_that_cannot_be_followed(tmp_path):
    files = {"Cargo.toml": '[package]\nname = "p"\n', "src/lib.rs": "mod ui;\n", "src/ui.rs": "use crate::gone::*;\nuse std::io;\nuse core::mem;\n"}
    assert [(g[1], g[2]) for g in judge_import(tmp_path, files, "src/ui.rs", {"from": ["src/ui.rs"], "to": ["src/**"]})] == [
        ("use crate::gone", "unresolved"), ("use std::io", "external"), ("use core::mem", "external")]


P_CARGO = {"Cargo.toml": '[package]\nname = "p"\n'}


def test_a_name_bound_to_a_module_with_a_file_per_cfg_goes_on_through_every_file(tmp_path):
    lib = '#[cfg_attr(unix, path = "unix.rs")]\n#[cfg_attr(windows, path = "win.rs")]\npub mod sys;\nmod ui;\n'
    files = {**P_CARGO, "src/lib.rs": lib, "src/unix.rs": "pub mod db {\n    pub struct T;\n}\n",
             "src/win.rs": '#[path = "forbidden/db.rs"]\npub mod db;\n', "src/forbidden/db.rs": "pub struct T;\n"}
    rule = {"from": ["src/ui.rs"], "to": ["src/forbidden/**"]}
    bound = judge_import(tmp_path / "bound", {**files, "src/ui.rs": "use crate::sys as s;\nuse s::db::T;\n"}, "src/ui.rs", rule)
    globbed = judge_import(tmp_path / "glob", {**files, "src/ui.rs": "use crate::sys::*;\nuse db::T;\n"}, "src/ui.rs", rule)
    assert bound[1][4] == "violated" and globbed[1][4] == "violated"


def test_every_cfg_gated_use_of_the_same_name_is_followed(tmp_path):
    files = {**P_CARGO, "src/lib.rs": "pub mod unix;\npub mod forbidden;\nmod ui;\n", "src/unix.rs": "pub mod db {\n    pub struct T;\n}\n",
             "src/forbidden/mod.rs": "pub mod db;\n", "src/forbidden/db.rs": "pub struct T;\n",
             "src/ui.rs": "#[cfg(unix)]\nuse crate::unix as imp;\n#[cfg(windows)]\nuse crate::forbidden as imp;\nuse imp::db::T;\n"}
    assert judge_import(tmp_path, files, "src/ui.rs", {"from": ["src/ui.rs"], "to": ["src/forbidden/db.rs"]})[-1][4] == "violated"


def test_every_cfg_gated_mod_declaration_of_the_same_name_is_followed(tmp_path):
    lib = '#[cfg(windows)]\n#[path = "forbidden/imp.rs"]\npub mod imp;\n#[cfg(unix)]\n#[path = "unix_imp.rs"]\npub mod imp;\nmod ui;\n'
    files = {**P_CARGO, "src/lib.rs": lib, "src/forbidden/imp.rs": "pub struct T;\n", "src/unix_imp.rs": "pub struct T;\n", "src/ui.rs": "use crate::imp::T;\n"}
    assert judge_import(tmp_path, files, "src/ui.rs", {"from": ["src/ui.rs"], "to": ["src/forbidden/**"]})[0][4] == "violated"


def verdicts(repo, rel: str, rule: dict) -> list[tuple]:
    (parsed,) = rules.parse({"imports_forbidden": rule}).rules
    return [(i.specifier, i.target, rules.verdict(parsed, {"file": rel, "specifier": i.specifier, "resolution": i.resolution,
                                                        "target": i.target, "why": i.why, "also": i.also}, False)[0])
            for i in imports.read(repo, rel)]


def test_a_glob_cycle_gives_the_same_verdict_whatever_file_is_read_first(tmp_path):
    files = {**P_CARGO, "src/lib.rs": "pub mod a;\npub mod forbidden;\npub use self::a::*;\npub use self::forbidden::*;\nmod ui;\nmod other;\n",
             "src/a.rs": "pub use crate::*;\npub use std::collections::*;\n", "src/forbidden/mod.rs": "pub mod x;\n", "src/forbidden/x.rs": "pub struct T;\n",
             "src/ui.rs": "use crate::a::x::T;\n", "src/other.rs": "use crate::x::T;\n"}
    judge_import(tmp_path, files, "src/ui.rs", {"from": ["src/ui.rs"], "to": ["src/forbidden/**"]})
    rule = {"from": ["src/*.rs"], "to": ["src/forbidden/**"]}
    cold = verdicts(imports.Repo(tmp_path), "src/ui.rs", rule)
    warm = imports.Repo(tmp_path)
    verdicts(warm, "src/other.rs", rule)
    assert verdicts(warm, "src/ui.rs", rule) == cold == [("use crate::a::x::T", "src/forbidden/x.rs", "violated")]


def test_a_repository_crate_renamed_core_beside_a_glob_that_cannot_be_followed_is_judged_as_that_crate(tmp_path):
    files = {"Cargo.toml": '[package]\nname = "p"\n\n[dependencies]\ncore = { package = "dbc", path = "dbc" }\n', "src/lib.rs": "mod ui;\n",
             "dbc/Cargo.toml": '[package]\nname = "dbc"\n', "dbc/src/lib.rs": "pub mod db;\n", "dbc/src/db.rs": "pub struct T;\n",
             "src/ui.rs": "use crate::gen::*;\nuse core::db::T;\n"}
    got = judge_import(tmp_path, files, "src/ui.rs", {"from": ["src/ui.rs"], "to": ["dbc/**"]})
    assert got == [(1, "use crate::gen", "unresolved", None, "unresolved"), (2, "use core::db::T", "repository", "dbc/src/db.rs", "violated")]


def test_a_name_looked_up_in_a_module_file_that_cannot_be_read_is_unresolved(tmp_path):
    files = {**P_CARGO, "src/lib.rs": "pub mod db;\nmod ui;\n", "src/db.rs": "pub struct T;\n", "src/ui.rs": "use crate::db::T;\n"}
    judge_import(tmp_path, files, "src/ui.rs", {"from": ["src/ui.rs"], "to": ["src/db.rs"]})
    (tmp_path / "src" / "db.rs").write_bytes(b"\xff\xfe not utf-8")
    assert judge_import(tmp_path, {}, "src/ui.rs", {"from": ["src/ui.rs"], "to": ["src/db.rs"]})[0][2:] == ("unresolved", None, "unresolved")
