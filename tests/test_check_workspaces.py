from __future__ import annotations

import json
from pathlib import Path

import pytest

from test_audit import no_network
from test_check import judge_import
from decisis import cli, imports

ROOT = Path(__file__).resolve().parents[1]
FIX = ROOT / "fixtures" / "check-workspaces"
RULE = {"from": ["**/ui/**"], "to": ["**/db/**"]}
PAGE = "packages/ui/src/page.ts"


def manifest(**kw) -> str:
    return json.dumps(kw)


def workspace(**kw) -> dict[str, str]:
    return {"package.json": manifest(name="shop", workspaces=["packages/*"]),
            "packages/ui/package.json": manifest(name="@shop/ui", **kw)}


def read(tmp_path: Path, files: dict[str, str], rel: str = PAGE) -> list[imports.Import]:
    for name, text in files.items():
        (tmp_path / name).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / name).write_text(text, encoding="utf-8")
    return imports.read(imports.Repo(tmp_path), rel)


def result(found: imports.Import) -> tuple:
    return found.resolution, found.target


def check(capsys, *changed: str) -> tuple[int, dict]:
    capsys.readouterr()
    code = cli.main(["check", str(FIX / "vinc.json"), "--repo-dir", str(FIX / "repo"), "--changed", *changed])
    return code, json.loads(capsys.readouterr().out)


def listed(r: dict, file: str) -> list[tuple]:
    return [(i["line"], i["import"], i["resolution"], i["target"]) for i in r["imports"] if i["file"] == file]


def test_an_npm_workspace_package_imported_by_name_is_judged_through_its_main_exports_and_subpaths(capsys, no_network):
    file = "npm/packages/ui/src/page.ts"
    code, r = check(capsys, file)
    assert code == 1
    assert listed(r, file) == [
        (1, "@shop/db", "repository", "npm/packages/db/"),
        (2, "@shop/db/src/client", "repository", "npm/packages/db/src/client.ts"),
        (3, "@shop/api", "repository", "npm/packages/api/src/index.ts"),
        (4, "@shop/api/client", "repository", "npm/packages/api/src/client.ts"),
        (5, "@shop/api/utils/log", "repository", "npm/packages/api/src/utils/log.ts"),
        (6, "@shop/api/secret", "unresolved", "npm/packages/api/"),
        (7, "react", "external", "node_modules/react")]
    assert [(v["line"], v["decision"]) for v in r["violations"]] == [(1, "decision:ui-does-not-import-db"), (2, "decision:ui-does-not-import-db")]
    assert r["unresolved"] == []


def test_a_yarn_workspace_object_form_and_a_bun_workspace_resolve_the_same_way(capsys, no_network):
    for file, target in (("yarn/packages/ui/src/page.ts", "yarn/packages/db/src/main.ts"), ("bun/packages/ui/src/page.ts", "bun/packages/db/src/index.ts")):
        code, r = check(capsys, file)
        assert code == 1 and {t for _, _, _, t in listed(r, file)} == {target}, file
        assert {v["line"] for v in r["violations"]} == {i[0] for i in listed(r, file)}


def test_a_pnpm_workspace_follows_its_yaml_patterns_and_its_workspace_links(capsys, no_network):
    file = "pnpm/packages/ui/src/page.js"
    code, r = check(capsys, file)
    assert code == 1
    assert listed(r, file) == [(1, "data", "repository", "pnpm/packages/db/index.js"), (2, "path-linked", "repository", "pnpm/packages/db/index.js"),
                               (3, "ghost", "unresolved", None), (4, "@shop/old", "external", "node_modules/@shop/old")]
    assert [v["line"] for v in r["violations"]] == [1, 2]
    assert [(u["line"], "links the workspace package ghost" in u["why"]) for u in r["unresolved"]] == [(3, True)]


def test_a_workspace_package_name_resolves_in_its_own_workspace_only(capsys, no_network):
    _, r = check(capsys, "npm/packages/ui/src/page.ts", "pnpm/packages/ui/src/page.js")
    assert all(i["target"].startswith(i["file"].split("/")[0] + "/") for i in r["imports"] if i["resolution"] == "repository")


@pytest.mark.parametrize("exports,expected", [
    ("./src/a.ts", "packages/db/src/a.ts"),
    ({".": "./src/a.ts"}, "packages/db/src/a.ts"),
    ({"import": "./src/a.ts", "default": "./src/b.ts"}, "packages/db/src/a.ts"),
    ({".": {"node": {"import": "./src/a.ts"}, "default": "./src/b.ts"}}, "packages/db/src/a.ts"),
    ({".": ["./src/a.ts", "./src/b.ts"]}, "packages/db/src/a.ts")])
def test_the_exports_of_a_package_name_its_entry_with_every_condition_and_array_member_followed(tmp_path, exports, expected):
    files = {**workspace(), "packages/db/package.json": manifest(name="@shop/db", exports=exports), "packages/db/src/a.ts": "", "packages/db/src/b.ts": "",
             PAGE: 'import "@shop/db";\n'}
    (found,) = read(tmp_path, files)
    assert result(found) == ("repository", expected)
    assert {"packages/db/src/b.ts", "packages/db/src/a.ts"} >= set(found.also) - {"node_modules/@shop/db"}


def test_every_condition_of_an_export_is_a_file_the_import_may_name(tmp_path):
    files = {**workspace(), "packages/db/package.json": manifest(name="@shop/db", exports={".": {"import": "./esm/a.mjs", "require": "./cjs/a.cjs"}}),
             "packages/db/esm/a.mjs": "", "packages/db/cjs/a.cjs": "", PAGE: 'import "@shop/db";\n'}
    (found,) = read(tmp_path, files)
    assert (found.target, found.also) == ("packages/db/esm/a.mjs", ("packages/db/cjs/a.cjs", "node_modules/@shop/db"))


@pytest.mark.parametrize("exports,sub,expected", [
    ({"./client": "./src/client.ts"}, "client", ("repository", "packages/db/src/client.ts")),
    ({"./features/*": "./src/features/*.ts"}, "features/auth", ("repository", "packages/db/src/features/auth.ts")),
    ({"./features/*": "./src/features/*.ts", "./features/*/x": "./src/x/*.ts"}, "features/auth/x", ("repository", "packages/db/src/x/auth.ts")),
    ({"./features/": "./src/features/"}, "features/auth.ts", ("repository", "packages/db/src/features/auth.ts")),
    ({"./client": "./src/client.ts"}, "other", ("unresolved", "packages/db/")),
    ({"./client": None}, "client", ("unresolved", "packages/db/")),
    ({".": "./src/client.ts"}, "client", ("unresolved", "packages/db/"))])
def test_an_export_subpath_pattern_picks_the_file_and_a_subpath_that_is_not_exported_is_unresolved(tmp_path, exports, sub, expected):
    files = {**workspace(), "packages/db/package.json": manifest(name="@shop/db", exports=exports), "packages/db/src/client.ts": "",
             "packages/db/src/features/auth.ts": "", "packages/db/src/x/auth.ts": "", PAGE: f'import "@shop/db/{sub}";\n'}
    (found,) = read(tmp_path, files)
    assert result(found) == expected


def test_exports_that_mix_subpaths_and_conditions_are_unresolved(tmp_path):
    files = {**workspace(), "packages/db/package.json": manifest(name="@shop/db", exports={".": "./a.js", "import": "./b.js"}), PAGE: 'import "@shop/db";\n'}
    (found,) = read(tmp_path, files)
    assert result(found) == ("unresolved", "packages/db/") and "mix subpaths and conditions" in found.why


@pytest.mark.parametrize("fields,files,expected", [
    ({"main": "lib/main.js"}, ["lib/main.js"], "packages/db/lib/main.js"),
    ({"main": "lib/main"}, ["lib/main.ts"], "packages/db/lib/main.ts"),
    ({"main": "lib"}, ["lib/index.tsx"], "packages/db/lib/index.tsx"),
    ({"module": "esm/m.js", "types": "m.d.ts"}, ["esm/m.js"], "packages/db/esm/m.js"),
    ({}, ["index.ts"], "packages/db/index.ts"),
    ({"source": "src/s.ts"}, ["src/s.ts"], "packages/db/src/s.ts")])
def test_a_package_without_exports_is_entered_through_main_module_types_source_or_an_index_file(tmp_path, fields, files, expected):
    tree = {**workspace(), "packages/db/package.json": manifest(name="@shop/db", **fields), PAGE: 'import "@shop/db";\n',
            **{f"packages/db/{f}": "" for f in files}}
    (found,) = read(tmp_path, tree)
    assert result(found) == ("repository", expected)


def test_a_build_output_entry_that_has_a_source_file_beside_it_names_the_package_directory_and_that_file(tmp_path):
    files = {**workspace(), "packages/db/package.json": manifest(name="@shop/db", main="dist/main.js"), "packages/db/src/main.ts": "", PAGE: 'import "@shop/db";\n'}
    (found,) = read(tmp_path, files)
    assert (found.target, found.also) == ("packages/db/", ("packages/db/dist/main.js", "packages/db/src/main.ts", "node_modules/@shop/db"))


def test_a_package_entry_that_is_a_build_output_names_the_package_directory_and_the_paths_it_declares(tmp_path):
    files = {**workspace(), "packages/db/package.json": manifest(name="@shop/db", main="dist/index.js", types="dist/index.d.ts"),
             "packages/db/src/index.ts": "", PAGE: 'import "@shop/db";\nimport "@shop/db/dist/client";\n'}
    first, second = read(tmp_path, files)
    assert (first.resolution, first.target) == ("repository", "packages/db/")
    assert set(first.also) == {"packages/db/dist/index.js", "packages/db/dist/index.d.ts", "packages/db/src/index.ts", "node_modules/@shop/db"}
    assert (second.resolution, second.target) == ("repository", "packages/db/")
    assert "packages/db/dist/client" in second.also


def test_the_to_glob_of_a_package_directory_or_a_source_folder_both_judge_a_build_output_import(tmp_path):
    files = {**workspace(), "packages/db/package.json": manifest(name="@shop/db", main="dist/index.js"), "packages/db/src/index.ts": "",
             PAGE: 'import "@shop/db";\n'}
    for to in ("packages/db/**", "packages/db/src/**", "packages/db/dist/**", "packages/db"):
        assert judge_import(tmp_path, files, PAGE, {"from": ["packages/ui/**"], "to": [to]})[0][4] == "violated", to
    assert judge_import(tmp_path, files, PAGE, {"from": ["packages/ui/**"], "to": ["packages/api/**"]})[0][4] == "not_violated"


def test_a_rule_that_names_node_modules_keeps_judging_a_workspace_package_it_named_before(tmp_path):
    files = {**workspace(), "packages/db/package.json": manifest(name="@shop/db", main="index.js"), "packages/db/index.js": "", PAGE: 'import "@shop/db";\n'}
    assert judge_import(tmp_path, files, PAGE, {"from": ["packages/ui/**"], "to": ["node_modules/@shop/**"]})[0][4] == "violated"


@pytest.mark.parametrize("deps,expected", [
    ({"@shop/db": "workspace:*"}, ("repository", "packages/db/index.js")),
    ({"@shop/db": "workspace:^"}, ("repository", "packages/db/index.js")),
    ({"@shop/db": "workspace:~1.2.0"}, ("repository", "packages/db/index.js")),
    ({"@shop/db": "*"}, ("repository", "packages/db/index.js")),
    ({"@shop/db": "workspace:../db"}, ("repository", "packages/db/index.js")),
    ({"@shop/db": "workspace:@shop/other@*"}, ("repository", "packages/other/index.js")),
    ({"@shop/db": "workspace:@shop/gone"}, ("unresolved", None)),
    ({"@shop/db": "workspace:../gone"}, ("unresolved", None))])
def test_a_workspace_link_names_the_package_by_alias_path_or_name_and_a_link_to_nothing_is_unresolved(tmp_path, deps, expected):
    files = {**workspace(dependencies=deps), "packages/db/package.json": manifest(name="@shop/db", main="index.js"), "packages/db/index.js": "",
             "packages/other/package.json": manifest(name="@shop/other", main="index.js"), "packages/other/index.js": "", PAGE: 'import "@shop/db";\n'}
    (found,) = read(tmp_path, files)
    assert result(found) == expected


@pytest.mark.parametrize("field", ["devDependencies", "peerDependencies", "optionalDependencies"])
def test_a_workspace_link_in_any_dependency_field_counts(tmp_path, field):
    files = {**workspace(**{field: {"data": "workspace:@shop/db@*"}}), "packages/db/package.json": manifest(name="@shop/db", main="index.js"),
             "packages/db/index.js": "", PAGE: 'import "data/sub";\n'}
    (found,) = read(tmp_path, files)
    assert result(found) == ("repository", "packages/db/")


@pytest.mark.parametrize("declaration,names", [
    ({"workspaces": ["packages/*"]}, {"a", "b"}),
    ({"workspaces": {"packages": ["packages/*"], "nohoist": ["**/x"]}}, {"a", "b"}),
    ({"workspaces": ["packages/*", "!packages/b"]}, {"a"}),
    ({"workspaces": ["packages/a"]}, {"a"}),
    ({"workspaces": ["packages/**"]}, {"a", "b", "c"}),
    ({"workspaces": ["**/c"]}, {"c"}),
    ({"workspaces": ["packages/{a,c}"]}, {"a", "b", "c"}),
    ({"workspaces": "packages/*"}, {"a", "b", "c"}),
    ({"workspaces": [1]}, {"a", "b", "c"}),
    ({}, set())])
def test_the_workspace_patterns_of_a_package_json_pick_the_packages_and_one_that_cannot_be_read_picks_every_package_below(tmp_path, declaration, names):
    files = {"package.json": manifest(name="shop", **declaration), PAGE: "".join(f'import "n-{n}";\n' for n in "abc")}
    for n, d in (("a", "packages/a"), ("b", "packages/b"), ("c", "packages/b/inner/c")):
        files[f"{d}/package.json"] = manifest(name=f"n-{n}", main="index.js")
        files[f"{d}/index.js"] = ""
    got = {i.specifier[-1] for i in read(tmp_path, files, PAGE) if i.resolution == "repository"}
    assert got == names


@pytest.mark.parametrize("yaml,names", [
    ("packages:\n  - 'packages/*'\n", {"a", "b"}), ("packages:\n  - packages/*\n  - '!packages/b'\n", {"a"}),
    ("packages: [\"packages/a\"]\n", {"a"}), ("packages:\n  - 'packages/**'\n", {"a", "b", "c"}),
    ("packages: [unterminated\n", {"a", "b", "c"}), ("catalog:\n  x: 1\n", {"a", "b", "c"})])
def test_a_pnpm_workspace_yaml_picks_the_packages_and_one_that_cannot_be_read_picks_every_package_below(tmp_path, yaml, names):
    files = {"package.json": manifest(name="shop"), "pnpm-workspace.yaml": yaml, PAGE: "".join(f'import "n-{n}";\n' for n in "abc")}
    for n, d in (("a", "packages/a"), ("b", "packages/b"), ("c", "packages/b/inner/c")):
        files[f"{d}/package.json"] = manifest(name=f"n-{n}", main="index.js")
        files[f"{d}/index.js"] = ""
    assert {i.specifier[-1] for i in read(tmp_path, files, PAGE) if i.resolution == "repository"} == names


def test_a_name_that_two_workspace_packages_share_follows_both(tmp_path):
    files = {"package.json": manifest(name="shop", workspaces=["a/*", "b/*"]), "a/x/package.json": manifest(name="dup", main="i.js"), "a/x/i.js": "",
             "b/x/package.json": manifest(name="dup", main="i.js"), "b/x/i.js": "", PAGE: 'import "dup";\n'}
    (found,) = read(tmp_path, files)
    assert (found.target, found.also) == ("a/x/i.js", ("b/x/i.js", "node_modules/dup"))


def test_a_package_that_belongs_to_another_workspace_is_not_the_one_a_file_imports_unless_there_is_no_other(tmp_path):
    files = {"one/package.json": manifest(name="one", workspaces=["p/*"]), "one/p/d/package.json": manifest(name="d", main="i.js"), "one/p/d/i.js": "",
             "two/package.json": manifest(name="two", workspaces=["p/*"]), "two/p/d/package.json": manifest(name="d", main="i.js"), "two/p/d/i.js": "",
             "two/p/e/package.json": manifest(name="e", main="i.js"), "two/p/e/i.js": "", "one/p/u/x.js": 'import "d";\nimport "e";\n'}
    got = read(tmp_path, files, "one/p/u/x.js")
    assert [result(i) for i in got] == [("repository", "one/p/d/i.js"), ("repository", "two/p/e/i.js")]


def test_a_tsconfig_paths_entry_wins_over_a_workspace_package_of_the_same_name(tmp_path):
    files = {**workspace(), "tsconfig.json": json.dumps({"compilerOptions": {"baseUrl": ".", "paths": {"@shop/db": ["shim/db.ts"]}}}),
             "shim/db.ts": "", "packages/db/package.json": manifest(name="@shop/db", main="index.js"), "packages/db/index.js": "", PAGE: 'import "@shop/db";\n'}
    (found,) = read(tmp_path, files)
    assert result(found) == ("repository", "shim/db.ts")


def test_a_name_that_is_no_workspace_package_stays_external_and_a_repository_with_no_workspace_is_unchanged(tmp_path):
    files = {"package.json": manifest(name="shop"), "packages/db/package.json": manifest(name="@shop/db", main="index.js"), "packages/db/index.js": "",
             PAGE: 'import "@shop/db";\nimport "@shop/db-extra";\nimport "lodash/fp";\nimport "#internal";\nimport "node:fs";\n'}
    assert [result(i) for i in read(tmp_path, files)] == [("external", "node_modules/@shop/db"), ("external", "node_modules/@shop/db-extra"),
                                                          ("external", "node_modules/lodash/fp"), ("external", "node_modules/#internal"),
                                                          ("external", "node_modules/node:fs")]


def test_a_dynamic_import_and_a_require_of_a_workspace_package_resolve_and_a_text_search_hit_names_it(tmp_path):
    files = {**workspace(), "packages/db/package.json": manifest(name="@shop/db", main="index.js"), "packages/db/index.js": "",
             "packages/api/package.json": manifest(name="@shop/api", main="index.js"), "packages/api/index.js": "",
             PAGE: 'const a = await import("@shop/db");\nconst b = require("@shop/db");\n/* import "@shop/api" */\nconst s = `\nimport "@shop/api"\n`;\n'}
    got = read(tmp_path, files)
    assert [(i.line, i.resolution, i.target) for i in got] == [(1, "repository", "packages/db/index.js"), (2, "repository", "packages/db/index.js"),
                                                               (3, "unresolved", "packages/api/index.js"), (5, "unresolved", "packages/api/index.js")]
    assert judge_import(tmp_path, files, PAGE, {"from": ["packages/ui/**"], "to": ["packages/api/**"]})[2][4] == "unresolved"
    assert judge_import(tmp_path, files, PAGE, {"from": ["packages/ui/**"], "to": ["packages/db/**"]})[2][4] == "not_violated"


def test_a_package_json_with_no_name_or_with_a_name_that_is_not_text_is_no_workspace_package(tmp_path):
    files = {"package.json": manifest(name="shop", workspaces=["packages/*"]), "packages/a/package.json": manifest(main="i.js"), "packages/b/package.json": manifest(name=3),
             "packages/c/package.json": "{ not json", PAGE: 'import "a";\nimport "b";\nimport "c";\n'}
    assert {i.resolution for i in read(tmp_path, files)} == {"external"}


def test_a_workspace_package_imported_from_its_own_files_by_name_resolves_to_itself(tmp_path):
    files = {"package.json": manifest(name="shop", workspaces=["packages/*"]), "packages/db/package.json": manifest(name="@shop/db", exports={"./client": "./src/client.ts"}),
             "packages/db/src/client.ts": "", "packages/db/src/use.ts": 'import "@shop/db/client";\n'}
    (found,) = read(tmp_path, files, "packages/db/src/use.ts")
    assert result(found) == ("repository", "packages/db/src/client.ts")


def test_a_workspace_pattern_with_many_double_stars_a_deep_package_json_and_deep_exports_are_read_without_failing(tmp_path):
    deep = {"import": "./x.js"}
    for _ in range(200):
        deep = {"node": deep}
    files = {"package.json": manifest(name="shop", workspaces=["**/" * 60 + "x", "packages/*"]), "packages/a/package.json": "[" * 5000,
             "packages/db/package.json": manifest(name="n-db", exports=deep), "packages/ok/package.json": manifest(name="n-ok", main="i.js"), "packages/ok/i.js": "",
             PAGE: 'import "n-db";\nimport "n-ok";\n'}
    assert [result(i) for i in read(tmp_path, files)] == [("unresolved", "packages/db/"), ("repository", "packages/ok/i.js")]


def test_a_walk_that_was_cut_leaves_a_package_name_unresolved_except_a_node_core_module(tmp_path, monkeypatch):
    monkeypatch.setattr("decisis.workspaces.MAX_WALK", 1)
    files = {"package.json": '{"workspaces":["packages/*"]}', "README.md": "", "packages/db/package.json": '{"name":"@shop/db","main":"i.js"}', "packages/db/i.js": "",
             "packages/ui/page.ts": 'import x from "@shop/db";\nimport fs from "fs";\nimport p from "node:path";\nimport z from "fs/promises";\nimport r from "react";\n'}
    got = read(tmp_path, files, "packages/ui/page.ts")
    assert [(i.specifier, i.resolution) for i in got] == [("@shop/db", "unresolved"), ("fs", "external"), ("node:path", "external"), ("fs/promises", "external"),
                                                          ("react", "unresolved")]


def test_a_package_json_with_a_byte_order_mark_still_declares_its_package(tmp_path):
    files = {"package.json": "﻿" + manifest(name="shop", workspaces=["packages/*"]), "packages/db/package.json": "﻿" + manifest(name="@shop/db", main="i.js"),
             "packages/db/i.js": "", PAGE: 'import "@shop/db";\n'}
    assert result(read(tmp_path, files)[0]) == ("repository", "packages/db/i.js")
