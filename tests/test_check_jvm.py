from __future__ import annotations

import json
from pathlib import Path

import pytest

from test_audit import no_network
from decisis import cli, imports

ROOT = Path(__file__).resolve().parents[1]
FIX = ROOT / "fixtures" / "check-jvm"
VIEW = "app/src/main/java/com/shop/ui/CartView.java"
SCREEN = "app/src/main/kotlin/com/shop/ui/Screen.kt"
REPORT = "legacy/src/main/custom/com/shop/legacy/Report.java"
FORBIDDEN = "decision:ui-does-not-import-db"
DB = "db/src/main/java/com/shop/db/"


def write(tmp_path: Path, files: dict[str, str]) -> imports.Repo:
    for name, text in files.items():
        (tmp_path / name).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / name).write_text(text, encoding="utf-8")
    return imports.Repo(tmp_path)


def read(tmp_path: Path, files: dict[str, str], rel: str) -> list[tuple]:
    return [(i.line, i.specifier, i.resolution, i.target) for i in imports.read(write(tmp_path, files), rel)]


def one(tmp_path: Path, files: dict[str, str], rel: str) -> imports.Import:
    (found,) = imports.read(write(tmp_path, files), rel)
    return found


def check(capsys, *changed: str) -> tuple[int, dict]:
    capsys.readouterr()
    code = cli.main(["check", str(FIX / "vinc.json"), "--repo-dir", str(FIX / "repo"), "--changed", *changed])
    return code, json.loads(capsys.readouterr().out)


def listed(r: dict, file: str) -> list[tuple]:
    return [(i["line"], i["import"], i["resolution"], i["target"]) for i in r["imports"] if i["file"] == file]


def test_java_imports_resolve_to_source_files_under_gradle_and_maven_roots_and_the_package_directory(capsys, no_network):
    code, r = check(capsys, VIEW, REPORT)
    assert code == 1
    assert listed(r, VIEW) == [
        (4, "import com.shop.db.Pool", "repository", DB + "Pool.java"),
        (5, "import com.shop.db.Pool.Conn", "repository", DB + "Pool.java"),
        (6, "import static com.shop.db.Pool.open", "repository", DB + "Pool.java"),
        (7, "import com.shop.db.gen.Rows", "repository", "db/gen/rows/com/shop/db/gen/Rows.java"),
        (8, "import com.shop.db.hand.*", "repository", "db/hand/com/shop/db/hand/"),
        (9, "import com.shop.util.Strings", "repository", "app/src/main/java/com/shop/util/Strings.java"),
        (10, "import java.util.List", "external", None),
        (11, "import com.shop.db.Missing", "unresolved", DB),
        (16, "import com.shop.db.Cursor", "unresolved", "db/src/main/kotlin/com/shop/db/Queries.kt")]
    assert listed(r, REPORT) == [(3, "import com.shop.db.Row", "repository", DB + "Row.java"),
                                 (4, "import com.shop.legacy.Helper", "repository", "legacy/src/main/custom/com/shop/legacy/Helper.java")]
    assert {(v["file"], v["line"], v["decision"], v["rule"]) for v in r["violations"] if v["file"] != SCREEN} == {
        (VIEW, line, FORBIDDEN, "imports_forbidden") for line in (4, 5, 6, 7, 8)} | {(REPORT, 3, FORBIDDEN, "imports_forbidden")}


def test_kotlin_imports_with_alias_top_level_members_and_the_class_java_sees_resolve(capsys, no_network):
    _, r = check(capsys, SCREEN)
    queries = "db/src/main/kotlin/com/shop/db/Queries.kt"
    assert listed(r, SCREEN) == [
        (3, "import com.shop.db.Pool as ConnectionPool", "repository", DB + "Pool.java"),
        (4, "import com.shop.db.connect", "repository", queries), (5, "import com.shop.db.limit", "repository", queries),
        (6, "import com.shop.db.Cursor", "repository", queries), (7, "import com.shop.db.QueriesKt", "repository", queries),
        (8, "import com.shop.util.Strings", "repository", "app/src/main/java/com/shop/util/Strings.java"),
        (9, "import kotlin.collections.List", "external", None),
        (12, "import com.shop.db.Row", "unresolved", DB + "Row.java")]
    assert {v["line"] for v in r["violations"]} == {3, 4, 5, 6, 7}
    assert [u["line"] for u in r["unresolved"]] == [12]


def test_a_wildcard_names_the_package_directory_and_every_source_file_in_it(tmp_path):
    files = {"a/src/main/java/p/q/One.java": "package p.q;\nclass One {}\n", "b/src/main/kotlin/p/q/Two.kt": "package p.q\nclass Two\n",
             "c/src/main/java/x/Use.java": "package x;\nimport p.q.*;\n"}
    (found,) = imports.read(write(tmp_path, files), "c/src/main/java/x/Use.java")
    assert (found.resolution, found.target) == ("repository", "a/src/main/java/p/q/")
    assert set(found.also) == {"a/src/main/java/p/q", "b/src/main/kotlin/p/q", "a/src/main/java/p/q/One.java", "b/src/main/kotlin/p/q/Two.kt"}


def test_comments_strings_text_blocks_raw_strings_and_templates_are_not_imports(tmp_path):
    java = {"src/main/java/p/A.java": "package p;\npublic class A {}\n",
            "src/main/java/q/B.java": ('package q;\n// import p.A;\n/* import p.A; */\nimport p.A;\n'
                                       'class B { String s = "import p.A;"; String t = """\n  import p.A;\n  \\"""\n  """; char c = \'"\'; }\n')}
    assert [(i.line, i.resolution) for i in imports.read(write(tmp_path, java), "src/main/java/q/B.java") if i.why == ""] == [(4, "repository")]
    kotlin = {"src/main/kotlin/p/A.kt": "package p\nclass A\n",
              "src/main/kotlin/q/B.kt": ('package q\n/* outer /* nested */ import p.A */\nimport p.A\n'
                                         'val s = "${"}"} x"\nval raw = """a"" "$x" ${"}"}"""\nval c = \'"\'\nval `import` = 1\n')}
    got = read(tmp_path / "k", kotlin, "src/main/kotlin/q/B.kt")
    assert got == [(3, "import p.A", "repository", "src/main/kotlin/p/A.kt")]


def test_a_text_search_hit_that_the_scanner_read_as_text_is_unresolved_unless_it_would_be_external(tmp_path):
    files = {"src/main/java/p/A.java": "package p;\npublic class A {}\n",
             "src/main/java/q/B.java": 'package q;\nclass B {\n  String t = """\n  import p.A;\n  import java.util.List;\n  """;\n}\n'}
    got = imports.read(write(tmp_path, files), "src/main/java/q/B.java")
    assert [(i.line, i.specifier, i.resolution, i.target) for i in got] == [(4, "import p.A", "unresolved", "src/main/java/p/A.java")]
    assert "the scanner and the text search disagree" in got[0].why


@pytest.mark.parametrize("text", ['package q;\nimport p.A;\n/* never closed\n', 'package q;\nimport p.A;\nclass B { String s = "open;\n}\n',
                                  'package q;\nimport p.A;\nclass B { String t = """\nopen\n}\n'])
def test_a_file_the_scanner_cannot_finish_is_unresolved_and_its_imports_still_count(tmp_path, text):
    got = imports.read(write(tmp_path, {"src/main/java/p/A.java": "package p;\npublic class A {}\n", "src/main/java/q/B.java": text}), "src/main/java/q/B.java")
    assert [(i.resolution, i.target) for i in got if i.line] == [("repository", "src/main/java/p/A.java")]
    assert any(i.line is None and i.resolution == "unresolved" and "cannot be scanned to its end" in i.why for i in got)


def test_an_import_that_cannot_be_read_is_unresolved_and_the_next_one_is_still_read(tmp_path):
    files = {"src/main/java/p/A.java": "package p;\npublic class A {}\n", "src/main/java/q/B.java": "package q;\nimport p.;\nimport p.A;\n"}
    got = imports.read(write(tmp_path, files), "src/main/java/q/B.java")
    assert [(i.line, i.resolution) for i in got] == [(2, "unresolved"), (3, "repository")]
    assert "cannot be read" in got[0].why


def test_a_class_outside_the_repository_is_external_and_a_missing_class_of_a_repository_package_is_not(tmp_path):
    files = {"src/main/java/p/A.java": "package p;\npublic class A {}\n",
             "src/main/java/q/B.java": "package q;\nimport org.junit.Test;\nimport p.Gone;\nimport p.A.Inner;\nimport static p.A.method;\n"}
    got = imports.read(write(tmp_path, files), "src/main/java/q/B.java")
    assert [(i.specifier, i.resolution, i.target) for i in got] == [
        ("import org.junit.Test", "external", None), ("import p.Gone", "unresolved", "src/main/java/p/"),
        ("import p.A.Inner", "repository", "src/main/java/p/A.java"), ("import static p.A.method", "repository", "src/main/java/p/A.java")]
    assert "p is a package of the repository, but no source file in it declares Gone" in got[1].why


def test_a_class_in_several_source_roots_gives_every_file(tmp_path):
    files = {"core/src/main/java/p/A.java": "package p;\npublic class A {}\n", "alt/src/main/kotlin/p/A.kt": "package p\nclass A\n",
             "use/src/main/java/q/B.java": "package q;\nimport p.A;\n"}
    (found,) = imports.read(write(tmp_path, files), "use/src/main/java/q/B.java")
    assert (found.resolution, found.target, found.also) == ("repository", "alt/src/main/kotlin/p/A.kt", ("core/src/main/java/p/A.java",))


def test_a_nested_class_and_a_package_of_one_name_give_both_files(tmp_path):
    files = {"src/main/java/p/A.java": "package p;\npublic class A { public static class B {} }\n", "src/main/java/p/A/B.java": "package p.A;\npublic class B {}\n",
             "src/main/java/q/C.java": "package q;\nimport p.A.B;\n"}
    (found,) = imports.read(write(tmp_path, files), "src/main/java/q/C.java")
    assert (found.target, found.also) == ("src/main/java/p/A/B.java", ("src/main/java/p/A.java",))


def test_kotlin_files_are_found_by_their_package_line_whatever_directory_holds_them(tmp_path):
    files = {"src/main/kotlin/network/socket/Connection.kt": "package org.example.network.socket\n\nclass Connection\n\nfun open() {}\n",
             "src/main/kotlin/ui/Use.kt": "package org.example.ui\nimport org.example.network.socket.Connection\nimport org.example.network.socket.open\n"}
    assert read(tmp_path, files, "src/main/kotlin/ui/Use.kt") == [
        (2, "import org.example.network.socket.Connection", "repository", "src/main/kotlin/network/socket/Connection.kt"),
        (3, "import org.example.network.socket.open", "repository", "src/main/kotlin/network/socket/Connection.kt")]


def test_a_kotlin_extension_function_and_a_jvm_name_are_found_by_name(tmp_path):
    files = {"src/main/kotlin/p/Ext.kt": '@file:JvmName("Tools")\npackage p\n\ninternal fun List<String>.shout(): String = ""\nval Foo.size: Int get() = 1\n',
             "src/main/java/q/Use.java": "package q;\nimport static p.Tools.shout;\nimport p.ExtKt;\n"}
    got = read(tmp_path, {**files, "src/main/kotlin/q/Use.kt": "package q\nimport p.shout\nimport p.size\n"}, "src/main/kotlin/q/Use.kt")
    assert [g[2:] for g in got] == [("repository", "src/main/kotlin/p/Ext.kt")] * 2
    java = [g[2:] for g in read(tmp_path, files, "src/main/java/q/Use.java")]
    assert java == [("repository", "src/main/kotlin/p/Ext.kt")] * 2


@pytest.mark.parametrize("build,text", [
    ("mod/build.gradle", "sourceSets {\n  main { java { srcDirs = ['gen/a', \"gen/b\"] } }\n}\n"),
    ("mod/build.gradle.kts", 'sourceSets.main { java.srcDir("gen/b") }\n'),
    ("mod/build.gradle", "sourceSets.main.java.srcDirs += ['gen/b']\n"),
    ("mod/build.gradle", "sourceSets {\n  main {\n    java.srcDir 'gen/b'\n  }\n}\n"),
    ("mod/build.gradle.kts", 'kotlin.sourceSets["main"].kotlin.setSrcDirs(listOf("gen/b"))\n'),
    ("mod/pom.xml", "<project><build><sourceDirectory>gen/b</sourceDirectory></build></project>\n"),
    ("mod/pom.xml", "<project><build><testSourceDirectory>${project.basedir}/gen/b</testSourceDirectory></build></project>\n"),
    ("mod/pom.xml", "<build><plugins><plugin><configuration><sources><source>gen/b</source></sources></configuration></plugin></plugins></build>\n")])
def test_a_source_root_a_gradle_or_maven_module_declares_places_a_class_by_the_path_of_its_package(tmp_path, build, text):
    files = {build: text, "mod/gen/b/p/q/Thing.java": "class Thing {}\n", "use/src/main/java/x/Use.java": "package x;\nimport p.q.Thing;\n"}
    assert read(tmp_path, files, "use/src/main/java/x/Use.java") == [(2, "import p.q.Thing", "repository", "mod/gen/b/p/q/Thing.java")]


def test_a_source_directory_that_no_script_declares_is_not_a_root_for_a_file_with_no_package_line(tmp_path):
    files = {"mod/gen/p/q/Thing.java": "class Thing {}\n", "use/src/main/java/x/Use.java": "package x;\nimport p.q.Thing;\n"}
    assert read(tmp_path, files, "use/src/main/java/x/Use.java") == [(2, "import p.q.Thing", "external", None)]


def test_test_source_sets_and_multiplatform_roots_are_source_roots(tmp_path):
    files = {"m/src/test/java/p/T.java": "class T {}\n", "m/src/integrationTest/kotlin/p/I.kt": "class I\n", "m/src/jvmMain/kotlin/p/J.kt": "class J\n",
             "m/src/main/java/x/Use.java": "package x;\nimport p.T;\nimport p.I;\nimport p.J;\n"}
    assert [g[2:] for g in read(tmp_path, files, "m/src/main/java/x/Use.java")] == [
        ("repository", "m/src/test/java/p/T.java"), ("repository", "m/src/integrationTest/kotlin/p/I.kt"), ("repository", "m/src/jvmMain/kotlin/p/J.kt")]


def test_build_output_beside_a_build_script_is_not_a_source_of_the_repository(tmp_path):
    files = {"m/build.gradle": "", "m/build/generated/p/Gen.java": "package p;\nclass Gen {}\n", "n/pom.xml": "", "n/target/gen/p/Mvn.java": "package p;\nclass Mvn {}\n",
             "m/src/main/java/p/Real.java": "package p;\nclass Real {}\n", "m/src/main/java/x/Use.java": "package x;\nimport p.Gen;\nimport p.Mvn;\nimport p.Real;\n"}
    assert [(g[1], g[2]) for g in read(tmp_path, files, "m/src/main/java/x/Use.java")] == [
        ("import p.Gen", "unresolved"), ("import p.Mvn", "unresolved"), ("import p.Real", "repository")]


def test_a_repository_too_large_to_search_leaves_an_import_it_does_not_find_unresolved(tmp_path, monkeypatch):
    monkeypatch.setattr("decisis.jvm.MAX_WALK", 1)
    files = {"a/Use.java": "package x;\nimport org.junit.Test;\n", "b/Other.java": "package y;\n"}
    assert [(g[2], g[3]) for g in read(tmp_path, files, "a/Use.java")] == [("unresolved", None)]


def test_a_kts_script_is_read_and_its_gradle_imports_are_external(tmp_path):
    got = read(tmp_path, {"build.gradle.kts": "import org.gradle.api.Project\nplugins { }\n"}, "build.gradle.kts")
    assert got == [(1, "import org.gradle.api.Project", "external", None)]


def test_a_jvm_import_is_judged_against_a_to_glob_and_an_unplaced_one_never_clears_it():
    from decisis import rules
    (rule,) = rules.parse({"imports_forbidden": {"from": ["app/**"], "to": ["db/**"]}}).rules
    facts = {"file": "app/A.java", "specifier": "import p.Gone", "why": "why", "also": ()}
    assert rules.verdict(rule, {**facts, "resolution": "unresolved", "target": "db/src/p/"}, False)[0] == "unresolved"
    assert rules.verdict(rule, {**facts, "resolution": "unresolved", "target": "app/src/p/"}, False)[0] == "not_violated"
    assert rules.verdict(rule, {**facts, "resolution": "unresolved", "target": None}, False)[0] == "unresolved"
    assert rules.verdict(rule, {**facts, "resolution": "repository", "target": "app/x/", "also": ("db/y/Z.java",)}, False)[0] == "violated"


def test_a_header_of_many_comments_with_no_package_line_and_a_pom_with_a_long_run_of_spaces_are_read_at_once(tmp_path):
    files = {"src/main/java/p/A.java": "/* a */ /* b */ " * 400 + "\nclass A {}\n", "src/main/java/q/B.java": "package q;\nimport p.A;\n",
             "pom.xml": "<sourceDirectory>" + " " * 100000 + "x</sourceDirectory>" + "<source>" * 2000}
    assert read(tmp_path, files, "src/main/java/q/B.java") == [(2, "import p.A", "repository", "src/main/java/p/A.java")]
