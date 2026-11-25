from __future__ import annotations

from pathlib import Path

import pytest

from decisis import imports, jvm

APP_K = "app/src/main/kotlin/app/A.kt"
APP_J = "app/src/main/java/app/A.java"
IMPORT_K = "package app\nimport lib.ff.Ff\n"
IMPORT_J = "package app;\nimport lib.ff.Ff;\n"


def read(tmp_path: Path, files: dict[str, str | bytes], rel: str) -> list:
    for name, text in files.items():
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(text if isinstance(text, bytes) else text.encode("utf-8"))
    return imports.read(imports.Repo(tmp_path), rel)


@pytest.mark.parametrize("path,body,importer,rel", [
    ("lib/misc/W.kt", "#package lib.ff\nclass Ff\n", IMPORT_K, APP_K),
    ("lib/misc/W.kt", "~\npackage lib.ff\nclass Ff\n", IMPORT_K, APP_K),
    ("lib/misc/W.java", "?package lib.ff;\npublic class Ff {}\n", IMPORT_J, APP_J),
    ("lib/misc/W.java", b"\xff\xfe" + "package lib.ff;\npublic class Ff {}\n".encode("utf-16-le"), IMPORT_J, APP_J),
])
def test_a_file_whose_header_stops_before_a_package_line_is_unplaced_so_an_import_it_may_declare_is_never_external(tmp_path, path, body, importer, rel):
    (found,) = read(tmp_path, {path: body, rel: importer}, rel)
    assert found.resolution == imports.UNRESOLVED and found.target == path


@pytest.mark.parametrize("path,body,importer,rel", [
    ("lib/misc/W.kt", "/* package lib.ff\nclass Ff\n", "package app\nimport lib.ff.*\n", APP_K),
    ("lib/misc/W.java", "/* package lib.ff;\npublic class Ff {}\n", "package app;\nimport lib.ff.*;\n", APP_J),
    ("lib/misc/W.kt", "package lib.1x\nclass Ff\n", "package app\nimport lib.ff.*\n", APP_K),
])
def test_a_wildcard_import_is_never_external_while_a_file_whose_package_cannot_be_read_names_its_first_package(tmp_path, path, body, importer, rel):
    (found,) = read(tmp_path, {path: body, rel: importer}, rel)
    assert found.resolution == imports.UNRESOLVED and found.target == path


def test_a_wildcard_of_another_top_level_package_stays_external_beside_an_unplaced_file(tmp_path):
    files = {"lib/misc/W.kt": "/* package lib.ff\nclass Ff\n", APP_K: "package app\nimport org.other.*\nimport java.util.*\n"}
    assert [f.resolution for f in read(tmp_path, files, APP_K)] == [imports.EXTERNAL, imports.EXTERNAL]


@pytest.mark.parametrize("body", [
    "package lib.ff;\n\nimport java.lang.annotation.Target;\n\n@Target({})\n@interface Ignore {}\n",
    "package lib.ff;\n@Deprecated\npublic final class Ff {}\n",
    "public class Plain {}\n",
    "@file:JvmName(\"Util\")\npackage lib.ff\nprivate const val X = 1\nfun util() = X\n",
    "import java.util.List\n\nsealed interface Shape\n",
])
def test_an_ordinary_header_is_not_unplaced(tmp_path, body):
    name = "lib/misc/Ff.java" if "class Ff" in body or "@interface" in body or "Plain" in body else "lib/misc/Ff.kt"
    (tmp_path / name).parent.mkdir(parents=True, exist_ok=True)
    (tmp_path / name).write_text(body, encoding="utf-8")
    assert jvm.index_of(imports.Repo(tmp_path)).unplaced == []
