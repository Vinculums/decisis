import importlib.util
import json
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("gate_comments", ROOT / "scripts" / "gate_comments.py")
gate = importlib.util.module_from_spec(SPEC)
PREVIOUS_BYTECODE_FLAG = sys.dont_write_bytecode
sys.dont_write_bytecode = True
try:
    SPEC.loader.exec_module(gate)
finally:
    sys.dont_write_bytecode = PREVIOUS_BYTECODE_FLAG

SHA = "3d3c42e5aac5ba805825da76410c181273ba90b1"


def lines(rel, src):
    return [ln for ln, _ in gate.counted(rel, textwrap.dedent(src))]


def repo(tmp_path, files):
    for rel, text in files.items():
        path = tmp_path / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    subprocess.run(["git", "add", "-A"], cwd=tmp_path, check=True)
    return tmp_path


def baseline(root, files):
    path = root / "scripts" / "comments-baseline.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"files": files}), encoding="utf-8")
    return path


def test_python_comments_docstrings_and_bare_strings_are_counted_by_line():
    src = '''\
        """module doc"""
        import re  # trailing
        # whole line


        def f():
            """first
            second
            """
            "a bare string statement"
            return re.compile("# not a comment")


        class C:
            ("parenthesised" "and joined")
    '''
    assert lines("a.py", src) == [1, 2, 3, 7, 8, 9, 10, 15]


def test_a_string_with_a_hash_and_a_value_string_are_not_comments():
    src = '''\
        x = "# nope"
        y = f"{x} # nope"
        z = [1, "a"]
        w = ("only", "values")
    '''
    assert lines("a.py", src) == []


@pytest.mark.parametrize(
    "src, expected",
    [
        ("#!/usr/bin/env python3\nx = 1\n", []),
        ("x = 1\n#!/usr/bin/env python3\n", [2]),
        ("# -*- coding: utf-8 -*-\nx = 1\n", []),
        ("# coding=latin-1\nx = 1\n", []),
        ("x = 1\ny = 2\n# coding: utf-8\n", [3]),
        ("x = 1  # noqa: E501\n", []),
        ("x = 1  # type: ignore[attr-defined]\n", []),
        ("x = 1  # type: int\n", []),
        ("def f():\n    pass  # pragma: no cover\n", []),
        ("# fmt: off\nx = 1\n# fmt: on\n", []),
        ("x = 1  # pyright: ignore\ny = 2  # pylint: disable=x\nz = 3  # mypy: ignore-errors\n", []),
        ("x = 1  # explains why noqa\n", [1]),
        ("x = 1  # the type: of x\n", [1]),
        ("x = 1  # not a pragma\n", [1]),
    ],
)
def test_machine_pragmas_do_not_count_and_prose_that_mentions_one_does(src, expected):
    assert lines("a.py", src) == expected


def test_a_file_that_does_not_parse_still_has_its_hash_comments_counted():
    assert lines("a.py", "def broken(:\n    # why\n") == [2]


def test_yaml_hash_comments_count_and_a_quoted_hash_does_not():
    src = """\
        # top
        key: value  # trailing
        other: "a # b"
        third: 'c # d'
        url: http://x/y#frag
    """
    assert lines("a.yml", src) == [1, 2]
    assert lines("a.yaml", src) == [1, 2]


def test_a_version_label_after_a_pinned_action_sha_is_a_machine_label_and_nothing_else_is():
    src = f"""\
        steps:
          - uses: actions/checkout@{SHA} # v7.0.1
          - uses: actions/checkout@{SHA}   # v7
          - uses: actions/checkout@v4 # v4
          - uses: actions/checkout@{SHA} # pinned for the audit
          - uses: actions/checkout@{SHA} # v7.0.1 because of the audit
          - run: echo hi # v7.0.1
    """
    assert lines("a.yml", src) == [4, 5, 6, 7]


def test_a_yaml_language_server_line_is_a_machine_pragma():
    assert lines("a.yml", "# yaml-language-server: $schema=x.json\nkey: 1\n") == []


def test_toml_hash_comments_count():
    assert lines("a.toml", 'name = "x"  # why\n# more\nurl = "http://a/#b"\n') == [1, 2]


def test_cypher_line_and_block_comments_count_and_quoted_slashes_do_not():
    src = """\
        MATCH (a)  // why
        /* block
           two */
        WHERE a.url = 'http://x/y' AND a.name = "/* no */" AND a.`odd//name` = 1
        RETURN a
    """
    assert lines("a.cypher", src) == [1, 2, 3]


def test_fixtures_golden_files_and_other_kinds_of_file_are_not_scanned(tmp_path):
    root = repo(
        tmp_path,
        {
            "src/a.py": "x = 1\n",
            "fixtures/check/repo/a.py": "# fixture\n",
            "tests/fixtures/a.py": "# fixture\n",
            "tests/golden/a.yml": "# golden\n",
            "README.md": "# heading\n",
            "notes.txt": "# note\n",
            "web/a.ts": "// a\n",
        },
    )
    assert gate.scan(root) == {}


def test_only_tracked_files_are_scanned(tmp_path):
    root = repo(tmp_path, {"a.py": "x = 1\n"})
    (root / "b.py").write_text("# untracked\n", encoding="utf-8")
    assert gate.scan(root) == {}


def test_a_new_comment_blocks_and_names_the_file_and_line(tmp_path, capsys):
    root = repo(tmp_path, {"src/a.py": "x = 1\n# why\n"})
    baseline(root, {})
    assert gate.main(["--root", str(root)]) == 1
    out = capsys.readouterr().out
    assert "BLOCK" in out and "src/a.py: 1 > new file allowance 0" in out and "src/a.py:2  # why" in out


def test_a_file_at_its_baseline_passes_and_a_file_over_it_blocks(tmp_path, capsys):
    root = repo(tmp_path, {"a.py": "# one\n# two\n"})
    baseline(root, {"a.py": 2})
    assert gate.main(["--root", str(root)]) == 0
    baseline(root, {"a.py": 1})
    assert gate.main(["--root", str(root)]) == 1
    assert "a.py: 2 > baseline 1" in capsys.readouterr().out


def test_a_baseline_for_one_file_does_not_cover_another(tmp_path):
    root = repo(tmp_path, {"a.py": "# one\n", "b.py": "# two\n"})
    baseline(root, {"a.py": 1})
    assert gate.main(["--root", str(root)]) == 1


def test_a_missing_baseline_allows_nothing(tmp_path):
    root = repo(tmp_path, {"a.py": "# one\n"})
    assert gate.main(["--root", str(root)]) == 1


def test_a_file_that_went_down_passes_and_says_to_lock_it(tmp_path, capsys):
    root = repo(tmp_path, {"a.py": "# one\n"})
    baseline(root, {"a.py": 3})
    assert gate.main(["--root", str(root)]) == 0
    assert "1 files went down" in capsys.readouterr().out


def test_write_baseline_lowers_counts_and_drops_clean_files(tmp_path):
    root = repo(tmp_path, {"a.py": "# one\n", "b.py": "x = 1\n"})
    path = baseline(root, {"a.py": 3, "b.py": 2, "gone.py": 1})
    assert gate.main(["--root", str(root), "--write-baseline"]) == 0
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["files"] == {"a.py": 1} and data["_meta"]["total"] == 1


def test_write_baseline_never_raises_a_limit(tmp_path):
    root = repo(tmp_path, {"a.py": "# one\n# two\n"})
    path = baseline(root, {"a.py": 1})
    assert gate.main(["--root", str(root), "--write-baseline"]) == 1
    assert json.loads(path.read_text(encoding="utf-8"))["files"] == {"a.py": 1}


def test_write_baseline_starts_a_baseline_where_there_is_none(tmp_path):
    root = repo(tmp_path, {"a.py": "# one\n"})
    assert gate.main(["--root", str(root), "--write-baseline"]) == 0
    path = root / "scripts" / "comments-baseline.json"
    assert json.loads(path.read_text(encoding="utf-8"))["files"] == {"a.py": 1}
    assert gate.main(["--root", str(root)]) == 0


def test_outside_a_git_work_tree_the_gate_stops_with_an_internal_error(tmp_path, capsys):
    assert gate.main(["--root", str(tmp_path)]) == 3
    assert "internal error" in capsys.readouterr().err


@pytest.mark.skipif(not (ROOT / ".git").exists(), reason="needs a git checkout")
def test_this_repository_is_within_its_baseline(capsys):
    assert gate.main([]) == 0, capsys.readouterr().out
