from __future__ import annotations

import itertools
import json
import random
from pathlib import Path

import pytest

from decisis import cli, codeowners, init
from test_init import owned_by, owners_repo


def refs(tmp_path: Path, codeowners_text: str, files: list[str], *owners: str) -> list[str]:
    return owned_by(init.build(owners_repo(tmp_path, codeowners_text, files)), *owners)["props"]["code_ref"]


def test_a_directory_the_lines_own_only_in_part_is_not_named_for_the_owners_of_the_one_folder_it_holds(tmp_path, capsys):
    root = owners_repo(tmp_path / "app", "src/payments/** @payments-team\n", ["src/payments/pay.py"])
    out = tmp_path / "snapshot.json"
    capsys.readouterr()
    assert cli.main(["init", "--repo-dir", str(root), "--repo", "GitApp", "--out", str(out)]) == 0
    snap = json.loads(out.read_text(encoding="utf-8"))
    [node] = [n for n in snap["nodes"] if n["kind"] == "concept"]
    assert node["props"]["code_ref"] == ["GitApp:src/payments/"]
    assert node["props"]["owners"] == ["@payments-team"] and node["props"]["source_lines"] == [1]


@pytest.mark.parametrize("line", ["src/payments/", "/src/payments", "/src/payments/", "src/payments/**", "/src/payments/**"])
def test_a_line_that_owns_a_whole_directory_makes_that_directory_the_path_and_not_its_parent(tmp_path, line):
    files = ["src/payments/pay.py", "src/payments/deep/er/refund.py"]
    assert refs(tmp_path, f"{line} @pay\n", files, "@pay") == ["src/payments/"]


@pytest.mark.parametrize("line,files,expected", [
    ("docs/**", ["docs/a.md", "docs/b/c.md"], ["docs/"]),
    ("docs/", ["docs/a.md", "docs/b/c.md"], ["docs/"]),
    ("*", ["README.md", "src/a.py", "src/b/c.py"], [".github/", "README.md", "src/"]),
    ("/src/", ["src/a.py", "src/b/c.py"], ["src/"]),
])
def test_a_directory_every_line_form_owns_wholly_still_folds_where_it_did(tmp_path, line, files, expected):
    assert refs(tmp_path, f"{line} @x\n", files, "@x") == expected


@pytest.mark.parametrize("line,files,expected", [
    ("*.py", ["src/a.py", "src/b.py"], ["src/a.py", "src/b.py"]),
    ("docs/*", ["docs/a.md", "docs/b.md"], ["docs/a.md", "docs/b.md"]),
    ("src/payments/*", ["src/payments/pay.py"], ["src/payments/pay.py"]),
    ("/src/payments/*.py", ["src/payments/pay.py", "src/payments/refund.py"], ["src/payments/pay.py", "src/payments/refund.py"]),
    ("src/**/*.py", ["src/a/pay.py"], ["src/a/pay.py"]),
])
def test_a_line_that_ends_in_a_wildcard_never_folds_into_a_directory_it_does_not_own_wholly(tmp_path, line, files, expected):
    assert refs(tmp_path, f"{line} @x\n", files, "@x") == expected


def test_a_later_narrower_line_stops_the_fold_above_it_even_when_its_directory_holds_no_file_yet(tmp_path):
    text = "src/payments/ @pay\nsrc/payments/legacy/ @other\n"
    assert refs(tmp_path / "empty", text, ["src/payments/pay.py"], "@pay") == ["src/payments/pay.py"]
    files = ["src/payments/pay.py", "src/payments/legacy/old.py"]
    assert refs(tmp_path / "held", text, files, "@pay") == ["src/payments/pay.py"]
    assert refs(tmp_path / "held-other", text, files, "@other") == ["src/payments/legacy/"]


@pytest.mark.parametrize("later", [
    "/src/payments/legacy/ @other",
    "/src/payments/legacy/old.py @other",
    "/src/payments/*.txt @other",
    "src/*/legacy/ @other",
    "/src/**/legacy/ @other",
    "/src/payments/legacy/** @other",
])
def test_a_later_line_that_names_a_path_below_the_directory_for_other_owners_keeps_it_out(tmp_path, later):
    assert refs(tmp_path, f"src/payments/ @pay\n{later}\n", ["src/payments/pay.py"], "@pay") == ["src/payments/pay.py"]


def test_a_later_line_with_the_same_owners_or_an_earlier_one_does_not_stop_the_fold(tmp_path):
    same = "src/payments/ @pay\nsrc/payments/legacy/ @pay\n"
    assert refs(tmp_path / "same", same, ["src/payments/pay.py"], "@pay") == ["src/payments/"]
    earlier = "src/payments/legacy/ @other\nsrc/payments/ @pay\n"
    assert refs(tmp_path / "earlier", earlier, ["src/payments/pay.py"], "@pay") == ["src/payments/"]


def test_a_later_line_with_no_owners_stops_the_fold_because_it_leaves_new_files_unowned(tmp_path):
    text = "src/payments/ @pay\nsrc/payments/legacy/\n"
    assert refs(tmp_path, text, ["src/payments/pay.py"], "@pay") == ["src/payments/pay.py"]


def test_a_line_above_a_narrower_directory_keeps_the_fold_above_a_sibling_it_does_not_reach(tmp_path):
    text = "* @all\n/src/payments/ @pay\n"
    files = ["src/a.py", "src/other/b.py", "src/payments/pay.py"]
    snap = init.build(owners_repo(tmp_path, text, files))
    assert owned_by(snap, "@all")["props"]["code_ref"] == [".github/", "src/a.py", "src/other/"]
    assert owned_by(snap, "@pay")["props"]["code_ref"] == ["src/payments/"]
    only = init.build(owners_repo(tmp_path / "only", text, ["src/a.py"]))
    assert owned_by(only, "@all")["props"]["code_ref"] == [".github/", "src/a.py"]


def test_a_later_line_that_matches_by_name_at_any_depth_is_not_read_as_owning_files_that_do_not_exist(tmp_path):
    text = "/src/logging/** @platform @ana\ndocs/ @docs\n*.md @docs\n"
    assert refs(tmp_path, text, ["src/logging/format.py", "src/logging/redact.py"], "@ana", "@platform") == ["src/logging/"]


def test_a_later_line_that_matches_by_name_still_splits_a_directory_holding_a_file_it_owns(tmp_path):
    text = "/src/logging/** @platform\ndocs/ @docs\n"
    snap = init.build(owners_repo(tmp_path, text, ["src/logging/a.py", "src/logging/docs/n.md"]))
    assert owned_by(snap, "@platform")["props"]["code_ref"] == ["src/logging/a.py"]
    assert owned_by(snap, "@docs")["props"]["code_ref"] == ["src/logging/docs/"]


def test_the_owners_lines_and_ids_of_existing_files_do_not_depend_on_how_the_paths_are_folded(tmp_path):
    text = "* @all\n/src/ @core\n/src/payments/ @pay\n/src/payments/legacy/ @pay @other\n*.md @docs\n/ops/*.sh @ops\n"
    files = ["README.md", "ops/run.sh", "ops/lib/x.py", "src/a.py", "src/payments/pay.py", "src/payments/legacy/old.py", "src/payments/notes.md"]
    snap = init.build(owners_repo(tmp_path, text, files))
    found = {tuple(n["props"]["owners"]): (n["props"]["code_ref"], n["props"]["source_lines"], n["id"]) for n in snap["nodes"]}
    assert {k: (v[0], v[1]) for k, v in found.items()} == {
        ("@all",): ([".github/", "ops/lib/"], [1]),
        ("@core",): (["src/a.py"], [2]),
        ("@docs",): (["README.md", "src/payments/notes.md"], [5]),
        ("@ops",): (["ops/run.sh"], [6]),
        ("@other", "@pay"): (["src/payments/legacy/"], [4]),
        ("@pay",): (["src/payments/pay.py"], [3]),
    }
    assert len({v[2] for v in found.values()}) == len(found)
    assert [x for x in snap["meta"]["problems"] if x["file"] == ".github/CODEOWNERS"] == []


NAMES = ("a", "b", "x.py")
TOKENS = ("a", "b", "*", "a*", "?", "*.py", "**")


def owner_of(rules: list[codeowners.Rule], path: str) -> tuple[str, ...] | None:
    rule = next((r for r in reversed(rules) if r.regex.fullmatch(path)), None)
    return rule.owners if rule is not None and rule.owners else None


def random_rules(rng: random.Random) -> list[codeowners.Rule]:
    rules = []
    for line in range(1, rng.randint(1, 5) + 1):
        while True:
            segments = [rng.choice(TOKENS) for _ in range(rng.randint(1, 3))]
            if segments[0] == "**":
                continue
            pattern = "/" + "/".join(segments) + ("/" if rng.random() < 0.4 else "")
            try:
                regex = codeowners.compile_pattern(pattern)
            except codeowners.Unsupported:
                continue
            break
        owners = tuple(sorted(rng.sample(["@p", "@q", "@r"], rng.randint(1, 2))))
        rules.append(codeowners.Rule(line, pattern, owners, regex))
    return rules


def test_every_directory_named_for_an_owner_set_gives_that_set_to_every_path_below_it():
    below = ["/".join(c) for n in range(1, 5) for c in itertools.product(NAMES, repeat=n)]
    rng = random.Random(20261125)
    folded = 0
    for _ in range(250):
        rules = random_rules(rng)
        files = sorted({rng.choice(below) for _ in range(rng.randint(1, 6))})
        files = [f for f in files if not any(g.startswith(f + "/") for g in files)]
        won = codeowners.owning_rules(rules, files)
        for owners, paths in codeowners.cover(files, {f: r.owners for f, r in won.items()}, rules).items():
            for path in paths:
                assert any(f == path or f.startswith(path) for f in files)
                if path.endswith("/"):
                    folded += 1
                    assert all(owner_of(rules, path + tail) == owners for tail in below if len(path.split("/")) + len(tail.split("/")) <= 6), \
                        ([(r.pattern, r.owners) for r in rules], files, path)
    assert folded > 100
