from __future__ import annotations

import json
import re
import shlex
from pathlib import Path

import pytest

from decisis import checkout as co
from decisis import check, cli, init, madr, rules

RULE = {"review_required": {"paths": ["src/payments/**"], "reviewers": ["@shop/payments"]}}


def new_adr(capsys, root: Path, *args: str) -> Path:
    capsys.readouterr()
    assert cli.main(["new-adr", *args, "--repo-dir", str(root)]) == 0
    return Path(json.loads(capsys.readouterr().out)["out"])


def refused(capsys, *args: str) -> str:
    capsys.readouterr()
    with pytest.raises(SystemExit) as e:
        cli.main(["new-adr", *args])
    assert e.value.code == 2
    return capsys.readouterr().err


def test_init_reads_the_new_adr_back_with_the_same_code_refs_and_rule(tmp_path, capsys):
    root = tmp_path / "repo"
    (root / "docs" / "adr").mkdir(parents=True)
    (root / "docs" / "adr" / "0002-use-postgres.md").write_text("# Use Postgres\n", encoding="utf-8")
    path = new_adr(capsys, root, "Retry payment calls once", "--code-ref", "src/payments/retry.py", "--code-ref", "src/payments/",
                   "--rule", json.dumps(RULE), "--date", "2026-11-25")
    assert path == root / "docs" / "adr" / "0003-retry-payment-calls-once.md"
    snap = init.build(root, "Shop")
    [node] = [n for n in snap["nodes"] if n["props"]["source_file"] == "docs/adr/0003-retry-payment-calls-once.md"]
    assert node["title"] == "Retry payment calls once"
    assert node["props"]["status"] == "proposed" and node["props"]["date"] == "2026-11-25"
    assert node["props"]["code_ref"] == ["Shop:src/payments/retry.py", "Shop:src/payments/"]
    assert node["props"]["rule"] == RULE
    assert not [p for p in snap["meta"]["problems"] if p["file"].endswith("0003-retry-payment-calls-once.md")]
    report = check.run(co.load(init.dump(snap)), ["src/payments/retry.py"], root, [], 3, "Shop")
    assert report["violations"]


def test_the_rule_is_refused_with_the_reason_audit_and_check_give_and_nothing_is_written(tmp_path, capsys):
    root = tmp_path / "repo"
    (root / "doc" / "adr").mkdir(parents=True)
    bad = {"review_required": {"paths": ["src/**"]}}
    err = refused(capsys, "Bad rule", "--repo-dir", str(root), "--rule", json.dumps(bad))
    assert rules.parse(bad).problems[0].reason in err
    assert "is not valid JSON" in refused(capsys, "Bad rule", "--repo-dir", str(root), "--rule", "{review")
    assert "one JSON object" in refused(capsys, "Bad rule", "--repo-dir", str(root), "--rule", json.dumps([RULE]))
    assert "not a path relative to the repository root" in refused(capsys, "Bad ref", "--repo-dir", str(root), "--code-ref", "/etc/passwd")
    assert "one line" in refused(capsys, "two\nlines", "--repo-dir", str(root))
    assert list((root / "doc" / "adr").iterdir()) == []


def test_the_directory_is_the_first_one_init_reads_or_adr_dir(tmp_path, capsys):
    root = tmp_path / "repo"
    for d in ("adr", "docs/decisions"):
        (root / d).mkdir(parents=True)
    assert new_adr(capsys, root, "First").parent == root / "docs" / "decisions"
    assert new_adr(capsys, root, "Second", "--adr-dir", "adr") == root / "adr" / "0001-second.md"
    assert new_adr(capsys, root, "Third", "--adr-dir", "records/adr") == root / "records" / "adr" / "0001-third.md"
    assert "outside the repository" in refused(capsys, "Out", "--repo-dir", str(root), "--adr-dir", "../elsewhere")
    empty = tmp_path / "empty"
    empty.mkdir()
    assert "no ADR directory" in refused(capsys, "None", "--repo-dir", str(empty))


def test_the_number_follows_the_highest_one_and_keeps_its_width(tmp_path, capsys):
    root = tmp_path / "repo"
    adr = root / "docs" / "adr"
    adr.mkdir(parents=True)
    for name in ("1-a.md", "12-b.md", "README.md", "0000-template.md"):
        (adr / name).write_text("# x\n", encoding="utf-8")
    assert new_adr(capsys, root, "Next one: with  punctuation!").name == "13-next-one-with-punctuation.md"
    assert madr.next_name(adr, "결정 기록") == "14-결정-기록.md"
    assert madr.next_name(adr, "!!!") == "14.md"


def test_an_existing_file_is_never_overwritten(tmp_path, capsys, monkeypatch):
    root = tmp_path / "repo"
    adr = root / "docs" / "adr"
    adr.mkdir(parents=True)
    (adr / "0001-taken.md").write_text("# Taken\n", encoding="utf-8")
    monkeypatch.setattr(madr, "next_name", lambda folder, title: "0001-taken.md")
    assert "already exists; nothing was written" in refused(capsys, "Taken", "--repo-dir", str(root))
    assert (adr / "0001-taken.md").read_text(encoding="utf-8") == "# Taken\n"


def test_the_data_model_example_writes_an_adr_init_reads(tmp_path, capsys):
    model = (Path(__file__).resolve().parents[1] / "docs" / "data-model.md").read_text(encoding="utf-8")
    shown = model[model.index("## A new ADR: `new-adr`"):]
    command = re.search(r"```\n(.*?)\n```", shown, re.S).group(1).replace("\\\n", " ")
    assert command.startswith("decisis new-adr ")
    args = shlex.split(command)[1:]
    root = tmp_path / "repo"
    (root / "docs" / "adr").mkdir(parents=True)
    path = new_adr(capsys, root, *args[1:])
    [node] = init.build(root)["nodes"]
    assert node["props"]["code_ref"] == ["src/payments/"] and node["props"]["source_file"] == path.relative_to(root).as_posix()
    assert not rules.parse(node["props"]["rule"]).problems


def test_a_default_adr_directory_that_links_outside_the_repository_is_refused(tmp_path, capsys):
    root, outside = tmp_path / "repo", tmp_path / "outside"
    (root / "docs").mkdir(parents=True)
    outside.mkdir()
    (root / "docs" / "adr").symlink_to(outside, target_is_directory=True)
    assert "the ADR directory docs/adr is a symbolic link, and init does not read it" in refused(capsys, "Escape", "--repo-dir", str(root))
    assert list(outside.iterdir()) == []


def test_an_adr_dir_through_a_symlink_loop_is_refused_with_a_clear_error(tmp_path, capsys):
    root = tmp_path / "repo"
    root.mkdir()
    (root / "l1").symlink_to("l2")
    (root / "l2").symlink_to("l1")
    assert "--adr-dir l1/sub cannot be resolved" in refused(capsys, "Loop", "--repo-dir", str(root), "--adr-dir", "l1/sub")


def test_an_adr_dir_that_is_a_dangling_link_is_refused_with_a_clear_error(tmp_path, capsys):
    root = tmp_path / "repo"
    root.mkdir()
    (root / "adr").symlink_to("missing")
    assert "cannot use adr as the ADR directory" in refused(capsys, "Dangling", "--repo-dir", str(root), "--adr-dir", "adr")
    assert not (root / "missing").exists()


def test_a_write_that_fails_after_the_file_is_created_leaves_no_file(tmp_path, capsys, monkeypatch):
    root = tmp_path / "repo"
    adr = root / "docs" / "adr"
    adr.mkdir(parents=True)
    real = Path.open

    def failing(self, *args, **kwargs):
        f = real(self, *args, **kwargs)
        if self.parent == adr:
            def write(_):
                raise OSError(27, "File too large")
            f.write = write
        return f

    monkeypatch.setattr(Path, "open", failing)
    err = refused(capsys, "Partial", "--repo-dir", str(root))
    assert "File too large; nothing was kept" in err
    assert list(adr.iterdir()) == []


def test_a_default_adr_directory_that_links_inside_the_repository_is_refused_and_init_would_not_read_it(tmp_path, capsys):
    root = tmp_path / "repo"
    (root / "records").mkdir(parents=True)
    (root / "docs").mkdir()
    (root / "docs" / "adr").symlink_to("../records", target_is_directory=True)
    err = refused(capsys, "Linked", "--repo-dir", str(root))
    assert "the ADR directory docs/adr is a symbolic link, and init does not read it" in err and "--adr-dir" in err
    assert list((root / "records").iterdir()) == []
    assert {p["file"]: p["action"] for p in init.build(root)["meta"]["problems"]}["docs/adr"] == "not read"


def test_a_default_adr_directory_that_is_a_submodule_is_refused(tmp_path, capsys):
    root = tmp_path / "repo"
    adr = root / "docs" / "adr"
    adr.mkdir(parents=True)
    (adr / ".git").write_text("gitdir: ../../.git/modules/adr\n", encoding="utf-8")
    assert "the ADR directory docs/adr is a git submodule" in refused(capsys, "Sub", "--repo-dir", str(root))
    assert sorted(p.name for p in adr.iterdir()) == [".git"]


def test_an_explicit_adr_dir_through_a_link_writes_where_init_with_the_same_adr_dir_reads(tmp_path, capsys):
    root = tmp_path / "repo"
    (root / "records").mkdir(parents=True)
    (root / "linked").symlink_to("records", target_is_directory=True)
    path = new_adr(capsys, root, "Through a link", "--adr-dir", "linked", "--code-ref", "src/")
    [node] = init.build(root, adr_dir="linked")["nodes"]
    assert node["title"] == "Through a link" and node["props"]["code_ref"] == ["src/"]
    assert path.resolve().parent == (root / "records").resolve()
