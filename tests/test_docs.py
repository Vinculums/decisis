from __future__ import annotations

import json
import re
from pathlib import Path

from test_audit import no_network
from decisis import cli

ROOT = Path(__file__).resolve().parents[1]
README = (ROOT / "README.md").read_text(encoding="utf-8")
DATA_MODEL = (ROOT / "docs" / "data-model.md").read_text(encoding="utf-8")
BENCHMARK = (ROOT / "docs" / "benchmark.md").read_text(encoding="utf-8")


def example(tmp_path: Path) -> str:
    block = re.search(r"```json\n(.*?)```", DATA_MODEL, re.S).group(1)
    path = tmp_path / "my-snapshot.json"
    path.write_text(block, encoding="utf-8")
    return str(path)


def run(capsys, *args: str) -> str:
    capsys.readouterr()
    assert cli.main(list(args)) == 0
    return capsys.readouterr().out


def test_the_hand_written_snapshot_runs_paths_impact_and_audit_offline(tmp_path, capsys, no_network):
    snap = example(tmp_path)
    paths = json.loads(run(capsys, "paths", snap, "record:checkout-timeout-october", "concept:shop-web"))
    assert paths["paths"][0]["ids"] == ["record:checkout-timeout-october", "concept:checkout-flow", "concept:shop-web"]
    text = run(capsys, "impact", snap, "src/checkout/pay.py", "--format", "text")
    assert "decision:no-high-advisories-when-shipped  via concept:shop-web" in text
    assert "record:checkout-timeout-october  via concept:checkout-flow" in text
    report = json.loads(run(capsys, "audit", snap, str(ROOT / "fixtures/audit/demo-lockfile.json"), "--repo", "Shop",
                            "--osv-cache", str(ROOT / "fixtures/audit/osv-cache.json")))
    assert report["violations"] == 3
    assert {f["package"] for f in report["findings"] if any(p["verdict"] == "violated" for p in f["policies"])} == {"pkg:npm/lodash@4.17.15"}


def test_the_readme_digest_is_the_one_the_demo_prints():
    digest = json.loads((ROOT / "demo" / "expected_findings.json").read_text(encoding="utf-8"))["digest"]
    assert f"decisis demo --approve {digest}" in README


def test_the_benchmark_doc_table_is_the_committed_benchmark_table():
    committed = (ROOT / "bench" / "results.md").read_text(encoding="utf-8").split("\n\n")[0].strip()
    assert committed in BENCHMARK


def test_the_readme_quick_start_prints_what_the_readme_shows(tmp_path, capsys, no_network):
    block = re.search(r"```json\n(.*?)```", README, re.S).group(1)
    snap = tmp_path / "my-snapshot.json"
    snap.write_text(block, encoding="utf-8")
    shown = re.search(r"\$ decisis impact my-snapshot.json src/checkout/pay.py --format text\n(.*?)```", README, re.S).group(1)
    out = run(capsys, "impact", str(snap), "src/checkout/pay.py", "--format", "text")
    assert out.strip() == shown.strip()
    report = json.loads(run(capsys, "audit", str(snap), str(ROOT / "fixtures/audit/demo-lockfile.json"), "--repo", "Shop",
                            "--osv-cache", str(ROOT / "fixtures/audit/osv-cache.json")))
    assert report["violations"] == 3


def test_the_readme_check_example_prints_what_the_readme_shows(capsys, no_network):
    shown = re.search(r"\$ decisis check (.*?)\n(.*?)```", README, re.S)
    args = shown.group(1).split()
    args = [str(ROOT / a) if a.startswith("fixtures/") else a for a in args]
    capsys.readouterr()
    assert cli.main(["check", *args]) == 1
    assert capsys.readouterr().out.strip() == shown.group(2).strip()


def help_commands(capsys) -> list[str]:
    capsys.readouterr()
    try:
        cli.main(["--help"])
    except SystemExit as e:
        assert e.code == 0
    usage = capsys.readouterr().out
    return re.search(r"\{([a-z,]+)\}", usage).group(1).split(",")


def test_every_subcommand_in_the_help_has_a_row_in_the_readme_commands_table(capsys):
    commands = help_commands(capsys)
    assert len(commands) >= 13 and "serve" in commands and "check" in commands
    start = README.index("\n## Commands")
    table = README[start:README.index("\n## ", start + 1)]
    missing = [c for c in commands if not re.search(rf"^\| `{c}[ `]", table, re.M)]
    assert missing == []


def test_the_readme_says_the_old_name_was_removed_and_nothing_installs_it():
    history = README[README.index("## Name and history"):]
    assert "vinc-relate" in history and "removed in 0.2.0" in history
    assert "vinc-relate" not in (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert not (ROOT / "src" / "vinc_relate").exists()
