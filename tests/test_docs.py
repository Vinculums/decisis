from __future__ import annotations

import json
import re
from pathlib import Path

from test_audit import no_network
from decisis import cli

ROOT = Path(__file__).resolve().parents[1]
README = (ROOT / "README.md").read_text(encoding="utf-8")
DATA_MODEL = (ROOT / "docs" / "data-model.md").read_text(encoding="utf-8")


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


def test_the_readme_table_is_the_committed_benchmark_table():
    committed = (ROOT / "bench" / "results.md").read_text(encoding="utf-8").split("\n\n")[0].strip()
    assert committed in README
