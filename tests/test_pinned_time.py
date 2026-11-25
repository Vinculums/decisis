from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from test_audit import no_network
from decisis import audit, cli, external
from decisis.inventory import npm, shape
from decisis.sandbox import Subgraph

ROOT = Path(__file__).resolve().parents[1]
BOOKSHOP = ROOT / "examples" / "bookshop"
CACHE = json.loads((BOOKSHOP / "osv-cache.json").read_text(encoding="utf-8"))
CLOCKS = ["2030-01-01T00:00:00Z", "2031-06-15T12:30:00Z"]


def at(monkeypatch, clock: str) -> None:
    monkeypatch.setattr(shape, "now", lambda: clock)
    monkeypatch.setattr(npm, "now", lambda: clock)


def run(capsys, *args: str) -> tuple[int, str]:
    capsys.readouterr()
    code = cli.main(list(args))
    return code, capsys.readouterr().out


@pytest.mark.parametrize("inventory", ["app/.github/workflows/ci.yml", "app/package-lock.json"])
def test_a_cached_audit_prints_the_same_bytes_whatever_the_clock_says(tmp_path, capsys, monkeypatch, no_network, inventory):
    shutil.copytree(BOOKSHOP, tmp_path / "bookshop")
    monkeypatch.chdir(tmp_path / "bookshop")
    outputs = []
    for clock in CLOCKS:
        at(monkeypatch, clock)
        code, out = run(capsys, "audit", "snapshot.json", inventory, "--repo", "Bookshop", "--osv-cache", "osv-cache.json", "--today", "2026-11-25")
        outputs.append(out)
        assert clock not in out
    assert outputs[0] == outputs[1]
    stamps = {f["fetched_at"] for f in json.loads(outputs[0])["findings"]}
    assert stamps <= {CACHE["fetched_at"]} | {e["fetched_at"] for e in (CACHE.get("names") or {}).values()}


def test_propose_gives_the_same_write_set_and_digest_whatever_the_clock_says(tmp_path, capsys, monkeypatch, no_network):
    shutil.copytree(BOOKSHOP, tmp_path / "bookshop")
    monkeypatch.chdir(tmp_path / "bookshop")
    flags = ["--repo", "Bookshop", "--osv-cache", "osv-cache.json"]
    plans = []
    for n, clock in enumerate(CLOCKS):
        at(monkeypatch, clock)
        report, plan = f"report{n}.json", f"plan{n}.json"
        run(capsys, "audit", "snapshot.json", "app/.github/workflows/ci.yml", *flags, "--today", "2026-11-25", "--out", report)
        run(capsys, "propose", report, "snapshot.json", "app/.github/workflows/ci.yml", *flags, "--space", "demo-space", "--out", plan)
        plans.append(json.loads(Path(plan).read_text(encoding="utf-8")))
    assert plans[0] == plans[1]
    records = [n for n in plans[0]["nodes"] if n["props"].get("inventory_fetched_at")]
    assert records and {r["props"]["inventory_fetched_at"] for r in records} == {CACHE["fetched_at"]}


def test_without_a_cache_the_inventory_keeps_the_time_it_was_read(monkeypatch):
    at(monkeypatch, CLOCKS[0])
    lock = (BOOKSHOP / "app" / "package-lock.json").read_text(encoding="utf-8")
    graph = audit.compose(Subgraph([], [], {}), lock, "Bookshop", advisories=lambda packages: ([], []))
    assert {n["props"]["fetched_at"] for n in graph.nodes if "fetched_at" in n["props"]} == {CLOCKS[0]}
    assert external.pinned_at(lambda packages: ([], [])) is None
    assert external.pinned_at(external.cached_advisories(external.read_osv_cache(json.dumps(CACHE)))) == CACHE["fetched_at"]
