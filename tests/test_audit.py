from __future__ import annotations

import json
import socket
import urllib.request
from pathlib import Path

import pytest

from vinc_relate import audit, cli, external, semver
from vinc_relate import checkout as co

FIX = Path(__file__).resolve().parents[1] / "fixtures" / "audit"
CACHE = FIX / "osv-cache.json"


def osv_cache():
    return external.read_osv_cache(CACHE.read_text(encoding="utf-8"))


def advisories():
    return external.cached_advisories(osv_cache())


@pytest.fixture
def no_network(monkeypatch):
    def refuse(*a, **k):
        raise AssertionError("the network was used")
    monkeypatch.setattr(socket.socket, "connect", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)
    monkeypatch.setattr(socket, "getaddrinfo", refuse)


def lock():
    return (FIX / "demo-lockfile.json").read_text()


def test_the_lockfile_becomes_a_dependency_graph_with_nested_copies_resolved():
    nodes, edges = external.parse_npm_lock(lock(), "Demo")
    ids = {n["id"] for n in nodes}
    assert {"repo:Demo", "pkg:npm/lodash@4.17.15", "pkg:npm/lodash@4.17.21", "pkg:npm/report-kit@2.1.0"} <= ids
    pairs = {(e["source"], e["target"]) for e in edges}
    assert ("pkg:npm/report-kit@2.1.0", "pkg:npm/lodash@4.17.15") in pairs
    assert ("pkg:npm/test-kit@1.0.3", "pkg:npm/lodash@4.17.21") in pairs
    assert ("repo:Demo", "pkg:npm/test-kit@1.0.3") in pairs
    assert all(n["props"]["source_system"] == "npm-lockfile" for n in nodes)


def test_semver_ranges():
    events = [{"introduced": "0"}, {"fixed": "4.17.21"}]
    assert semver.in_range("4.17.15", events) is True
    assert semver.in_range("4.17.21", events) is False
    assert semver.in_range("1.0.0-beta.2", [{"introduced": "1.0.0-beta.1"}, {"fixed": "1.0.0"}]) is True
    assert semver.in_range("not-a-version", events) is None
    assert semver.affects("1.0.0", "npm", "x", [{"package": {"ecosystem": "PyPI", "name": "x"}, "ranges": []}]) is None


def test_the_audit_joins_dependency_paths_advisories_and_the_policies_that_govern_the_repository():
    rep = audit.run(co.load((FIX / "vinc.json").read_text()), lock(), "Demo", advisories=advisories())
    assert rep["loaded"] == {"nodes": 14, "edges": 15}
    assert {d["decision"] for d in rep["governing"]} == {"decision:no-high-advisories-in-shipped-dependencies", "decision:dependencies-are-pinned-by-a-lockfile"}
    violated = [f for f in rep["findings"] if any(p["verdict"] == "violated" for p in f["policies"])]
    assert {f["package"] for f in violated} == {"pkg:npm/lodash@4.17.15"}
    assert all(f["severity"] in ("HIGH", "CRITICAL") and f["status"] == "affected" and not f["dev_only"] for f in violated)
    assert violated[0]["path"] == ["repo:Demo", "pkg:npm/report-kit@2.1.0", "pkg:npm/lodash@4.17.15", violated[0]["advisory"]]
    dev = [f for f in rep["findings"] if f["dev_only"]]
    assert dev and all(p["verdict"] != "violated" for f in dev for p in f["policies"])
    lockfile_policy = [p for f in rep["findings"] for p in f["policies"] if p["decision"] == "decision:dependencies-are-pinned-by-a-lockfile"]
    assert {p["verdict"] for p in lockfile_policy} == {"relevant"}
    assert all(f["source_url"].startswith("https://osv.dev/vulnerability/") for f in rep["findings"])


def test_a_repository_without_a_code_ref_in_the_graph_gets_no_policy():
    rep = audit.run(co.load((FIX / "vinc.json").read_text()), lock(), "Other", advisories=advisories())
    assert rep["governing"] == [] and rep["violations"] == 0
    assert rep["summary"]["affected"] > 0


def test_the_cli_audit_reads_the_cache_offline_and_gives_the_same_report_every_time(no_network, tmp_path, capsys):
    args = ["audit", str(FIX / "vinc.json"), str(FIX / "demo-lockfile.json"), "--repo", "Demo", "--osv-cache", str(CACHE)]
    outs = []
    for i in range(2):
        assert cli.main(args + ["--out", str(tmp_path / f"r{i}.json")]) == 0
        outs.append((tmp_path / f"r{i}.json").read_text(encoding="utf-8"))
    capsys.readouterr()
    assert outs[0] == outs[1]
    rep = json.loads(outs[0])
    assert rep["summary"]["affected"] > 0 and rep["violations"] > 0


def test_a_cached_run_refuses_what_the_cache_does_not_hold(no_network, tmp_path, capsys):
    cache = osv_cache()
    del cache["queries"]["pkg:npm/minimist@1.2.8"]
    partial = tmp_path / "partial.json"
    partial.write_text(json.dumps(cache), encoding="utf-8")
    with pytest.raises(SystemExit) as e:
        cli.main(["audit", str(FIX / "vinc.json"), str(FIX / "demo-lockfile.json"), "--repo", "Demo", "--osv-cache", str(partial)])
    assert e.value.code == 1
    assert "pkg:npm/minimist@1.2.8 is not in the OSV cache" in capsys.readouterr().err
    opener = external.cache_opener(osv_cache())
    with pytest.raises(external.NetworkRefused):
        opener(urllib.request.Request(external.OSV_VULN.format(id="GHSA-0000-0000-0000")))


def test_a_live_audit_without_the_network_says_so_in_one_line_and_points_at_the_cache(monkeypatch, capsys):
    def refused(*a, **k):
        raise ConnectionRefusedError(111, "Connection refused")
    monkeypatch.setattr(socket, "create_connection", refused)
    monkeypatch.setattr(socket.socket, "connect", refused)
    with pytest.raises(SystemExit) as e:
        cli.main(["audit", str(FIX / "vinc.json"), str(FIX / "demo-lockfile.json"), "--repo", "Demo"])
    assert e.value.code == 1
    err = capsys.readouterr().err
    assert err.count("\n") == 1 and "Traceback" not in err
    assert err.startswith("vinc-relate: error: could not reach OSV at https://api.osv.dev/") and "--osv-cache" in err


def test_a_cache_without_its_fetch_time_is_refused(tmp_path, capsys):
    cache = osv_cache()
    del cache["fetched_at"]
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps(cache), encoding="utf-8")
    with pytest.raises(SystemExit) as e:
        cli.main(["audit", str(FIX / "vinc.json"), str(FIX / "demo-lockfile.json"), "--repo", "Demo", "--osv-cache", str(bad)])
    assert e.value.code == 2 and "fetched_at" in capsys.readouterr().err


def test_each_finding_carries_the_advisory_fetch_time_and_content_hash():
    cache = osv_cache()
    rep = audit.run(co.load((FIX / "vinc.json").read_text()), lock(), "Demo", advisories=advisories())
    for f in rep["findings"]:
        osv = f["advisory"].split(":", 1)[1]
        assert f["fetched_at"] == cache["fetched_at"]
        assert f["content_hash"] == external.digest(cache["vulns"][osv])
