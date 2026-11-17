from __future__ import annotations

import functools
import io
import json
from pathlib import Path

from vinc_relate import audit, external, semver
from vinc_relate import checkout as co

FIX = Path(__file__).resolve().parents[1] / "fixtures" / "audit"
HITS = {("lodash", "4.17.15"): ["GHSA-29mw-wpgm-hmr9", "GHSA-35jh-r3h4-6jhm", "GHSA-p6mc-m468-83gw", "GHSA-r5fr-rjxr-66jc", "GHSA-xxjr-mmjv-4gpg"],
        ("lodash", "4.17.21"): ["GHSA-r5fr-rjxr-66jc", "GHSA-xxjr-mmjv-4gpg"]}


class Resp(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def osv_opener(req, timeout):
    queries = json.loads(req.data)["queries"]
    return Resp(json.dumps({"results": [{"vulns": [{"id": i} for i in HITS.get((q["package"]["name"], q["version"]), [])]} for q in queries]}).encode())


def advisories():
    cache = json.loads((FIX / "osv-cache.json").read_text())["vulns"]
    return functools.partial(external.fetch_advisories, opener=osv_opener, cache=cache)


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
