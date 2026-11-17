from __future__ import annotations

import copy
import functools
import json
import re
from pathlib import Path

import pytest

from test_audit import advisories, lock
from vinc_relate import audit
from vinc_relate import checkout as co
from vinc_relate import commit as wb

FIX = Path(__file__).resolve().parents[1] / "fixtures" / "audit"
NODE_ID = re.compile(r"^record:[a-z0-9]+(?:-[a-z0-9]+)*$")


def report():
    return audit.run(co.load((FIX / "vinc.json").read_text()), lock(), "Demo", advisories=advisories())


class FakeVinc:
    def __init__(self, existing=(), tamper=None):
        self.nodes = {i: {"id": i, "props": {}} for i in existing}
        self.edges, self.calls, self.tamper = [], [], tamper

    def tool(self, name, args):
        self.calls.append(name)
        if name == "vinc_node":
            n = self.nodes.get(args["node_id"])
            return {"found": n is not None, "node": n}
        if name == "vinc_ingest":
            assert args["create_only"] is True and args["operation_id"]
            for n in args["nodes"]:
                props = dict(n["props"])
                if self.tamper and n["id"] == self.tamper:
                    props["severity"] = "LOW"
                self.nodes[n["id"]] = {"id": n["id"], "props": props}
            self.edges += args["edges"]
            return {"executed": True, "warnings": []}
        if name == "vinc_neighbors":
            return {"neighbors": [{"id": e["to"]} for e in self.edges if e["from"] == args["node"]]}
        raise AssertionError(name)


def test_only_verified_findings_enter_the_write_set_with_ids_the_graph_accepts():
    plan = wb.propose(report(), "Demo", "space-1", today="2026-11-17")
    assert len(plan["nodes"]) == 7 and plan["held"] == []
    for n in plan["nodes"]:
        assert NODE_ID.match(n["id"]) and len(n["id"].split(":", 1)[1]) <= 60
        assert not re.search(r"\d{4}-\d{2}-\d{2}", n["id"])
        assert not any(v.replace(".", "-") in n["id"] for v in n["props"]["versions"])
        assert n["props"]["source"].startswith("https://osv.dev/") and n["props"]["measured_ref"]
        assert n["props"]["subject_path"] == "demo:package-lock.json"
    shipped = [n for n in plan["nodes"] if n["props"]["violates"]]
    assert shipped and all(n["props"]["scope"] == "shipped" and n["props"]["severity"] == "HIGH" for n in shipped)
    targets = {e["to"] for e in plan["edges"]}
    assert targets == {"decision:no-high-advisories-in-shipped-dependencies", "decision:dependencies-are-pinned-by-a-lockfile"}


def test_one_advisory_on_two_versions_in_one_scope_is_one_record():
    rep = report()
    twin = copy.deepcopy(rep["findings"][0])
    name, version = twin["package"].rsplit("@", 1)
    twin["package"] = f"{name}@0.0.1"
    rep["findings"].append(twin)
    plan = wb.propose(rep, "Demo", "space-1", today="2026-11-17")
    ids = [n["id"] for n in plan["nodes"]]
    assert len(ids) == len(set(ids)) == 7
    merged = next(n for n in plan["nodes"] if "0.0.1" in n["props"]["versions"])
    assert merged["props"]["versions"] == sorted(["0.0.1", version]) and len(merged["props"]["dependency_paths"]) == 2


def test_the_lockfile_path_and_commit_go_into_the_claim_fields():
    plan = wb.propose(report(), "Demo", "space-1", today="2026-11-17", lockfile_path="./app/package-lock.json", ref="abc123")
    assert {n["props"]["subject_path"] for n in plan["nodes"]} == {"demo:app/package-lock.json"}
    assert {n["props"]["measured_ref"] for n in plan["nodes"]} == {"abc123"}


def test_unverified_findings_are_held_back():
    rep = report()
    rep["findings"][0]["status"] = "unresolved"
    plan = wb.propose(rep, "Demo", "space-1", today="2026-11-17")
    assert len(plan["nodes"]) == 6 and len(plan["held"]) == 1


def test_nothing_is_written_without_the_matching_approval_or_after_the_plan_changed():
    plan = wb.propose(report(), "Demo", "space-1", today="2026-11-17")
    fake = FakeVinc()
    with pytest.raises(SystemExit):
        wb.commit(plan, "0" * 16, fake)
    edited = copy.deepcopy(plan)
    edited["nodes"][0]["props"]["severity"] = "LOW"
    with pytest.raises(SystemExit):
        wb.commit(edited, plan["digest"], fake)
    assert "vinc_ingest" not in fake.calls


def test_an_approved_write_is_read_back_and_existing_ids_are_left_alone():
    plan = wb.propose(report(), "Demo", "space-1", today="2026-11-17")
    first = plan["nodes"][0]["id"]
    fake = FakeVinc(existing=[first])
    receipt = wb.commit(plan, plan["digest"], fake)
    assert receipt["verified"], receipt["problems"]
    assert receipt["existing"] == [first] and first not in receipt["written"] and len(receipt["written"]) == 6
    assert fake.calls.count("vinc_ingest") == 1


def test_a_store_that_kept_something_else_fails_the_read_back():
    plan = wb.propose(report(), "Demo", "space-1", today="2026-11-17")
    fake = FakeVinc(tamper=plan["nodes"][1]["id"])
    receipt = wb.commit(plan, plan["digest"], fake)
    assert not receipt["verified"]
    assert any("stored props differ" in p for p in receipt["problems"])
