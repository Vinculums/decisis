from __future__ import annotations

import json
from pathlib import Path

import relate

from test_audit import no_network
from decisis import checkout as co
from decisis import cli, demo
from decisis.fake_vinc import FakeVinc

ROOT = Path(__file__).resolve().parents[1]
FIX = ROOT / "fixtures"
COMMITTED = ROOT / "demo"


def committed_findings() -> dict:
    return json.loads((COMMITTED / "expected_findings.json").read_text(encoding="utf-8"))


def run(tmp_path: Path, name: str, **kw) -> tuple[int, dict, Path]:
    out = tmp_path / name / "demo"
    shm = tmp_path / name / "shm"
    shm.mkdir(parents=True)
    code, transcript = demo.run(out, FIX, sandbox_root=shm, emit=lambda *_: None, **kw)
    assert list(shm.iterdir()) == []
    return code, transcript, out


def without_timestamps(transcript: dict) -> dict:
    return {k: v for k, v in transcript.items() if k != "timestamps"}


def test_the_approved_demo_finds_what_the_expected_findings_say_and_commits_them(tmp_path, no_network):
    want = committed_findings()
    code, transcript, out = run(tmp_path, "a", approve=want["digest"])
    assert code == 0
    assert transcript["findings"] == want
    assert json.loads((out / "expected_findings.json").read_text(encoding="utf-8")) == want
    assert json.loads((out / "transcript.json").read_text(encoding="utf-8")) == transcript
    assert transcript["approval"] == {"status": "approved", "digest": want["digest"], "by": "--approve"}
    last = transcript["steps"][-1]["data"]
    assert last["sandbox_removed"] is True
    assert last["receipt"]["verified"] and sorted(last["receipt"]["written"]) == sorted(want["records"])
    assert last["edges_after_checkout"] == len(want["edges"])
    assert [s["title"].split(":")[0] for s in transcript["steps"]] == [
        "Vinc knowledge", "The task", "Checkout", "Relate graph", "Multi-hop path", "Checker and approval", "Commit, read-back and cleanup"]


def test_the_multi_hop_path_runs_from_a_violated_decision_through_the_lockfile_to_an_advisory():
    path = committed_findings()["multi_hop_path"]
    assert path["ids"][0] == "decision:no-high-advisories-in-shipped-dependencies"
    assert path["ids"][2] == "repo:Demo" and path["ids"][-1].startswith("adv:GHSA-")
    assert path["rels"] == ["ABOUT", "DESCRIBED_BY", "DEPENDS_ON", "DEPENDS_ON", "AFFECTED_BY"]


def test_two_runs_give_the_same_transcript_apart_from_timestamps(tmp_path, no_network):
    _, first, _ = run(tmp_path, "a", yes=True)
    _, second, _ = run(tmp_path, "b", yes=True)
    assert without_timestamps(first) == without_timestamps(second)
    assert set(first["timestamps"]) == {"started_at", "checked_out_at", "read_back_at", "finished_at"}


def test_the_committed_transcript_matches_a_fresh_run(tmp_path, no_network):
    code, fresh, _ = run(tmp_path, "a", approve=committed_findings()["digest"])
    assert code == 0
    committed = json.loads((COMMITTED / "transcript.json").read_text(encoding="utf-8"))
    assert without_timestamps(committed) == without_timestamps(fresh)


def test_without_approval_nothing_is_written_and_a_wrong_digest_is_refused(tmp_path, no_network):
    code, pending, _ = run(tmp_path, "a")
    assert code == 0 and pending["approval"]["status"] == "pending"
    assert pending["steps"][-1]["data"]["receipt"] is None
    code, refused, _ = run(tmp_path, "b", approve="0" * 16)
    assert code == 1 and refused["approval"]["status"] == "refused"
    assert refused["steps"][-1]["data"]["receipt"] is None


def test_the_sample_database_opens_read_only_and_holds_the_task_graph(tmp_path, no_network):
    _, transcript, out = run(tmp_path, "a", yes=True)
    loaded = transcript["steps"][3]["data"]["loaded"]
    for path in (out / demo.SAMPLE, COMMITTED / demo.SAMPLE):
        con = relate.connect(str(path), read_only=True)
        try:
            nodes = dict(con.execute("MATCH (n) RETURN count(n) AS c").single())["c"]
            edges = dict(con.execute("MATCH ()-[r]->() RETURN count(r) AS c").single())["c"]
        finally:
            con.close()
        assert {"nodes": nodes, "edges": edges} == loaded


def test_checkout_from_the_synthetic_space_takes_only_the_audit_knowledge():
    space = co.load((FIX / "demo" / "vinc_space.json").read_text(encoding="utf-8"))
    got = co.checkout(FakeVinc(space), [demo.SEED], 1)
    want = co.load((FIX / "audit" / "vinc.json").read_text(encoding="utf-8"))
    assert [n["id"] for n in got.nodes] == sorted(n["id"] for n in want.nodes)
    assert {n["id"]: n["props"] for n in got.nodes} == {n["id"]: n["props"] for n in want.nodes}
    assert {(e["source"], e["type"], e["target"]) for e in got.edges} == {(e["source"], e["type"], e["target"]) for e in want.edges}


def test_the_cli_runs_the_demo_and_exits_zero_once_approved(tmp_path, no_network, capsys):
    assert cli.main(["demo", "--out", str(tmp_path / "demo"), "--yes"]) == 0
    text = capsys.readouterr().out
    assert "Persistent Knowledge. Ephemeral Reasoning." in text
    assert "Approved by a person with --yes" in text and "Operational sandbox deleted: yes." in text
