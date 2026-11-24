from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import time
import uuid
from pathlib import Path

import pytest

from decisis import audit, cli
from decisis import checkout as co
from decisis import sandbox as sb
from decisis.sandbox import Limits, QueryTimeout, Sandbox, Subgraph, TooLarge, sandbox

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "fixtures" / "vinc_subgraph.json"
AUDIT = [str(ROOT / "fixtures/audit/vinc.json"), str(ROOT / "fixtures/audit/demo-lockfile.json"), "--repo", "Demo",
         "--osv-cache", str(ROOT / "fixtures/audit/osv-cache.json")]
SLOW = "MATCH p = (a {id: 'n0'})-[*1..12]->() RETURN count(p) AS c"
sweeps = pytest.mark.skipif(not sb.can_sweep(), reason="this platform cannot check the owner of a task directory")


def graph() -> Subgraph:
    return co.load(FIXTURE.read_text(encoding="utf-8"))


def dense(n: int = 12) -> Subgraph:
    nodes = [{"id": f"n{i}", "kind": "concept", "title": f"n{i}"} for i in range(n)]
    edges = [{"source": f"n{i}", "target": f"n{j}", "type": "RELATED_TO"} for i in range(n) for j in range(n) if i != j]
    return Subgraph(nodes, edges, {})


def left(root: Path) -> list[str]:
    return sorted(p.name for p in root.iterdir() if p.name.startswith("decisis-"))


@pytest.fixture
def scratch(tmp_path, monkeypatch):
    monkeypatch.setattr(sb, "TMPFS", tmp_path)
    return tmp_path


@pytest.fixture
def dead_pid() -> int:
    proc = subprocess.Popen([sys.executable, "-c", "pass"])
    proc.wait()
    return proc.pid


def task_dir(root: Path, pid: int | None, age: float = 3600, start: str | None = None, host: str | None = None, name: str | None = None) -> Path:
    d = root / (name or f"decisis-{uuid.uuid4().hex}")
    d.mkdir(mode=0o700)
    if pid is not None:
        (d / sb.OWNER).write_text(json.dumps({"pid": pid, "start": start, "host": host or socket.gethostname()}), encoding="utf-8")
    (d / "task.rl").write_bytes(b"task")
    old = time.time() - age
    os.utime(d, (old, old))
    return d


def test_a_graph_over_the_node_or_edge_cap_is_refused_before_anything_is_written(tmp_path):
    for limits, message in [(Limits(max_nodes=4), "5 nodes, over the cap of 4"), (Limits(max_edges=3), "4 edges, over the cap of 3")]:
        with sandbox(tmp_path, limits) as box:
            with pytest.raises(TooLarge, match=message):
                box.load(graph())
            assert not box.path.exists() and not box.loaded
        assert left(tmp_path) == []
    with sandbox(tmp_path, Limits(max_nodes=5, max_edges=4)) as box:
        assert box.load(graph()) == {"nodes": 5, "edges": 4}


def test_the_caps_default_and_can_be_raised_by_flag_or_environment_up_to_a_ceiling():
    assert Limits.resolve(env={}) == Limits(sb.MAX_NODES, sb.MAX_EDGES, sb.QUERY_SECONDS)
    env = {"DECISIS_MAX_NODES": "200000", "DECISIS_MAX_EDGES": "900000", "DECISIS_QUERY_TIMEOUT": "120"}
    assert Limits.resolve(env=env) == Limits(200000, 900000, 120)
    assert Limits.resolve(7, None, 3, env=env) == Limits(7, 900000, 3)
    for name, value in [("DECISIS_MAX_NODES", str(sb.CEILING_NODES + 1)), ("DECISIS_MAX_EDGES", "0"), ("DECISIS_QUERY_TIMEOUT", "soon")]:
        with pytest.raises(ValueError, match=name):
            Limits.resolve(env={name: value})
    with pytest.raises(ValueError, match="DECISIS_MAX_NODES must be between 1 and"):
        Limits.resolve(sb.CEILING_NODES + 1, env={})


def test_the_cli_refuses_an_oversized_snapshot_with_a_clear_error(scratch, capsys, monkeypatch):
    with pytest.raises(SystemExit) as e:
        cli.main(["paths", str(FIXTURE), "record:tls-advisory-example", "concept:service-api", "--max-nodes", "4"])
    err = capsys.readouterr().err
    assert e.value.code == 1 and "over the cap of 4" in err and "--max-nodes" in err and "Traceback" not in err
    monkeypatch.setenv("DECISIS_MAX_EDGES", "1")
    with pytest.raises(SystemExit) as e:
        cli.main(["impact", str(FIXTURE), "services/api"])
    assert e.value.code == 1 and "2 edges, over the cap of 1" in capsys.readouterr().err
    with pytest.raises(SystemExit) as e:
        cli.main(["paths", str(FIXTURE), "a", "b", "--max-nodes", str(sb.CEILING_NODES + 1)])
    assert e.value.code == 2 and "argument --max-nodes" in capsys.readouterr().err
    monkeypatch.setenv("DECISIS_MAX_EDGES", "lots")
    with pytest.raises(SystemExit) as e:
        cli.main(["paths", str(FIXTURE), "a", "b"])
    assert e.value.code == 2 and "DECISIS_MAX_EDGES='lots' is not a whole number" in capsys.readouterr().err
    assert left(scratch) == []


def test_audit_depth_is_bounded_like_paths_hops(scratch, capsys):
    for value in ["0", str(audit.MAX_DEPTH + 1), "x"]:
        with pytest.raises(SystemExit) as e:
            cli.main(["audit", *AUDIT, "--depth", value])
        err = capsys.readouterr().err
        assert e.value.code == 2 and "argument --depth" in err and "Traceback" not in err
    assert cli.main(["audit", *AUDIT, "--depth", str(audit.MAX_DEPTH)]) == 0
    assert json.loads(capsys.readouterr().out)["findings"]
    with sandbox(scratch) as box, pytest.raises(ValueError, match="depth must be between 1 and"):
        audit.analyze(box, graph(), "Demo", depth=audit.MAX_DEPTH + 1)


def test_a_query_over_the_time_limit_is_stopped_and_the_directory_is_removed(tmp_path):
    started = time.monotonic()
    with sandbox(tmp_path, Limits(query_seconds=1)) as box:
        box.load(dense())
        with pytest.raises(QueryTimeout, match="ran longer than 1 s and was stopped"):
            box.query(SLOW)
        assert time.monotonic() - started < 30
        assert box.query("MATCH (n) RETURN count(n) AS c") == [{"c": 12}]
    assert left(tmp_path) == []


def test_the_query_process_is_killed_when_the_limit_is_reached(tmp_path):
    with sandbox(tmp_path, Limits(query_seconds=1)) as box:
        box.load(dense())
        box.query("MATCH (n) RETURN count(n) AS c")
        worker = sb._shared[0]
        with pytest.raises(QueryTimeout):
            box.query(SLOW)
        assert worker.proc.poll() is not None and worker not in sb._shared


def test_the_cli_stops_a_slow_query_prints_a_clear_error_and_exits_non_zero(scratch, capsys):
    snap = scratch / "dense.json"
    g = dense()
    snap.write_text(json.dumps({"meta": {}, "nodes": g.nodes, "edges": g.edges}), encoding="utf-8")
    with pytest.raises(SystemExit) as e:
        cli.main(["paths", str(snap), "n0", "n1", "--hops", "6", "--query-timeout", "1"])
    err = capsys.readouterr().err
    assert e.value.code == 1 and "decisis: error: the query ran longer than 1 s and was stopped" in err and "Traceback" not in err
    assert left(scratch) == []


def test_a_task_directory_records_its_owner_process(tmp_path):
    with sandbox(tmp_path) as box:
        owner = json.loads((box.dir / sb.OWNER).read_text(encoding="utf-8"))
        assert owner["pid"] == os.getpid() and owner["host"] == socket.gethostname()
        assert owner["start"] == sb._start_time(os.getpid())
        assert (box.dir / sb.OWNER).stat().st_mode & 0o777 == 0o600


@sweeps
def test_a_new_sandbox_removes_the_directory_a_killed_run_left(tmp_path):
    code = "import sys, time; from decisis.sandbox import Sandbox; print(Sandbox(__import__('pathlib').Path(sys.argv[1])).dir, flush=True); time.sleep(60)"
    proc = subprocess.Popen([sys.executable, "-c", code, str(tmp_path)], stdout=subprocess.PIPE, text=True)
    orphan = Path(proc.stdout.readline().strip())
    proc.kill()
    proc.wait()
    proc.stdout.close()
    assert orphan.is_dir()
    old = time.time() - sb.GRACE_SECONDS - 60
    os.utime(orphan, (old, old))
    with sandbox(tmp_path) as box:
        assert left(tmp_path) == [box.dir.name]


@sweeps
def test_a_dead_owner_is_removed_and_a_live_one_is_kept(tmp_path, dead_pid):
    dead = task_dir(tmp_path, dead_pid)
    live = task_dir(tmp_path, os.getpid(), start=sb._start_time(os.getpid()))
    unknown_start = task_dir(tmp_path, os.getpid())
    assert sb.sweep(tmp_path) == [dead]
    assert left(tmp_path) == sorted([live.name, unknown_start.name])


@sweeps
@pytest.mark.skipif(sb._start_time(os.getpid()) is None, reason="no process start time on this platform")
def test_a_pid_reused_by_another_process_does_not_keep_the_directory(tmp_path):
    reused = task_dir(tmp_path, os.getpid(), start="1")
    assert sb.sweep(tmp_path) == [reused]


@sweeps
def test_young_unowned_misnamed_and_foreign_host_directories_are_kept(tmp_path, dead_pid):
    kept = [task_dir(tmp_path, dead_pid, age=10), task_dir(tmp_path, None), task_dir(tmp_path, dead_pid, host="elsewhere"),
            task_dir(tmp_path, dead_pid, name="decisis-notahexname"), task_dir(tmp_path, dead_pid, name=f"decisis-{uuid.uuid4().hex}0"),
            task_dir(tmp_path, dead_pid, name=f"other-{uuid.uuid4().hex}")]
    (task_dir(tmp_path, None) / sb.OWNER).write_text(json.dumps({"pid": 0}), encoding="utf-8")
    assert sb.sweep(tmp_path) == []
    assert all(d.is_dir() for d in kept)


@sweeps
def test_another_users_directory_is_never_touched(tmp_path, dead_pid, monkeypatch):
    theirs = task_dir(tmp_path, dead_pid)
    real = os.getuid()
    monkeypatch.setattr(sb.os, "getuid", lambda: real + 1)
    assert sb.sweep(tmp_path) == []
    assert theirs.is_dir()


@sweeps
def test_a_sweep_stays_inside_its_own_root(tmp_path, dead_pid):
    mine, other = tmp_path / "mine", tmp_path / "other"
    mine.mkdir()
    other.mkdir()
    there = task_dir(other, dead_pid)
    here = task_dir(mine, dead_pid)
    assert sb.sweep(mine) == [here]
    assert there.is_dir()


@sweeps
def test_a_symlink_is_never_followed(tmp_path, dead_pid):
    root, elsewhere = tmp_path / "root", tmp_path / "elsewhere"
    root.mkdir()
    elsewhere.mkdir()
    target = task_dir(elsewhere, dead_pid)
    link = root / f"decisis-{uuid.uuid4().hex}"
    link.symlink_to(target, target_is_directory=True)
    keep = elsewhere / "keep.txt"
    keep.write_text("keep", encoding="utf-8")
    stale = task_dir(root, dead_pid)
    (stale / "outside").symlink_to(elsewhere, target_is_directory=True)
    (stale / "file").symlink_to(keep)
    old = time.time() - 3600
    os.utime(stale, (old, old))
    assert sb.sweep(root) == [stale]
    assert link.is_symlink() and target.is_dir() and keep.read_text(encoding="utf-8") == "keep"


@sweeps
def test_a_symlinked_owner_record_is_not_read(tmp_path, dead_pid):
    record = tmp_path / "record.json"
    record.write_text(json.dumps({"pid": dead_pid, "host": socket.gethostname()}), encoding="utf-8")
    d = task_dir(tmp_path, None)
    (d / sb.OWNER).symlink_to(record)
    old = time.time() - 3600
    os.utime(d, (old, old))
    assert sb.sweep(tmp_path) == []


@sweeps
def test_a_server_directory_is_swept_under_the_same_rules(tmp_path, dead_pid, monkeypatch):
    serve = lambda pid, **kw: task_dir(tmp_path, pid, name=kw.pop("name", f"{sb.SERVE_PREFIX}{uuid.uuid4().hex}"), **kw)
    stale = serve(dead_pid)
    kept = [serve(os.getpid(), start=sb._start_time(os.getpid())), serve(dead_pid, age=10), serve(None), serve(dead_pid, host="elsewhere"),
            serve(dead_pid, name="decisis-serve-notahexname"), serve(dead_pid, name=f"decisis-serve-{uuid.uuid4().hex}0"),
            serve(dead_pid, name=f"decisis-serve-{uuid.uuid4().hex.upper()}"), serve(dead_pid, name=f"decisis-servo-{uuid.uuid4().hex}")]
    link = tmp_path / f"{sb.SERVE_PREFIX}{uuid.uuid4().hex}"
    link.symlink_to(serve(dead_pid, name="elsewhere"), target_is_directory=True)
    (stale / "outside").symlink_to(kept[0], target_is_directory=True)
    old = time.time() - 3600
    os.utime(stale, (old, old))
    assert sb.sweep(tmp_path) == [stale]
    assert all(d.is_dir() for d in kept) and link.is_symlink() and (kept[0] / "task.rl").is_file()
    theirs = serve(dead_pid)
    real = os.getuid()
    monkeypatch.setattr(sb.os, "getuid", lambda: real + 1)
    assert sb.sweep(tmp_path) == [] and theirs.is_dir()


@sweeps
def test_gc_removes_stale_directories_on_demand_and_prints_them(tmp_path, dead_pid, capsys):
    stale = task_dir(tmp_path, dead_pid)
    live = task_dir(tmp_path, os.getpid())
    assert cli.main(["gc", "--root", str(tmp_path)]) == 0
    out = capsys.readouterr().out
    assert f"removed {stale}" in out and f"removed 1 task directory under {tmp_path}" in out
    assert not stale.exists() and live.is_dir()
    assert cli.main(["gc", "--root", str(tmp_path)]) == 0
    assert "removed 0 task directories" in capsys.readouterr().out


def test_gc_degrades_where_ownership_cannot_be_checked(tmp_path, dead_pid, capsys, monkeypatch):
    stale = task_dir(tmp_path, dead_pid)
    monkeypatch.setattr(sb, "can_sweep", lambda: False)
    assert cli.main(["gc", "--root", str(tmp_path)]) == 0
    assert "nothing was removed" in capsys.readouterr().out and stale.is_dir()
    assert sb.sweep(tmp_path) == [] and stale.is_dir()


def test_propose_rederives_under_the_same_caps_and_depth_bounds(scratch, capsys):
    report = scratch / "report.json"
    assert cli.main(["audit", *AUDIT, "--out", str(report)]) == 0
    args = ["propose", str(report), AUDIT[0], AUDIT[1], "--repo", "Demo", "--space", "demo-space", "--osv-cache", AUDIT[5],
            "--out", str(scratch / "plan.json")]
    capsys.readouterr()
    with pytest.raises(SystemExit) as e:
        cli.main([*args, "--max-nodes", "4"])
    err = capsys.readouterr().err
    assert e.value.code == 1 and "over the cap of 4" in err and "Traceback" not in err
    with pytest.raises(SystemExit) as e:
        cli.main([*args, "--depth", str(audit.MAX_DEPTH + 1)])
    assert e.value.code == 2 and "argument --depth" in capsys.readouterr().err
    assert cli.main([*args, "--query-timeout", "30"]) == 0
    assert left(scratch) == []


@sweeps
def test_a_pid_too_large_for_the_platform_keeps_the_directory_without_an_error(tmp_path, capsys):
    huge = task_dir(tmp_path, 2**40)
    assert sb._read_owner(huge) is None
    assert sb._alive({"pid": 2**40, "start": None}) is True
    assert sb.sweep(tmp_path) == []
    with sandbox(tmp_path) as box:
        assert left(tmp_path) == sorted([huge.name, box.dir.name])
    assert cli.main(["gc", "--root", str(tmp_path)]) == 0
    assert "removed 0 task directories" in capsys.readouterr().out and huge.is_dir()


@sweeps
def test_an_unexpected_error_on_one_entry_keeps_it_and_the_sweep_goes_on(tmp_path, dead_pid, monkeypatch, capsys):
    broken, stale = task_dir(tmp_path, dead_pid), task_dir(tmp_path, dead_pid)
    real = sb._stale

    def flaky(path, grace):
        if path == broken:
            raise RuntimeError("cannot judge this one")
        return real(path, grace)

    monkeypatch.setattr(sb, "_stale", flaky)
    assert cli.main(["gc", "--root", str(tmp_path)]) == 0
    out = capsys.readouterr().out
    assert f"removed {stale}" in out and f"kept {broken}: RuntimeError: cannot judge this one" in out
    assert broken.is_dir() and not stale.exists()


def test_a_failing_sweep_never_stops_a_new_sandbox(tmp_path, monkeypatch):
    def boom(root, grace=sb.GRACE_SECONDS, errors=None):
        raise OverflowError("signed integer is greater than maximum")

    monkeypatch.setattr(sb, "sweep", boom)
    with sandbox(tmp_path) as box:
        assert box.load(graph()) == {"nodes": 5, "edges": 4}
