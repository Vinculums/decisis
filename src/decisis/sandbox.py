from __future__ import annotations

import atexit
import builtins
import json
import math
import os
import pickle
import queue
import re
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator, Mapping

import relate

TMPFS = Path("/dev/shm")
TASK_PREFIX = "decisis-"
SERVE_PREFIX = "decisis-serve-"
TASK_DIR = re.compile(r"decisis-(?:serve-)?[0-9a-f]{32}")
OWNER = "owner.json"
GRACE_SECONDS = 600
MAX_PID = 2**31 - 1

MAX_NODES = 50_000
MAX_EDGES = 250_000
QUERY_SECONDS = 60
CEILING_NODES = 1_000_000
CEILING_EDGES = 5_000_000
CEILING_SECONDS = 3600


@dataclass(frozen=True)
class Subgraph:
    nodes: list[dict]
    edges: list[dict]
    meta: dict = field(default_factory=dict)


class LimitExceeded(Exception):
    pass


class TooLarge(LimitExceeded):
    pass


class QueryTimeout(LimitExceeded):
    pass


class NotReadOnly(ValueError):
    pass


@dataclass(frozen=True)
class Limits:
    max_nodes: int = MAX_NODES
    max_edges: int = MAX_EDGES
    query_seconds: float = QUERY_SECONDS

    @classmethod
    def resolve(cls, max_nodes: int | None = None, max_edges: int | None = None, query_seconds: int | None = None,
                env: Mapping[str, str] = os.environ) -> Limits:
        return cls(_pick(max_nodes, env, "DECISIS_MAX_NODES", MAX_NODES, CEILING_NODES),
                   _pick(max_edges, env, "DECISIS_MAX_EDGES", MAX_EDGES, CEILING_EDGES),
                   _pick(query_seconds, env, "DECISIS_QUERY_TIMEOUT", QUERY_SECONDS, CEILING_SECONDS))


def _pick(value: int | None, env: Mapping[str, str], name: str, default: int, ceiling: int) -> int:
    if value is None:
        text = env.get(name, "").strip()
        if not text:
            return default
        try:
            value = int(text)
        except ValueError:
            raise ValueError(f"{name}={text!r} is not a whole number") from None
    if not 1 <= value <= ceiling:
        raise ValueError(f"{name} must be between 1 and {ceiling}, not {value}")
    return value


def check_size(graph: Subgraph, limits: Limits) -> None:
    check_counts(len(graph.nodes), len(graph.edges), limits, "the graph to load has", "nothing was written")


def check_counts(nodes: int, edges: int, limits: Limits, lead: str, tail: str) -> None:
    over = []
    if nodes > limits.max_nodes:
        over.append(f"{nodes} nodes, over the cap of {limits.max_nodes} (raise it with --max-nodes or DECISIS_MAX_NODES, at most {CEILING_NODES})")
    if edges > limits.max_edges:
        over.append(f"{edges} edges, over the cap of {limits.max_edges} (raise it with --max-edges or DECISIS_MAX_EDGES, at most {CEILING_EDGES})")
    if over:
        raise TooLarge(f"{lead} " + "; and ".join(over) + f"; {tail}")


def default_root() -> Path:
    return TMPFS if TMPFS.is_dir() and os.access(TMPFS, os.W_OK) else Path(tempfile.gettempdir())


RESERVED_PROPS = frozenset({"title", "domain"})


class LoadMismatch(ValueError):
    pass


def _mismatch(graph: Subgraph, got: dict, overwritten: list[str] | None = None) -> str:
    found = unloadable(graph, overwritten)
    if got == {"nodes": len(graph.nodes), "edges": len(graph.edges)} and found:
        return "the snapshot cannot be loaded: " + "; ".join(found)
    out = [f"loaded {got['nodes']} nodes and {got['edges']} edges, but the snapshot has {len(graph.nodes)} nodes and {len(graph.edges)} edges"]
    return "; ".join(out + found)


def check_ids(graph: Subgraph) -> None:
    bad = [n.get("id") for n in graph.nodes
           if not ((isinstance(n.get("id"), str) and n["id"]) or (type(n.get("id")) is int))]
    if bad:
        shown = ", ".join(repr(b)[:40] for b in bad[:5])
        raise ValueError(f"a node id must be non-empty text or a whole number, not {shown}; nothing was written")


def unloadable(graph: Subgraph, overwritten: list[str] | None = None) -> list[str]:
    kinds: dict = {}
    for n in graph.nodes:
        kinds.setdefault(n["id"], []).append(str(n["kind"]))
    out = []
    dupes = sorted((i for i, k in kinds.items() if len(k) > 1), key=str)
    if dupes:
        out.append("repeated node ids: " + ", ".join(f"{i} ({', '.join(kinds[i])})" for i in dupes[:5]))
    if overwritten:
        out.append("node props overrode id: " + ", ".join(overwritten[:5]))
    dangling = [f"{e['source']} -{e['type']}-> {e['target']}" for e in graph.edges if e["source"] not in kinds or e["target"] not in kinds]
    if dangling:
        out.append("edges with a missing endpoint: " + ", ".join(dangling[:5]))
    return out


def prop_ids(graph: Subgraph) -> list[str]:
    return sorted({str(n["id"]) for n in graph.nodes if "id" in (n.get("props") or {}) and n["props"]["id"] != n["id"]})


FULLTEXT_INDEX = "decisis_text"


def _constraint_name(label: str) -> str:
    safe = re.sub(r"[^A-Za-z0-9_]", "_", label)
    if safe == label:
        return f"uniq_{safe}_id"
    import hashlib
    return f"uniq_{safe}_{hashlib.sha256(label.encode('utf-8')).hexdigest()[:8]}_id"


def apply_schema(con, graph: Subgraph) -> None:
    by_label: dict[str, list[dict]] = {}
    for n in graph.nodes:
        by_label.setdefault(_label(n["kind"]), []).append(n)
    type_entries = []
    constraints = []
    for label, nodes in sorted(by_label.items()):
        quoted = "`" + label.replace("`", "``") + "`"
        constraints.append(f"CREATE CONSTRAINT `{_constraint_name(label)}` IF NOT EXISTS FOR (n:{quoted}) REQUIRE n.id IS UNIQUE")
        if all(isinstance(n["id"], str) for n in nodes):
            type_entries.append(f"(:{quoted} => {{id :: STRING NOT NULL}})")
    if type_entries:
        con.execute("ALTER CURRENT GRAPH TYPE SET { " + ", ".join(type_entries) + " }")
    for stmt in constraints:
        con.execute(stmt)


def apply_fulltext(con) -> None:
    con.execute(f"CREATE FULLTEXT INDEX {FULLTEXT_INDEX} IF NOT EXISTS "
                "FOR (n:Decision|Record|Concept) ON EACH [n.title, n.statement, n.summary, n.body, n.domain]")


class Sandbox:
    def __init__(self, root: Path | None = None, limits: Limits | None = None):
        self.limits = limits or Limits.resolve()
        self.dir = owned_dir(root or default_root())
        self.path = self.dir / "task.rl"
        self.loaded = False

    def load(self, graph: Subgraph, schema: bool = True, fulltext: bool = False) -> dict:
        if self.loaded:
            raise RuntimeError("a sandbox is loaded once; build a new one for a new task")
        check_size(graph, self.limits)
        check_ids(graph)
        _warm()
        con = relate.connect(str(self.path))
        overwritten: list[str] = []
        try:
            con.autocommit = False
            made: dict[str, list[int]] = {}
            for kind in sorted({n["kind"] for n in graph.nodes}):
                rows = [{"id": n["id"], "title": n.get("title") or "", "domain": n.get("domain") or "",
                         "props": {k: v for k, v in _flat(n.get("props")).items() if k not in RESERVED_PROPS}}
                        for n in graph.nodes if n["kind"] == kind]
                for r in con.execute(f"UNWIND $rows AS r CREATE (n:{_label(kind)} {{id: r.id, title: r.title, domain: r.domain}}) SET n += r.props "
                                     "RETURN r.id AS want, n.id AS id, id(n) AS nid", {"rows": rows}).fetchall():
                    if r["id"] != r["want"]:
                        overwritten.append(str(r["want"]))
                    if isinstance(r["id"], str):
                        made.setdefault(r["id"], []).append(r["nid"])
            seek = {i: n[0] for i, n in made.items() if len(n) == 1}
            for rel in sorted({e["type"] for e in graph.edges}):
                for by_id, rows in _runs([e for e in graph.edges if e["type"] == rel], seek):
                    match = "MATCH (a) WHERE id(a) = r.s MATCH (b) WHERE id(b) = r.t" if by_id else "MATCH (a {id: r.s}), (b {id: r.t})"
                    con.execute(f"UNWIND $rows AS r {match} CREATE (a)-[:{_label(rel)} {{evidence: r.evidence}}]->(b)", {"rows": rows})
            con.commit()
            con.autocommit = True
            nodes = con.execute("MATCH (n) RETURN count(n) AS c").single()
            edges = con.execute("MATCH ()-[r]->() RETURN count(r) AS c").single()
            got = {"nodes": dict(nodes)["c"] if nodes else 0, "edges": dict(edges)["c"] if edges else 0}
            ids = [n["id"] for n in graph.nodes]
            if got != {"nodes": len(graph.nodes), "edges": len(graph.edges)} or len(ids) != len(set(ids)) or overwritten:
                raise LoadMismatch(_mismatch(graph, got, sorted(set(overwritten))))
            if schema and graph.nodes:
                apply_schema(con, graph)
            if fulltext:
                apply_fulltext(con)
        finally:
            con.close()
        self.loaded = True
        return got

    def query(self, cypher: str, params: dict | None = None) -> list[dict]:
        if not self.loaded:
            raise RuntimeError("load the sandbox before querying it")
        reply = _ask((str(self.path), cypher, params or {}), self.limits.query_seconds)
        if reply[0] == "error":
            _reraise(*reply[1:])
        return reply[1]

    def write(self, cypher: str, params: dict | None = None) -> None:
        if not self.loaded:
            raise RuntimeError("load the sandbox before writing to it")
        con = relate.connect(str(self.path))
        try:
            con.execute(cypher, params or {}).fetchall()
        finally:
            con.close()

    def page(self, cypher: str, params: dict | None, max_rows: int, max_bytes: int, profile: bool = False) -> dict:
        if not self.loaded:
            raise RuntimeError("load the sandbox before querying it")
        reply = _ask((str(self.path), cypher, params or {}, (max_rows, max_bytes, profile)), self.limits.query_seconds)
        if reply[0] == "error":
            _reraise(*reply[1:])
        columns, rows, total, prof = reply[1:]
        return {"columns": columns, "rows": rows, "total": total, **({"profile": prof} if prof is not None else {})}

    def save(self, dest: Path, force: bool = False) -> Path:
        if not self.loaded:
            raise RuntimeError("load the sandbox before saving it")
        check_keep_graph(dest, force)
        dest.parent.mkdir(parents=True, exist_ok=True)
        part = dest.parent / f".{dest.name}.{uuid.uuid4().hex}.part"
        try:
            shutil.copyfile(self.path, part)
            if force:
                os.replace(part, dest)
            else:
                _place_new(part, dest)
        finally:
            part.unlink(missing_ok=True)
        return dest

    def destroy(self) -> None:
        shutil.rmtree(self.dir, ignore_errors=True)


def query_store(store: Path, cypher: str, params: dict | None, max_rows: int, max_bytes: int,
                limits: Limits | None = None, profile: bool = False) -> dict:
    lim = limits or Limits.resolve()
    _warm()
    reply = _ask((str(store), cypher, params or {}, (max_rows, max_bytes, profile)), lim.query_seconds)
    if reply[0] == "error":
        _reraise(*reply[1:])
    columns, rows, total, prof = reply[1:]
    return {"columns": columns, "rows": rows, "total": total, **({"profile": prof} if prof is not None else {})}


def _place_new(part: Path, dest: Path) -> None:
    try:
        os.link(part, dest)
    except FileExistsError:
        raise ValueError(f"--keep-graph {dest} already exists; pass --force to replace it") from None
    except OSError:
        if os.path.lexists(dest):
            raise ValueError(f"--keep-graph {dest} already exists; pass --force to replace it") from None
        os.replace(part, dest)


def same_path(a: Path, b: Path) -> bool:
    try:
        return os.path.samefile(a, b)
    except OSError:
        return os.path.realpath(a) == os.path.realpath(b)


def check_keep_graph(dest: Path, force: bool = False, inputs: tuple[Path, ...] = ()) -> None:
    if dest.is_symlink():
        raise ValueError(f"--keep-graph refuses a symbolic link: {dest}")
    if dest.is_dir():
        raise ValueError(f"--keep-graph expects a file path, not a directory: {dest}")
    if dest.suffix.lower() != STORE_SUFFIX:
        raise ValueError(f"--keep-graph saves a Relate database, so its name must end in {STORE_SUFFIX}: {dest}")
    for src in inputs:
        if same_path(dest, src):
            raise ValueError(f"--keep-graph {dest} is an input of this run; decisis never replaces an input, even with --force")
    if os.path.lexists(dest) and not force:
        raise ValueError(f"--keep-graph {dest} already exists; pass --force to replace it")


STORE_SUFFIX = ".rl"


def store_size(store: Path, limits: Limits) -> None:
    _warm()
    counts = []
    for cypher in ("MATCH (n) RETURN count(n) AS c", "MATCH ()-[r]->() RETURN count(r) AS c"):
        reply = _ask((str(store), cypher, {}), limits.query_seconds)
        if reply[0] == "error":
            _reraise(*reply[1:])
        counts.append(dict(reply[1][0])["c"] if reply[1] else 0)
    check_counts(counts[0], counts[1], limits, f"the saved graph {store} has", "the query was not run")


@contextmanager
def sandbox(root: Path | None = None, limits: Limits | None = None, keep_graph: Path | None = None,
            force: bool = False) -> Iterator[Sandbox]:
    box = Sandbox(root, limits)
    try:
        yield box
        if keep_graph is not None and box.loaded:
            box.save(keep_graph, force)
    finally:
        box.destroy()


_shared: list = []
_lock = threading.Lock()


def _warm() -> None:
    if _lock.acquire(blocking=False):
        try:
            if not _shared:
                _shared.append(_Worker())
        finally:
            _lock.release()


def _ask(job: tuple, seconds: float) -> tuple:
    with _lock:
        worker = _shared.pop() if _shared else None
        if worker is None or worker.proc.poll() is not None:
            worker = _Worker()
        try:
            reply = worker.ask(job, seconds)
        except BaseException:
            worker.proc.kill()
            worker.stop()
            raise
        _shared.append(worker)
        return reply


def _stop_shared() -> None:
    while _shared:
        _shared.pop().stop()


atexit.register(_stop_shared)

BOOT = "import pickle, sys; sys.path[:] = pickle.load(sys.stdin.buffer); from decisis.sandbox import _serve; _serve()"


def _worker_path() -> list[str]:
    root = str(Path(__file__).resolve().parents[1])
    return [root, *(p for p in sys.path if p != root)]


class _Worker:
    def __init__(self):
        self.proc = subprocess.Popen([sys.executable, "-I", "-c", BOOT], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        self._send(_worker_path())

    def _send(self, obj) -> None:
        pickle.dump(obj, self.proc.stdin)
        self.proc.stdin.flush()

    def _receive(self, box: list) -> None:
        try:
            box.append(pickle.load(self.proc.stdout))
        except Exception:
            pass

    def ask(self, job: tuple, seconds: float) -> tuple:
        box: list = []
        reader = threading.Thread(target=self._receive, args=(box,), daemon=True)
        try:
            self._send(job)
        except OSError as e:
            self.stop()
            raise RuntimeError(f"the query process is gone: {e}") from None
        reader.start()
        reader.join(seconds)
        if reader.is_alive():
            self.proc.kill()
            reader.join(10)
            self.stop()
            raise QueryTimeout(f"the query ran longer than {seconds:g} s and was stopped; raise the limit with --query-timeout "
                               f"or DECISIS_QUERY_TIMEOUT, at most {CEILING_SECONDS} s")
        if not box:
            self.stop()
            raise RuntimeError("the query process ended without an answer")
        return box[0]

    def stop(self) -> None:
        try:
            self.proc.stdin.close()
        except OSError:
            pass
        try:
            self.proc.wait(5)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait()
        self.proc.stdout.close()


def _serve() -> None:
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    out = os.fdopen(os.dup(1), "wb")
    os.dup2(2, 1)
    jobs: queue.Queue = queue.Queue()
    threading.Thread(target=_read_jobs, args=(jobs,), daemon=True).start()
    while True:
        out.write(_reply(*jobs.get()))
        out.flush()


def _read_jobs(jobs: queue.Queue) -> None:
    try:
        while True:
            jobs.put(pickle.load(sys.stdin.buffer))
    except Exception:
        pass
    os._exit(0)


def _reply(path: str, cypher: str, params: dict, page: tuple | None = None) -> bytes:
    try:
        return pickle.dumps(_answer(path, cypher, params) if page is None else _page_answer(path, cypher, params, *page))
    except Exception as e:
        return pickle.dumps(("error", "builtins", "TypeError", f"the query result cannot be returned: {e}"))


def _answer(path: str, cypher: str, params: dict) -> tuple:
    try:
        con = relate.connect(path, read_only=True)
        try:
            return ("rows", con.execute(cypher, params).fetchall())
        finally:
            con.close()
    except Exception as e:
        return ("error", type(e).__module__, type(e).__name__, str(e))


READ_ONLY_PLAN = "r"


def _profile_summary(summary) -> dict:
    return {"elapsed_ms": round(summary.elapsed_ms, 3), "parse_ms": round(summary.parse_ms, 3),
            "plan_ms": round(summary.plan_ms, 3), "execute_ms": round(summary.execute_ms, 3),
            "plan": summary.plan, "notifications": summary.notifications}


def _page_answer(path: str, cypher: str, params: dict, max_rows: int, max_bytes: int, profile: bool = False) -> tuple:
    try:
        con = relate.connect(path, read_only=True)
        try:
            kind = _plan(con, cypher, params)
            if kind != READ_ONLY_PLAN:
                return ("error", __name__, "NotReadOnly", f"Relate plans this query as query type {kind!r}, not read only ({READ_ONLY_PLAN!r}); "
                                                         "it was not run")
            stmt = ("PROFILE\n" + cypher) if profile else cypher
            cursor = con.execute(stmt, params)
            rows = cursor.fetchall()
            prof = _profile_summary(cursor.consume()) if profile else None
            return ("page", list(cursor.keys()), _cut(rows, max_rows, max_bytes), len(rows), prof)
        finally:
            con.close()
    except Exception as e:
        return ("error", type(e).__module__, type(e).__name__, str(e))


def _plan(con, cypher: str, params: dict) -> str:
    try:
        return con.execute("EXPLAIN\n" + cypher, params).consume().query_type
    except relate.Error as e:
        text = re.sub(r"at line (\d+)", lambda m: f"at line {int(m.group(1)) - 1}", str(e))
        raise type(e)(text) from None


def _cut(rows: list, max_rows: int, max_bytes: int) -> list[dict]:
    kept, size = [], 2
    for row in rows[:max_rows]:
        plain = {str(k): _plain(v) for k, v in dict(row).items()}
        size += len(json.dumps(plain, ensure_ascii=False).encode("utf-8")) + 1
        if size > max_bytes:
            break
        kept.append(plain)
    return kept


def _plain(value):
    if isinstance(value, float) and not math.isfinite(value):
        return str(value)
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, (list, tuple)):
        return [_plain(v) for v in value]
    if isinstance(value, dict):
        return {str(k): _plain(v) for k, v in value.items()}
    if isinstance(value, relate.Node):
        return {"labels": list(value.labels), "properties": _plain(dict(value.items()))}
    if isinstance(value, relate.Relationship):
        return {"type": value.type, "properties": _plain(dict(value.items()))}
    if isinstance(value, relate.Path):
        return {"nodes": _plain(list(value.nodes)), "relationships": _plain(list(value.relationships))}
    return str(value)


def _reraise(module: str, name: str, text: str) -> None:
    home = relate if module.split(".")[0] == "relate" else sys.modules[__name__] if module == __name__ else builtins
    cls = getattr(home, name, None)
    if isinstance(cls, type) and issubclass(cls, Exception):
        raise cls(text)
    raise RuntimeError(f"{name}: {text}")


def _start_time(pid: int) -> str | None:
    try:
        text = Path(f"/proc/{pid}/stat").read_text(encoding="ascii")
    except (OSError, ValueError):
        return None
    fields = text.rsplit(")", 1)[-1].split()
    return fields[19] if len(fields) > 19 else None


def _write_owner(path: Path) -> None:
    owner = {"pid": os.getpid(), "start": _start_time(os.getpid()), "host": socket.gethostname(), "created": time.time()}
    fd = os.open(path / OWNER, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(owner, f)


def owned_dir(root: Path, prefix: str = TASK_PREFIX) -> Path:
    _quiet_sweep(root)
    path = root / f"{prefix}{uuid.uuid4().hex}"
    path.mkdir(mode=0o700)
    _write_owner(path)
    return path


def can_sweep() -> bool:
    return hasattr(os, "getuid") and shutil.rmtree.avoids_symlink_attacks


def _quiet_sweep(root: Path) -> None:
    try:
        sweep(root)
    except Exception:
        pass


def sweep(root: Path, grace: float = GRACE_SECONDS, errors: list | None = None) -> list[Path]:
    if not can_sweep():
        return []
    try:
        entries = [Path(e.path) for e in os.scandir(root)]
    except OSError:
        return []
    removed = []
    for path in entries:
        try:
            if _stale(path, grace):
                shutil.rmtree(path)
                removed.append(path)
        except Exception as e:
            if errors is not None:
                errors.append((path, f"{type(e).__name__}: {e}"))
    return removed


def _stale(path: Path, grace: float) -> bool:
    if not TASK_DIR.fullmatch(path.name):
        return False
    try:
        st = os.lstat(path)
    except OSError:
        return False
    if not stat.S_ISDIR(st.st_mode) or st.st_uid != os.getuid() or time.time() - st.st_mtime < grace:
        return False
    owner = _read_owner(path)
    return owner is not None and owner.get("host") == socket.gethostname() and not _alive(owner)


def _read_owner(path: Path) -> dict | None:
    try:
        fd = os.open(path / OWNER, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError:
        return None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_uid != os.getuid():
            return None
        owner = json.loads(os.read(fd, 4096))
    except (OSError, ValueError):
        return None
    finally:
        os.close(fd)
    if not isinstance(owner, dict) or type(owner.get("pid")) is not int or not 0 < owner["pid"] <= MAX_PID:
        return None
    return owner


def _alive(owner: dict) -> bool:
    pid = owner["pid"]
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except (OSError, OverflowError, ValueError):
        return True
    start = owner.get("start")
    return start is None or _start_time(pid) in (None, start)


def _label(name: str) -> str:
    clean = "".join(ch if ch.isalnum() else "_" for ch in name.strip())
    if not clean or not clean[0].isalpha():
        raise ValueError(f"not a usable label: {name!r}")
    return clean[0].upper() + clean[1:]


def _runs(edges: list[dict], seek: dict[str, int]) -> list[tuple[bool, list[dict]]]:
    out: list[tuple[bool, list[dict]]] = []
    for e in edges:
        by_id = isinstance(e["source"], str) and isinstance(e["target"], str) and e["source"] in seek and e["target"] in seek
        ends = (seek[e["source"]], seek[e["target"]]) if by_id else (e["source"], e["target"])
        row = {"s": ends[0], "t": ends[1], "evidence": e.get("evidence") or ""}
        if out and out[-1][0] == by_id:
            out[-1][1].append(row)
        else:
            out.append((by_id, [row]))
    return out


def _flat(props: dict | None) -> dict:
    out = {}
    for k, v in (props or {}).items():
        if isinstance(v, (str, int, float, bool)) or v is None:
            out[k] = v
        elif isinstance(v, list) and all(isinstance(x, (str, int, float, bool)) for x in v):
            out[k] = v
    return out
