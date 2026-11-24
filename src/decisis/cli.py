from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import audit
from . import compare
from . import demo
from . import external
from . import impact
from . import commit as wb
from . import checkout as co
from .queries import load as query
from . import sandbox as sb
from .sandbox import sandbox

MAX_LIMIT = 100


def bounded(lo: int, hi: int):
    def parse(text: str) -> int:
        try:
            value = int(text)
        except ValueError:
            raise argparse.ArgumentTypeError(f"{text!r} is not a whole number") from None
        if not lo <= value <= hi:
            raise argparse.ArgumentTypeError(f"{value} is outside {lo} to {hi}")
        return value
    return parse


def limit_flags(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--max-nodes", type=bounded(1, sb.CEILING_NODES), metavar="N",
                        help=f"refuse a graph with more nodes (default {sb.MAX_NODES} or DECISIS_MAX_NODES, at most {sb.CEILING_NODES})")
    parser.add_argument("--max-edges", type=bounded(1, sb.CEILING_EDGES), metavar="N",
                        help=f"refuse a graph with more edges (default {sb.MAX_EDGES} or DECISIS_MAX_EDGES, at most {sb.CEILING_EDGES})")
    parser.add_argument("--query-timeout", type=bounded(1, sb.CEILING_SECONDS), metavar="SECONDS",
                        help=f"stop a query that runs longer (default {sb.QUERY_SECONDS} or DECISIS_QUERY_TIMEOUT, at most {sb.CEILING_SECONDS})")


def limits(a: argparse.Namespace) -> sb.Limits:
    return sb.Limits.resolve(a.max_nodes, a.max_edges, a.query_timeout)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="decisis")
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("checkout", help="export a bounded subgraph from Vinc to a JSON snapshot")
    c.add_argument("seeds", nargs="+")
    c.add_argument("--depth", type=int, default=1)
    c.add_argument("--out", required=True)
    p = sub.add_parser("paths", help="load a snapshot into a throwaway Relate file and list paths between two ids")
    p.add_argument("snapshot")
    p.add_argument("source")
    p.add_argument("target")
    p.add_argument("--hops", type=bounded(1, impact.MAX_HOPS), default=4, help=f"longest path to look for (1 to {impact.MAX_HOPS})")
    p.add_argument("--limit", type=bounded(1, MAX_LIMIT), default=10, help=f"most paths to return (1 to {MAX_LIMIT})")
    im = sub.add_parser("impact", help="list the decisions, records and concepts that govern one or more code paths")
    im.add_argument("snapshot")
    im.add_argument("code_paths", nargs="+", metavar="code_path", help="a file or directory, for example reports/export.py or storage/")
    im.add_argument("--hops", type=bounded(0, impact.MAX_HOPS), default=3, help=f"how far from a matching concept to look (0 to {impact.MAX_HOPS})")
    im.add_argument("--repo", help="skip code_refs that name another repository, for example Demo")
    im.add_argument("--format", choices=["json", "text"], default="json")
    au = sub.add_parser("audit", help="join a Vinc snapshot, an npm lockfile and OSV advisories in a throwaway Relate graph")
    au.add_argument("snapshot")
    au.add_argument("lockfile")
    au.add_argument("--repo", required=True, help="repository name as it appears in Vinc code_ref, for example Vinc")
    au.add_argument("--depth", type=bounded(1, audit.MAX_DEPTH), default=8, help=f"longest dependency chain to follow (1 to {audit.MAX_DEPTH})")
    au.add_argument("--out")
    au.add_argument("--osv-cache", metavar="FILE", help="read OSV advisories from this file and never from the network")
    pr = sub.add_parser("propose", help="turn an audit report into the exact write set the owner approves")
    pr.add_argument("report")
    pr.add_argument("--repo", required=True)
    pr.add_argument("--space", required=True)
    pr.add_argument("--out", required=True)
    pr.add_argument("--lockfile-path", default="package-lock.json", help="the lockfile path inside the repository, for subject_path")
    pr.add_argument("--ref", help="the commit the lockfile was read at, for measured_ref")
    cm = sub.add_parser("commit", help="write an approved write set to Vinc and read it back (needs a full key)")
    cm.add_argument("plan")
    cm.add_argument("--approve", required=True, help="the approval digest printed by propose")
    dm = sub.add_parser("demo", help="run the whole sandbox procedure on synthetic data, offline, against an in-process fake Vinc")
    dm.add_argument("--out", default="demo", help="where the transcript, the expected findings and the sample Relate database go")
    dm.add_argument("--fixtures", type=Path, help="the fixtures directory (default: the one in this repository)")
    ok = dm.add_mutually_exclusive_group()
    ok.add_argument("--approve", metavar="DIGEST", help="approve the write set with the digest the demo prints")
    ok.add_argument("--yes", action="store_true", help="approve the demo write set without typing the digest")
    cp = sub.add_parser("compare", help="run the benchmark: Vinc retrieval (A), a text join (B) and the Relate graph (C) on the same tasks")
    cp.add_argument("--tasks", type=Path, help="the task file with expected findings (default: bench/tasks.json in this repository)")
    cp.add_argument("--out", type=Path, help="write the full results as JSON here")
    cp.add_argument("--table", type=Path, help="write the results table as Markdown here")
    gc = sub.add_parser("gc", help="remove task directories that a killed run left behind")
    gc.add_argument("--root", type=Path, help="the directory that holds the task directories (default: /dev/shm, or the system temporary directory)")
    gc.add_argument("--grace", type=bounded(0, 86400), default=sb.GRACE_SECONDS, metavar="SECONDS",
                    help=f"leave directories younger than this (default {sb.GRACE_SECONDS})")
    for s in (p, im, au):
        limit_flags(s)
    a = ap.parse_args(argv)
    try:
        return run(a)
    except ValueError as e:
        ap.error(str(e))
    except (external.NetworkRefused, external.NetworkFailed, sb.LimitExceeded) as e:
        ap.exit(1, f"{ap.prog}: error: {e}\n")


def run(a: argparse.Namespace) -> int:
    if a.cmd == "gc":
        return gc(a.root or sb.default_root(), a.grace)
    if a.cmd == "compare":
        root = demo.default_fixtures().parent
        result = compare.run(root, a.tasks or root / "bench" / "tasks.json")
        if a.out:
            a.out.write_text(json.dumps(result, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
        table = compare.render(result)
        if a.table:
            a.table.write_text(table, encoding="utf-8")
        sys.stdout.write(table)
        return 0
    if a.cmd == "demo":
        return demo.run(Path(a.out), a.fixtures, approve=a.approve, yes=a.yes)[0]
    if a.cmd == "propose":
        plan = wb.propose(json.loads(Path(a.report).read_text(encoding="utf-8")), a.repo, a.space,
                          lockfile_path=a.lockfile_path, ref=a.ref)
        Path(a.out).write_text(json.dumps(plan, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
        print(wb.render(plan))
        return 0
    if a.cmd == "commit":
        plan = json.loads(Path(a.plan).read_text(encoding="utf-8"))
        wb.check_approval(plan, a.approve)
        client = co.VincMCP.from_env("full")
        client.space = plan["space"]
        receipt = wb.commit(plan, a.approve, client)
        print(json.dumps(receipt, ensure_ascii=False, indent=1))
        return 0 if receipt["verified"] else 1
    if a.cmd == "impact":
        report = impact.run(co.load(Path(a.snapshot).read_text(encoding="utf-8")), a.code_paths, a.hops, a.repo, limits=limits(a))
        if a.format == "text":
            print(impact.render(report))
        else:
            json.dump(report, sys.stdout, ensure_ascii=False, indent=1)
            sys.stdout.write("\n")
        return 0
    if a.cmd == "audit":
        advisories = external.fetch_advisories
        if a.osv_cache:
            advisories = external.cached_advisories(external.read_osv_cache(Path(a.osv_cache).read_text(encoding="utf-8")))
        report = audit.run(co.load(Path(a.snapshot).read_text(encoding="utf-8")), Path(a.lockfile).read_text(encoding="utf-8"), a.repo, a.depth,
                           advisories=advisories, limits=limits(a))
        text = json.dumps(report, ensure_ascii=False, indent=1)
        if a.out:
            Path(a.out).write_text(text + "\n", encoding="utf-8")
            print(json.dumps({"summary": report["summary"], "violations": report["violations"], "loaded": report["loaded"], "out": a.out}))
        else:
            sys.stdout.write(text + "\n")
        return 0
    if a.cmd == "checkout":
        graph = co.checkout(co.VincMCP.from_env(), a.seeds, a.depth)
        Path(a.out).write_text(co.dump(graph), encoding="utf-8")
        print(json.dumps(graph.meta))
        return 0
    graph = co.load(Path(a.snapshot).read_text(encoding="utf-8"))
    with sandbox(limits=limits(a)) as box:
        counts = box.load(graph)
        rows = box.query(query("paths_between", hops=a.hops, limit=a.limit), {"source": a.source, "target": a.target})
    json.dump({"loaded": counts, "paths": rows}, sys.stdout, ensure_ascii=False, indent=1)
    sys.stdout.write("\n")
    return 0


def gc(root: Path, grace: int) -> int:
    if not sb.can_sweep():
        print("decisis gc: this platform cannot check the owner of a task directory safely; nothing was removed")
        return 0
    removed = sb.sweep(root, grace)
    for path in removed:
        print(f"removed {path}")
    print(f"removed {len(removed)} task director{'y' if len(removed) == 1 else 'ies'} under {root}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
