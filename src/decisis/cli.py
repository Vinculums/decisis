from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import audit
from . import checker
from . import compare
from . import demo
from . import external
from . import impact
from . import init
from . import render
from . import commit as wb
from . import checkout as co
from .queries import load as query
from .sandbox import sandbox

MAX_LIMIT = 100
VIEWS = {"mermaid": render.mermaid, "html": render.html}


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


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="decisis")
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("checkout", help="export a bounded subgraph from Vinc to a JSON snapshot")
    c.add_argument("seeds", nargs="+")
    c.add_argument("--depth", type=int, default=1)
    c.add_argument("--out", required=True)
    ini = sub.add_parser("init", help="build a snapshot from a repository's ADRs, CODEOWNERS and postmortems")
    ini.add_argument("--repo-dir", default=".", help="the repository to read (default: the current directory)")
    ini.add_argument("--repo", help="the repository name to put before each code path, for example Shop")
    ini.add_argument("--adr-dir", help=f"read ADRs only from this directory, relative to --repo-dir (default: {', '.join(init.ADR_DIRS)})")
    ini.add_argument("--postmortem-dir", help=f"read postmortems only from this directory, relative to --repo-dir (default: {', '.join(init.POSTMORTEM_DIRS)})")
    ini.add_argument("--out", required=True)
    p = sub.add_parser("paths", help="load a snapshot into a throwaway Relate file and list paths between two ids")
    p.add_argument("snapshot")
    p.add_argument("source")
    p.add_argument("target")
    p.add_argument("--hops", type=bounded(1, impact.MAX_HOPS), default=4, help=f"longest path to look for (1 to {impact.MAX_HOPS})")
    p.add_argument("--limit", type=bounded(1, MAX_LIMIT), default=10, help=f"most paths to return (1 to {MAX_LIMIT})")
    p.add_argument("--format", choices=["json", *VIEWS], default="json")
    im = sub.add_parser("impact", help="list the decisions, records and concepts that govern one or more code paths")
    im.add_argument("snapshot")
    im.add_argument("code_paths", nargs="+", metavar="code_path", help="a file or directory, for example reports/export.py or storage/")
    im.add_argument("--hops", type=bounded(0, impact.MAX_HOPS), default=3, help=f"how far from a matching concept to look (0 to {impact.MAX_HOPS})")
    im.add_argument("--repo", help="skip code_refs that name another repository, for example Demo")
    im.add_argument("--format", choices=["json", "text", *VIEWS], default="json")
    au = sub.add_parser("audit", help="join a Vinc snapshot, an npm lockfile and OSV advisories in a throwaway Relate graph")
    au.add_argument("snapshot")
    au.add_argument("lockfile")
    au.add_argument("--repo", required=True, help="repository name as it appears in Vinc code_ref, for example Vinc")
    au.add_argument("--depth", type=int, default=8)
    au.add_argument("--out", help="write the JSON report here; with --format mermaid or html the view still goes to stdout")
    au.add_argument("--format", choices=["json", *VIEWS], default="json")
    au.add_argument("--osv-cache", metavar="FILE", help="read OSV advisories from this file and never from the network")
    pr = sub.add_parser("propose", help="re-derive an audit report's records and print the exact write set the owner approves")
    pr.add_argument("report")
    pr.add_argument("snapshot", help="the snapshot the audit read")
    pr.add_argument("lockfile", help="the lockfile the audit read")
    pr.add_argument("--repo", required=True)
    pr.add_argument("--space", required=True)
    pr.add_argument("--out", required=True)
    pr.add_argument("--lockfile-path", default="package-lock.json", help="the lockfile path inside the repository, for subject_path")
    pr.add_argument("--ref", help="the commit the lockfile was read at, for measured_ref")
    pr.add_argument("--depth", type=int, default=8, help="the audit's --depth, for the dependency paths")
    pr.add_argument("--osv-cache", metavar="FILE", help="read OSV advisories from this file and never from the network")
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
    a = ap.parse_args(argv)
    try:
        return run(a)
    except ValueError as e:
        ap.error(str(e))
    except (external.NetworkRefused, external.NetworkFailed) as e:
        ap.exit(1, f"{ap.prog}: error: {e}\n")


def run(a: argparse.Namespace) -> int:
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
        advisories = external.fetch_advisories
        if a.osv_cache:
            advisories = external.cached_advisories(external.read_osv_cache(Path(a.osv_cache).read_text(encoding="utf-8")))
        plan, checked = checker.rederive(plan, co.load(Path(a.snapshot).read_text(encoding="utf-8")),
                                         Path(a.lockfile).read_text(encoding="utf-8"), a.repo, advisories, a.depth)
        Path(a.out).write_text(json.dumps(plan, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
        failed = sum(1 for c in checked if c["problems"])
        print(f"Re-derived {len(checked)} records with {sum(c['checks'] for c in checked)} checks; {failed} failed.\n")
        print(wb.render(plan))
        return 1 if failed else 0
    if a.cmd == "commit":
        plan = json.loads(Path(a.plan).read_text(encoding="utf-8"))
        wb.check_approval(plan, a.approve)
        client = co.VincMCP.from_env("full")
        client.space = plan["space"]
        receipt = wb.commit(plan, a.approve, client)
        print(json.dumps(receipt, ensure_ascii=False, indent=1))
        return 0 if receipt["verified"] else 1
    if a.cmd == "impact":
        report = impact.run(co.load(Path(a.snapshot).read_text(encoding="utf-8")), a.code_paths, a.hops, a.repo)
        if a.format == "text":
            print(impact.render(report))
        elif a.format in VIEWS:
            sys.stdout.write(VIEWS[a.format]("impact", report))
        else:
            json.dump(report, sys.stdout, ensure_ascii=False, indent=1)
            sys.stdout.write("\n")
        return 0
    if a.cmd == "audit":
        advisories = external.fetch_advisories
        if a.osv_cache:
            advisories = external.cached_advisories(external.read_osv_cache(Path(a.osv_cache).read_text(encoding="utf-8")))
        report = audit.run(co.load(Path(a.snapshot).read_text(encoding="utf-8")), Path(a.lockfile).read_text(encoding="utf-8"), a.repo, a.depth,
                           advisories=advisories)
        text = json.dumps(report, ensure_ascii=False, indent=1)
        if a.format in VIEWS:
            if a.out:
                Path(a.out).write_text(text + "\n", encoding="utf-8")
            sys.stdout.write(VIEWS[a.format]("audit", report))
        elif a.out:
            Path(a.out).write_text(text + "\n", encoding="utf-8")
            print(json.dumps({"summary": report["summary"], "violations": report["violations"], "loaded": report["loaded"], "out": a.out}))
        else:
            sys.stdout.write(text + "\n")
        return 0
    if a.cmd == "init":
        snapshot = init.build(a.repo_dir, a.repo, adr_dir=a.adr_dir, postmortem_dir=a.postmortem_dir)
        Path(a.out).write_text(init.dump(snapshot), encoding="utf-8")
        meta = snapshot["meta"]
        print(json.dumps({"out": a.out, "nodes": meta["nodes"], "edges": meta["edges"], "problems": meta["problems"]}, ensure_ascii=False, indent=1))
        return 0
    if a.cmd == "checkout":
        graph = co.checkout(co.VincMCP.from_env(), a.seeds, a.depth)
        Path(a.out).write_text(co.dump(graph), encoding="utf-8")
        print(json.dumps(graph.meta))
        return 0
    graph = co.load(Path(a.snapshot).read_text(encoding="utf-8"))
    with sandbox() as box:
        counts = box.load(graph)
        rows = box.query(query("paths_between", hops=a.hops, limit=a.limit), {"source": a.source, "target": a.target})
    report = {"loaded": counts, "paths": rows}
    if a.format in VIEWS:
        sys.stdout.write(VIEWS[a.format]("paths", render.annotate_paths(report, graph, a.source, a.target)))
        return 0
    json.dump(report, sys.stdout, ensure_ascii=False, indent=1)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
