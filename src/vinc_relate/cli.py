from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import audit
from . import checkout as co
from .sandbox import sandbox

PATH_QUERY = ("MATCH p = (a {id: $source})-[*1..$hops]-(b {id: $target}) "
              "RETURN [n IN nodes(p) | n.id] AS ids, [r IN relationships(p) | type(r)] AS rels ORDER BY length(p) LIMIT $limit")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="vinc-relate")
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("checkout", help="export a bounded subgraph from Vinc to a JSON snapshot")
    c.add_argument("seeds", nargs="+")
    c.add_argument("--depth", type=int, default=1)
    c.add_argument("--out", required=True)
    p = sub.add_parser("paths", help="load a snapshot into a throwaway Relate file and list paths between two ids")
    p.add_argument("snapshot")
    p.add_argument("source")
    p.add_argument("target")
    p.add_argument("--hops", type=int, default=4)
    p.add_argument("--limit", type=int, default=10)
    au = sub.add_parser("audit", help="join a Vinc snapshot, an npm lockfile and OSV advisories in a throwaway Relate graph")
    au.add_argument("snapshot")
    au.add_argument("lockfile")
    au.add_argument("--repo", required=True, help="repository name as it appears in Vinc code_ref, for example Vinc")
    au.add_argument("--depth", type=int, default=8)
    au.add_argument("--out")
    a = ap.parse_args(argv)
    if a.cmd == "audit":
        report = audit.run(co.load(Path(a.snapshot).read_text(encoding="utf-8")), Path(a.lockfile).read_text(encoding="utf-8"), a.repo, a.depth)
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
    with sandbox() as box:
        counts = box.load(graph)
        query = PATH_QUERY.replace("$hops", str(int(a.hops))).replace("$limit", str(int(a.limit)))
        rows = box.query(query, {"source": a.source, "target": a.target})
    json.dump({"loaded": counts, "paths": rows}, sys.stdout, ensure_ascii=False, indent=1)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
