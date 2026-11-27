from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import urllib.request
from pathlib import Path

from decisis import external, init, inventory

STATEMENT_CHARS = 200
DECISION_PROPS = ("source_file", "status", "date", "statement", "code_ref", "content_hash")
CONCEPT_PROPS = ("source_file", "code_ref", "content_hash")
LOCK_KEYS = ("name", "version", "dev", "optional", "devOptional", "peer", "link", "license", "dependencies", "devDependencies",
             "optionalDependencies", "peerDependencies", "peerDependenciesMeta")
VULN_KEYS = ("id", "summary", "aliases", "published", "modified", "affected", "database_specific")


def words(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


def short(text: str | None) -> str | None:
    if not text:
        return text
    text = words(text)
    if len(text) <= STATEMENT_CHARS:
        return text
    cut = text[:STATEMENT_CHARS].rsplit(" ", 1)[0]
    return cut + " ..."


def clean(path: str) -> str:
    path = path[2:] if path.startswith("./") else path
    return path.rstrip("/")


def mapped_refs(clone: Path, repo: str, mapping: dict) -> dict[str, list[str]]:
    out = {}
    for adr, rows in mapping["decisions"].items():
        text = words((clone / adr).read_text(encoding="utf-8"))
        for row in rows:
            if words(row["sentence"]) not in text:
                raise SystemExit(f"{adr}: the quoted sentence is not in the ADR: {row['sentence']!r}")
            if row["path"] not in row["sentence"]:
                raise SystemExit(f"{adr}: {row['path']} is not in the sentence it is taken from")
        out[adr] = sorted({f"{repo}:{clean(r['path'])}" for r in rows})
    return out


def snapshot(clone: Path, repo: str, mapping: dict) -> dict:
    refs = mapped_refs(clone, repo, mapping)
    built = init.build(clone, repo)
    found = {n["props"].get("source_file") for n in built["nodes"]}
    missing = sorted(set(refs) - found)
    if missing:
        raise SystemExit(f"the mapping names ADRs that init did not read: {missing}")
    nodes = []
    for n in built["nodes"]:
        props = dict(n["props"])
        if n["kind"] == "decision" and props.get("source_file") in refs:
            props["code_ref"] = refs[props["source_file"]]
        props["statement"] = short(props.get("statement"))
        keep = DECISION_PROPS if n["kind"] == "decision" else CONCEPT_PROPS
        nodes.append({"id": n["id"], "kind": n["kind"], "title": n["title"], "props": {k: props[k] for k in keep if props.get(k)}})
    meta = {"source": "decisis init, then bench/holdout/build_inputs.py", "repo": repo, "repository": mapping["repository"],
            "commit": mapping["commit"], "nodes": len(nodes), "edges": len(built["edges"]), "problems": built["meta"]["problems"]}
    return {"meta": meta, "nodes": nodes, "edges": built["edges"]}


def trimmed_lock(text: str) -> dict:
    lock = json.loads(text)
    lock["packages"] = {p: {k: m[k] for k in LOCK_KEYS if k in m} for p, m in lock["packages"].items()}
    return lock


def graph_of(text: str, repo: str) -> tuple:
    nodes, edges = inventory.read(text, "package-lock.json", repo)
    return sorted((n["id"], n["kind"]) for n in nodes), sorted((e["source"], e["type"], e["target"]) for e in edges)


def post(url: str, payload: dict) -> dict:
    req = urllib.request.Request(url, data=json.dumps(payload).encode(), headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.loads(r.read())


def osv_cache(lock_text: str, repo: str, fetched_at: str) -> dict:
    nodes, _ = inventory.read(lock_text, "package-lock.json", repo)
    pkgs = [n for n in nodes if external.queryable(n)]
    queries = {}
    for i in range(0, len(pkgs), external.BATCH):
        chunk = pkgs[i:i + external.BATCH]
        reply = post(external.OSV_BATCH, {"queries": [{"package": {"ecosystem": p["props"]["ecosystem"], "name": p["props"]["name"]},
                                                       "version": p["props"]["version"]} for p in chunk]})
        for p, r in zip(chunk, reply["results"]):
            if r.get("next_page_token"):
                raise SystemExit(f"OSV paged the answer for {p['id']}; this tool does not follow pages")
            queries[p["id"]] = sorted(v["id"] for v in r.get("vulns") or [])
    vulns = {}
    for vid in sorted({v for vs in queries.values() for v in vs}):
        with urllib.request.urlopen(external.OSV_VULN.format(id=vid), timeout=60) as r:
            v = json.loads(r.read())
        v = {k: v[k] for k in VULN_KEYS if k in v}
        v["affected"] = [{k: a[k] for k in ("package", "ranges", "versions") if k in a} for a in v.get("affected") or []]
        v["database_specific"] = {k: s for k, s in (v.get("database_specific") or {}).items() if k == "severity"}
        vulns[vid] = v
    return {"fetched_at": fetched_at, "source": "https://api.osv.dev/v1/querybatch and https://api.osv.dev/v1/vulns/{id}",
            "queries": dict(sorted(queries.items())), "vulns": vulns}


def dump(path: Path, data: dict) -> None:
    path.write_text(json.dumps(data, ensure_ascii=False, indent=1, sort_keys=False) + "\n", encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Build the stored inputs of one held-out repository from a clone at its pinned commit.")
    ap.add_argument("clone", type=Path)
    ap.add_argument("out", type=Path, help="bench/holdout/<repo>, which holds mapping.json")
    ap.add_argument("--osv", metavar="FETCHED_AT", help="also build osv-cache.json from api.osv.dev, stamped with this time")
    a = ap.parse_args(argv)
    mapping = json.loads((a.out / "mapping.json").read_text(encoding="utf-8"))
    repo = mapping["repo"]
    head = subprocess.run(["git", "-C", str(a.clone), "rev-parse", "HEAD"], capture_output=True, text=True, check=True).stdout.strip()
    if head != mapping["commit"]:
        raise SystemExit(f"the clone is at {head}, the mapping pins {mapping['commit']}")
    dump(a.out / "snapshot.json", snapshot(a.clone, repo, mapping))
    if mapping.get("lockfile"):
        text = (a.clone / mapping["lockfile"]).read_text(encoding="utf-8")
        small = json.dumps(trimmed_lock(text), indent=1) + "\n"
        if graph_of(small, repo) != graph_of(text, repo):
            raise SystemExit("trimming the lockfile changed the packages or their edges")
        (a.out / "package-lock.json").write_text(small, encoding="utf-8")
        if a.osv:
            dump(a.out / "osv-cache.json", osv_cache(small, repo, a.osv))
    return 0


if __name__ == "__main__":
    sys.exit(main())
