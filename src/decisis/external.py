from __future__ import annotations

import functools
import io
import json
import urllib.request

from . import cvss
from .inventory.npm import parse_npm_lock
from .inventory.shape import digest, now, package_id

OSV_BATCH = "https://api.osv.dev/v1/querybatch"
OSV_VULN = "https://api.osv.dev/v1/vulns/{id}"
BATCH = 500
NAME_ONLY = ("GitHub Actions",)


class NetworkRefused(RuntimeError):
    pass


class NetworkFailed(RuntimeError):
    pass


def _open(req: urllib.request.Request, opener) -> dict:
    try:
        with opener(req, timeout=60) as resp:
            return json.loads(resp.read())
    except OSError as e:
        reason = getattr(e, "reason", None) or e
        raise NetworkFailed(f"could not reach OSV at {req.full_url} ({reason}); to run without the network, "
                            "pass --osv-cache FILE (fixtures/audit/osv-cache.json covers the demo lockfile)") from None


def _post(url: str, payload: dict, opener) -> dict:
    return _open(urllib.request.Request(url, data=json.dumps(payload).encode(), headers={"Content-Type": "application/json"}), opener)


def _get(url: str, opener) -> dict:
    return _open(urllib.request.Request(url), opener)


def read_osv_cache(text: str) -> dict:
    cache = json.loads(text)
    if not isinstance(cache, dict) or not isinstance(cache.get("queries"), dict) or not isinstance(cache.get("vulns"), dict) \
            or not isinstance(cache.get("fetched_at"), str):
        raise ValueError("an OSV cache needs fetched_at, queries (package id to advisory ids) and vulns (advisory id to record)")
    return cache


def cache_opener(cache: dict):
    vuln_prefix = OSV_VULN.format(id="")

    def opener(req, timeout=None):
        url = req.full_url
        if url == OSV_BATCH and req.data:
            results = []
            for q in json.loads(req.data)["queries"]:
                pid = query_id(q)
                if pid not in cache["queries"]:
                    raise NetworkRefused(f"{pid} is not in the OSV cache, and a cached run does not use the network")
                results.append({"vulns": [{"id": v} for v in cache["queries"][pid]]})
            return io.BytesIO(json.dumps({"results": results}).encode())
        vid = url[len(vuln_prefix):] if url.startswith(vuln_prefix) else None
        if vid in cache["vulns"]:
            return io.BytesIO(json.dumps(cache["vulns"][vid]).encode())
        raise NetworkRefused(f"{url} is not in the OSV cache, and a cached run does not use the network")

    return opener


def cached_advisories(cache: dict):
    return functools.partial(fetch_advisories, opener=cache_opener(cache), cache=dict(cache["vulns"]), fetched_at=cache["fetched_at"])


def query_id(q: dict) -> str:
    pid = package_id(q["package"]["ecosystem"], q["package"]["name"], q.get("version", ""))
    return pid if "version" in q else pid.removesuffix("@")


def osv_queries(props: dict) -> list[dict]:
    if props["ecosystem"] not in NAME_ONLY:
        return [{"package": {"ecosystem": props["ecosystem"], "name": props["name"]}, "version": props["version"]}]
    names = dict.fromkeys([props["name"], *(props.get("spellings") or [])])
    return [{"package": {"ecosystem": props["ecosystem"], "name": name}} for name in names]


def queryable(node: dict) -> bool:
    props = node.get("props") or {}
    return node.get("kind") == "Package" and bool(props.get("ecosystem")) and bool(props.get("version")) and not props.get("unresolved")


def fetch_advisories(packages: list[dict], opener=urllib.request.urlopen, cache: dict | None = None,
                     fetched_at: str | None = None) -> tuple[list[dict], list[dict]]:
    cache = cache if cache is not None else {}
    pkgs = [p for p in packages if queryable(p)]
    hits: dict[str, list[str]] = {p["id"]: [] for p in pkgs}
    asks = [(p["id"], q) for p in pkgs for q in osv_queries(p["props"])]
    for i in range(0, len(asks), BATCH):
        chunk = asks[i:i + BATCH]
        reply = _post(OSV_BATCH, {"queries": [q for _, q in chunk]}, opener)
        for (pid, _), r in zip(chunk, reply.get("results", [])):
            hits[pid] += [v["id"] for v in (r.get("vulns") or []) if v["id"] not in hits[pid]]
    fetched = fetched_at or now()
    nodes = []
    vids = sorted({v for vs in hits.values() for v in vs})
    for vid in vids:
        if vid not in cache:
            cache[vid] = _get(OSV_VULN.format(id=vid), opener)
    for vid in vids:
        v = cache[vid]
        sev, source = severity_of(vid, v, cache)
        nodes.append({"id": f"adv:{vid}", "kind": "Advisory", "title": v.get("summary") or vid,
                      "props": {"osv_id": vid, "severity": sev, **({"severity_source": source} if source else {}), "aliases": v.get("aliases") or [], "published": v.get("published") or "",
                                "affected_json": json.dumps(v.get("affected") or [], sort_keys=True),
                                "source_system": "osv", "source_ref": vid, "source_url": f"https://osv.dev/vulnerability/{vid}",
                                "fetched_at": fetched, "content_hash": digest(v)}})
    asked = {p["id"]: "name; decisis compares the version" if p["props"]["ecosystem"] in NAME_ONLY else "name and version" for p in pkgs}
    edges = [{"source": pid, "target": f"adv:{vid}", "type": "AFFECTED_BY", "evidence": f"OSV returned {vid} for this {asked[pid]}"}
             for pid, vids in sorted(hits.items()) for vid in vids]
    return nodes, edges


def _own_severity(v: dict) -> str:
    return str((v.get("database_specific") or {}).get("severity") or "").upper()


def ghsa_aliases(vid: str, v: dict, records: dict) -> list[str]:
    named = {a for a in v.get("aliases") or [] if isinstance(a, str) and a.startswith("GHSA-")}
    back = {k for k, r in records.items() if k.startswith("GHSA-") and vid in ((r or {}).get("aliases") or [])}
    return sorted(named | back)


def severity_of(vid: str, v: dict, records: dict) -> tuple[str, str]:
    if _own_severity(v):
        return _own_severity(v), ""
    alias = next((a for a in ghsa_aliases(vid, v, records) if _own_severity(records.get(a) or {})), None)
    if alias:
        return _own_severity(records[alias]), f"GHSA alias {alias} in the same OSV data"
    vectors = {s.get("type"): s.get("score") for s in v.get("severity") or [] if isinstance(s, dict)}
    score = cvss.base_score(vectors.get("CVSS_V3") or "")
    if score is not None:
        return cvss.band(score), f"CVSS v3 base score {score} of {vectors['CVSS_V3']}"
    unscored = f"; {', '.join(sorted(vectors))} is not scored" if vectors else ""
    return "UNKNOWN", f"no severity in the record, no GHSA alias with one in the OSV data and no CVSS v3 vector{unscored}"
