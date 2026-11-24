from __future__ import annotations

import functools
import io
import json
import urllib.request

from .inventory.npm import parse_npm_lock
from .inventory.shape import digest, now, package_id

OSV_BATCH = "https://api.osv.dev/v1/querybatch"
OSV_VULN = "https://api.osv.dev/v1/vulns/{id}"
BATCH = 500


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
                pid = package_id(q["package"]["ecosystem"], q["package"]["name"], q["version"])
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


def queryable(node: dict) -> bool:
    props = node.get("props") or {}
    return node.get("kind") == "Package" and bool(props.get("ecosystem")) and bool(props.get("version")) and not props.get("unresolved")


def fetch_advisories(packages: list[dict], opener=urllib.request.urlopen, cache: dict | None = None,
                     fetched_at: str | None = None) -> tuple[list[dict], list[dict]]:
    cache = cache if cache is not None else {}
    pkgs = [p for p in packages if queryable(p)]
    hits: dict[str, list[str]] = {}
    for i in range(0, len(pkgs), BATCH):
        chunk = pkgs[i:i + BATCH]
        queries = [{"package": {"ecosystem": p["props"]["ecosystem"], "name": p["props"]["name"]}, "version": p["props"]["version"]} for p in chunk]
        reply = _post(OSV_BATCH, {"queries": queries}, opener)
        for p, r in zip(chunk, reply.get("results", [])):
            hits[p["id"]] = [v["id"] for v in (r.get("vulns") or [])]
    fetched = fetched_at or now()
    nodes = []
    for vid in sorted({v for vs in hits.values() for v in vs}):
        if vid not in cache:
            cache[vid] = _get(OSV_VULN.format(id=vid), opener)
        v = cache[vid]
        sev = ((v.get("database_specific") or {}).get("severity") or "UNKNOWN").upper()
        nodes.append({"id": f"adv:{vid}", "kind": "Advisory", "title": v.get("summary") or vid,
                      "props": {"osv_id": vid, "severity": sev, "aliases": v.get("aliases") or [], "published": v.get("published") or "",
                                "affected_json": json.dumps(v.get("affected") or [], sort_keys=True),
                                "source_system": "osv", "source_ref": vid, "source_url": f"https://osv.dev/vulnerability/{vid}",
                                "fetched_at": fetched, "content_hash": digest(v)}})
    edges = [{"source": pid, "target": f"adv:{vid}", "type": "AFFECTED_BY", "evidence": f"OSV returned {vid} for this name and version"}
             for pid, vids in sorted(hits.items()) for vid in vids]
    return nodes, edges
