from __future__ import annotations

import json
import os
import urllib.request
from datetime import datetime, timezone

from .sandbox import Subgraph

DEFAULT_URL = "https://mcp.vincs.io/mcp"
EDGE_TYPES = {"RELATED_TO", "PREREQUISITE_OF", "DERIVES_FROM", "INHERITS_FROM", "CONNECTS_VIA", "ABOUT", "SUPERSEDES", "RETURNS_TO"}
WRITE_NAMES = {"RELATES_TO": "RELATED_TO"}
CARRIER = "ATTACHES_TO"


def relation(edge: dict) -> str:
    rel = str(edge.get("type", "")).upper()
    if rel == CARRIER:
        rel = str(edge.get("role") or edge.get("subtype") or "").upper()
    return WRITE_NAMES.get(rel, rel)


class VincMCP:
    def __init__(self, token: str, url: str = DEFAULT_URL, space: str | None = None, opener=urllib.request.urlopen):
        self.token, self.url, self.space, self.opener, self.session = token, url, space, opener, None

    @classmethod
    def from_env(cls, key_kind: str = "read-only") -> "VincMCP":
        token = os.environ.get("VINC_API_KEY")
        if not token:
            raise SystemExit(f"VINC_API_KEY is not set; use a {key_kind} key")
        return cls(token, os.environ.get("VINC_MCP_URL", DEFAULT_URL), os.environ.get("VINC_SPACE"))

    def _post(self, payload: dict) -> dict:
        headers = {"Authorization": f"Bearer {self.token}", "Content-Type": "application/json", "Accept": "application/json, text/event-stream"}
        if self.session:
            headers["Mcp-Session-Id"] = self.session
        req = urllib.request.Request(self.url, data=json.dumps(payload).encode(), headers=headers)
        with self.opener(req, timeout=60) as resp:
            self.session = resp.headers.get("Mcp-Session-Id") or self.session
            body = resp.read().decode()
        start = body.find("{")
        return json.loads(body[start:]) if start >= 0 else {}

    def tool(self, name: str, arguments: dict) -> dict:
        if self.session is None:
            self._post({"jsonrpc": "2.0", "id": 0, "method": "initialize",
                        "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "vinc-relate", "version": "0"}}})
        args = {**arguments, **({"space": self.space} if self.space else {})}
        reply = self._post({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": name, "arguments": args}})
        result = reply.get("result") or {}
        if result.get("isError") or "error" in reply:
            raise RuntimeError(f"{name} failed: {json.dumps(reply)[:300]}")
        if "structuredContent" in result:
            return result["structuredContent"]
        text = "".join(c.get("text", "") for c in result.get("content", []) if c.get("type") == "text")
        return json.loads(text) if text else {}


def normalize(raw_graphs: list[dict], seeds: list[str], space: str | None) -> Subgraph:
    nodes: dict[str, dict] = {}
    edges: dict[tuple, dict] = {}
    for g in raw_graphs:
        for n in g.get("nodes", []):
            nodes.setdefault(n["id"], {"id": n["id"], "kind": n.get("kind") or n["id"].split(":", 1)[0], "title": n.get("label") or n.get("title") or "",
                                       "domain": n.get("domain") or "", "valid_until": n.get("valid_until"), "props": n.get("props") or {}})
        for e in g.get("edges", []):
            rel = relation(e)
            if rel not in EDGE_TYPES:
                continue
            key = (e["source"], rel, e["target"])
            edges.setdefault(key, {"source": e["source"], "target": e["target"], "type": rel, "evidence": e.get("evidence") or ""})
    kept = [e for e in edges.values() if e["source"] in nodes and e["target"] in nodes]
    meta = {"seeds": seeds, "space": space or "personal", "extracted_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "nodes": len(nodes), "edges": len(kept)}
    return Subgraph(sorted(nodes.values(), key=lambda n: n["id"]), sorted(kept, key=lambda e: (e["source"], e["type"], e["target"])), meta)


def checkout(client: VincMCP, seeds: list[str], depth: int = 1) -> Subgraph:
    raws = [client.tool("vinc_graph", {"seed_id": s, "depth": depth}) for s in seeds]
    return normalize(raws, seeds, client.space)


def dump(graph: Subgraph) -> str:
    return json.dumps({"meta": graph.meta, "nodes": graph.nodes, "edges": graph.edges}, ensure_ascii=False, indent=1)


def load(text: str) -> Subgraph:
    d = json.loads(text)
    meta = d.get("meta", {})
    for key in ("nodes", "edges"):
        if isinstance(meta.get(key), int) and meta[key] != len(d[key]):
            raise ValueError(f"the snapshot says it has {meta[key]} {key} but lists {len(d[key])}")
    return Subgraph(d["nodes"], d["edges"], meta)
