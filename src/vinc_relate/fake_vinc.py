from __future__ import annotations

from collections import deque

from .sandbox import Subgraph

CARRIER = "ATTACHES_TO"


class FakeVinc:
    def __init__(self, space: Subgraph | None = None, existing=(), tamper=None, flip=False, name: str = "demo-space"):
        self.nodes: dict[str, dict] = {}
        self.edges: list[dict] = []
        self.calls: list[str] = []
        self.tamper, self.flip, self.space = tamper, flip, name
        for n in (space.nodes if space else []):
            self.nodes[n["id"]] = {"id": n["id"], "kind": n.get("kind") or n["id"].split(":", 1)[0], "label": n.get("title") or "",
                                   "domain": n.get("domain") or "", "props": dict(n.get("props") or {})}
        for e in (space.edges if space else []):
            self.edges.append({"source": e["source"], "target": e["target"], "type": e["type"], "evidence": e.get("evidence") or ""})
        for i in existing:
            self.nodes[i] = {"id": i, "kind": i.split(":", 1)[0], "label": i, "props": {}}

    def counts(self) -> dict:
        return {"nodes": len(self.nodes), "edges": len(self.edges)}

    def tool(self, name: str, args: dict) -> dict:
        self.calls.append(name)
        if name == "vinc_node":
            n = self.nodes.get(args["node_id"])
            return {"found": n is not None, "node": n}
        if name == "vinc_ingest":
            if args.get("create_only") is not True or not args.get("operation_id"):
                raise ValueError("vinc_ingest needs create_only and an operation id")
            for n in args["nodes"]:
                props = dict(n["props"])
                if self.tamper and n["id"] == self.tamper:
                    props["severity"] = "LOW"
                self.nodes[n["id"]] = {"id": n["id"], "kind": n["type"], "label": n.get("title") or n["id"],
                                       "domain": n.get("domain") or "", "props": props}
            for e in args["edges"]:
                src, dst = (e["to"], e["from"]) if self.flip else (e["from"], e["to"])
                self.edges.append({"source": src, "target": dst, "type": CARRIER, "role": e["type"], "evidence": e["evidence"]})
            return {"executed": True, "warnings": []}
        if name == "vinc_graph":
            return self._graph(args["seed_id"], int(args.get("depth", 1)))
        raise ValueError(f"the fake Vinc does not serve {name}")

    def _graph(self, seed: str, depth: int) -> dict:
        reached, frontier, kept = {seed}, deque([(seed, 0)]), []
        while frontier:
            at, hops = frontier.popleft()
            if hops == depth:
                continue
            for i, e in enumerate(self.edges):
                if at in (e["source"], e["target"]):
                    other = e["target"] if e["source"] == at else e["source"]
                    kept.append(i)
                    if other not in reached:
                        reached.add(other)
                        frontier.append((other, hops + 1))
        nodes = [self.nodes.get(i) or {"id": i, "kind": i.split(":", 1)[0], "label": i, "props": {}} for i in sorted(reached)]
        return {"nodes": nodes, "edges": [self.edges[i] for i in sorted(set(kept))]}
