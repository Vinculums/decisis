"""`SUPERSEDES` cycles in a snapshot.

A superseded decision does not govern, so decisions that name each other as the one that replaces them would all drop
out and leave no rule in force. A cycle is a set of nodes that reach each other through `SUPERSEDES` edges, or one node
with an edge to itself. `find` lists each cycle that holds a decision. `impact.superseded_by` treats no member of a cycle
as superseded, `init` lists each cycle in `meta.problems`, and `check` lists each one as a result that cannot be judged.
The edges stay in the snapshot as the evidence. `Cycle.arriving` words a cycle that a pull request adds, which the
Action reads from the pull request's head and lists as a result that cannot be judged in the run that reads the base.
"""
from __future__ import annotations

from dataclasses import dataclass

SUPERSEDES = "SUPERSEDES"
RULE = "supersedes_cycle"
IN_FORCE = "in force"
DECISION = "decision"


@dataclass(frozen=True)
class Cycle:
    members: tuple[str, ...]
    decisions: tuple[str, ...]
    files: tuple[str, ...]

    @property
    def named(self) -> str:
        names = list(self.members)
        if len(names) == 1:
            return f"{names[0]} supersedes itself"
        if len(names) == 2:
            return f"{names[0]} and {names[1]} supersede each other"
        return f"{', '.join(names[:-1])} and {names[-1]} supersede one another in a cycle"

    @property
    def held(self) -> str:
        count = len(self.members)
        if count == 1:
            return "it is not treated as superseded, so its rules are judged"
        return f"{'neither' if count == 2 else 'none of them'} is treated as superseded, so their rules are judged"

    @property
    def where(self) -> str:
        return f" ({', '.join(self.files)})" if self.files else ""

    @property
    def reason(self) -> str:
        return f"{self.named}{self.where}; {self.held}. Fix the supersedes and superseded_by lines"

    @property
    def arriving(self) -> str:
        return f"{self.named}{self.where} once this pull request is merged; {self.held}. Fix the supersedes and superseded_by lines"


def components(follows: dict[str, set[str]]) -> list[list[str]]:
    index: dict[str, int] = {}
    low: dict[str, int] = {}
    open_: list[str] = []
    waiting: set[str] = set()
    found: list[list[str]] = []
    for start in sorted(follows):
        if start in index:
            continue
        index[start] = low[start] = len(index)
        open_.append(start)
        waiting.add(start)
        work = [(start, iter(sorted(follows[start])))]
        while work:
            node, rest = work[-1]
            for nxt in rest:
                if nxt not in index:
                    index[nxt] = low[nxt] = len(index)
                    open_.append(nxt)
                    waiting.add(nxt)
                    work.append((nxt, iter(sorted(follows[nxt]))))
                    break
                if nxt in waiting:
                    low[node] = min(low[node], index[nxt])
            else:
                work.pop()
                if work:
                    low[work[-1][0]] = min(low[work[-1][0]], low[node])
                if low[node] == index[node]:
                    group = []
                    while True:
                        member = open_.pop()
                        waiting.discard(member)
                        group.append(member)
                        if member == node:
                            break
                    found.append(sorted(group))
    return found


def source_file(node: dict) -> str:
    found = (node.get("props") or {}).get("source_file")
    return found if isinstance(found, str) else ""


def find(nodes: list[dict], edges: list[dict]) -> list[Cycle]:
    by_id = {n["id"]: n for n in nodes}
    follows: dict[str, set[str]] = {}
    for e in edges:
        if e["type"] == SUPERSEDES and e["source"] in by_id and e["target"] in by_id:
            follows.setdefault(e["source"], set()).add(e["target"])
            follows.setdefault(e["target"], set())
    out = []
    for group in components(follows):
        if len(group) == 1 and group[0] not in follows[group[0]]:
            continue
        decisions = tuple(m for m in group if by_id[m]["kind"] == DECISION)
        if not decisions:
            continue
        out.append(Cycle(tuple(group), decisions, tuple(sorted({f for m in group if (f := source_file(by_id[m]))}))))
    return sorted(out, key=lambda c: c.members)
