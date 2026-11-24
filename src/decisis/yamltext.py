from __future__ import annotations

import yaml

LOADER = getattr(yaml, "CBaseLoader", yaml.BaseLoader)
MAX_BYTES = 64 * 1024 * 1024
MAX_NODES = 100_000
MAX_DEPTH = 64


def _refuse_aliases(event, name: str) -> None:
    if isinstance(event, yaml.AliasEvent) or getattr(event, "anchor", None):
        raise ValueError(f"{name} uses a YAML anchor or alias, which a lockfile never needs; refused before it is expanded")


class _Budget:
    def __init__(self, name: str, max_nodes: int | None, max_depth: int):
        self.name, self.max_nodes, self.max_depth = name, max_nodes, max_depth
        self.sizes: dict[str, int] = {}
        self.stack: list[list] = []
        self.total = 0

    def _add(self, size: int, anchor: str | None) -> None:
        if anchor:
            self.sizes[anchor] = size
        if self.stack:
            self.stack[-1][1] += size
        else:
            self.total += size
        if self.max_nodes is not None and self.total + sum(f[1] for f in self.stack) > self.max_nodes:
            raise ValueError(f"{self.name} expands to more than {self.max_nodes} YAML nodes; refused")

    def see(self, event) -> None:
        if isinstance(event, (yaml.MappingStartEvent, yaml.SequenceStartEvent)):
            self.stack.append([event.anchor, 1])
            if len(self.stack) > self.max_depth:
                raise ValueError(f"{self.name} nests YAML deeper than {self.max_depth} levels; refused")
        elif isinstance(event, (yaml.MappingEndEvent, yaml.SequenceEndEvent)):
            anchor, size = self.stack.pop()
            self._add(size, anchor)
        elif isinstance(event, yaml.ScalarEvent):
            self._add(1, event.anchor)
        elif isinstance(event, yaml.AliasEvent):
            self._add(self.sizes.get(event.anchor, 1), None)


def check(text: str, name: str, aliases: bool = False, max_nodes: int = MAX_NODES, max_depth: int = MAX_DEPTH) -> None:
    if len(text.encode("utf-8", errors="replace")) > MAX_BYTES:
        raise ValueError(f"{name} is larger than {MAX_BYTES} bytes")
    budget = _Budget(name, max_nodes if aliases else None, max_depth)
    for event in yaml.parse(text, Loader=LOADER):
        if not aliases:
            _refuse_aliases(event, name)
        budget.see(event)


def load(text: str, name: str, aliases: bool = False, max_nodes: int = MAX_NODES, max_depth: int = MAX_DEPTH):
    try:
        check(text, name, aliases, max_nodes, max_depth)
        return yaml.load(text, Loader=LOADER)
    except yaml.YAMLError as e:
        raise ValueError(f"{name} is not valid YAML: {e}") from None
