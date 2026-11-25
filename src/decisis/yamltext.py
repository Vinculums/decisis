from __future__ import annotations

import re

import yaml

LOADER = getattr(yaml, "CBaseLoader", yaml.BaseLoader)
MAX_BYTES = 64 * 1024 * 1024
MAX_NODES = 100_000
MAX_DEPTH = 64
CORE_TAGS = ("tag:yaml.org,2002:str", "tag:yaml.org,2002:seq", "tag:yaml.org,2002:map")
NULLS = ("", "~", "null", "Null", "NULL")
TRUES = ("true", "True", "TRUE")
FALSES = ("false", "False", "FALSE")
WHOLE = re.compile(r"-?(?:0|[1-9][0-9]{0,17})")


class Refused(ValueError):
    def __init__(self, message: str, line: int | None = None):
        super().__init__(message)
        self.line = line


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


def check(text: str, name: str, aliases: bool = False, max_nodes: int = MAX_NODES, max_depth: int = MAX_DEPTH,
          max_bytes: int = MAX_BYTES) -> None:
    if len(text.encode("utf-8", errors="replace")) > max_bytes:
        raise ValueError(f"{name} is larger than {max_bytes} bytes")
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


def _scalar(node: yaml.ScalarNode):
    text = node.value
    if node.style:
        return text
    if text in NULLS:
        return None
    if text in TRUES or text in FALSES:
        return text in TRUES
    return int(text) if WHOLE.fullmatch(text) else text


def _plain(node, name: str, depth: int, max_depth: int, path: frozenset):
    if id(node) in path:
        raise ValueError(f"{name} holds a YAML node inside itself; refused")
    if node.tag not in CORE_TAGS:
        raise ValueError(f"{name} uses a YAML tag, which is refused")
    if isinstance(node, yaml.ScalarNode):
        return _scalar(node)
    if depth >= max_depth:
        raise ValueError(f"{name} nests YAML deeper than {max_depth} levels; refused")
    path = path | {id(node)}
    if isinstance(node, yaml.SequenceNode):
        return [_plain(item, name, depth + 1, max_depth, path) for item in node.value]
    found: dict = {}
    for key, item in node.value:
        if not isinstance(key, yaml.ScalarNode):
            raise ValueError(f"{name} has a mapping key that is not text")
        if key.value in found:
            raise ValueError(f"{name} gives the key {key.value} twice")
        found[key.value] = _plain(item, name, depth + 1, max_depth, path)
    return found


def plain(text: str, name: str, max_bytes: int = MAX_BYTES, max_nodes: int = MAX_NODES, max_depth: int = MAX_DEPTH):
    try:
        check(text, name, True, max_nodes, max_depth, max_bytes)
        node = yaml.compose(text, Loader=LOADER)
    except yaml.YAMLError as e:
        marked = isinstance(e, yaml.MarkedYAMLError)
        reason = e.problem if marked and e.problem else str(e)
        mark = e.problem_mark if marked else None
        raise Refused(f"{name} is not valid YAML: {' '.join(reason.split())}", mark.line + 1 if mark else None) from None
    return None if node is None else _plain(node, name, 0, max_depth, frozenset())
