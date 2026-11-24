"""Build a snapshot from what a repository already records: ADRs, CODEOWNERS and postmortems.

Each reader takes a `Tree` and returns `(nodes, edges)` in snapshot shape. `build` runs the readers, merges
what they return and sorts it, so the same tree always gives the same bytes. A file that cannot be read or
parsed is listed in `meta.problems` with its path and the reason, and skipped; nothing is guessed from prose,
except that `--suggest-refs` adds the paths an ADR's text names and marks them as suggested.
docs/data-model.md lists the front matter keys and headings each reader understands.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import dataclass, field
from functools import cached_property
from pathlib import Path
from typing import Callable

from . import codeowners as owners
from . import suggest
from .impact import REF_KEYS, code_path

ADR_DIRS = ("docs/adr", "docs/decisions", "adr", "doc/adr")
POSTMORTEM_DIRS = ("docs/postmortems",)
CODEOWNERS_FILES = (".github/CODEOWNERS", "CODEOWNERS", "docs/CODEOWNERS")
NOT_RECORDS = ("readme.md", "index.md")
REPO_NAME = re.compile(r"[A-Za-z0-9_-]+")
SKIPPED, KEPT, NO_EDGE, NOT_READ, NO_EFFECT = "skipped", "kept without code paths", "no edge", "not read", "no effect"
NOT_SUGGESTED = "not suggested"

TEXT_KEYS = ("title", "status", "date")
LIST_KEYS = ("deciders", "decision-makers", "supersedes", "superseded_by", "superseded-by", "decisions", *REF_KEYS)
KEY_LINE = re.compile(r"([A-Za-z_][A-Za-z0-9_-]*):(?:[ \t]+(.*))?$")
LIST_ITEM = re.compile(r"\s*-(?:[ \t]+(.*))?$")
PREAMBLE = re.compile(r"\s*(?:[*-]\s+)?(\*\*|__)?(status|date|deciders|decision-makers)(?(1)(?::\1|\1\s*:)|\s*:)\s*(.+)$", re.I)
RELATION = re.compile(r"(super[sc]edes|super[sc]eded by|amends|amended by|clarifies|clarified by)\b\s*:?\s*(.*)$", re.I)
LINK = re.compile(r"\[[^\]]*\]\(\s*([^)\s]+)[^)]*\)")
MENTION = re.compile(r"\bADR[- ]?(\d+)\b")
NUMBERED = re.compile(r"(?:adr[- ]?)?0*(\d+)", re.I)
LEADING_NUMBER = re.compile(r"(\d+)")


class Malformed(ValueError):
    pass


Reader = Callable[["Tree"], "tuple[list[dict], list[dict]]"]


@dataclass
class Tree:
    root: Path
    repo: str | None = None
    adr_dir: str | None = None
    postmortem_dir: str | None = None
    problems: list[dict] = field(default_factory=list)
    suggest_refs: bool = False

    def rel(self, path: Path) -> str:
        return path.relative_to(self.root).as_posix()

    def problem(self, where: Path | str, reason: str, action: str = SKIPPED) -> None:
        self.problems.append({"file": self.rel(where) if isinstance(where, Path) else where, "reason": reason, "action": action})

    def located(self, given: str | None, defaults: tuple[str, ...]) -> list[Path]:
        if given is None:
            return [self.root / d for d in defaults if (self.root / d).is_dir()]
        path = Path(os.path.normpath(self.root / given))
        if not path.is_relative_to(self.root):
            raise ValueError(f"{given} is outside the repository directory {self.root}")
        if not path.is_dir():
            raise ValueError(f"{given} is not a directory under {self.root}")
        return [path]

    def records(self, directory: Path) -> list[Path]:
        out = []
        for path in sorted(directory.iterdir()):
            name = path.name.lower()
            if path.suffix.lower() != ".md" or name in NOT_RECORDS or "template" in name or not path.is_file():
                continue
            if not path.resolve().is_relative_to(self.root.resolve()):
                self.problem(path, "it is a link to a file outside the repository")
                continue
            out.append(path)
        return out

    @cached_property
    def adr_files(self) -> list[Path]:
        return [p for d in self.located(self.adr_dir, ADR_DIRS) for p in self.records(d)]

    @cached_property
    def adr_index(self) -> dict[str, set[str]]:
        index: dict[str, set[str]] = {}
        for path in self.adr_files:
            nid = self.node_id("decision", path)
            keys = [self.rel(path).lower(), path.name.lower(), path.stem.lower()]
            if m := LEADING_NUMBER.match(path.name):
                keys.append(f"#{int(m.group(1))}")
            for key in keys:
                index.setdefault(key, set()).add(nid)
        return index

    @cached_property
    def path_index(self) -> suggest.Index | None:
        try:
            files, notes = suggest.repository_files(self.root)
        except suggest.TooLarge as e:
            self.problem(".", f"{e}; no code refs are suggested", NOT_READ)
            return None
        for where, note in notes:
            self.problem(where, note, NOT_READ)
        return suggest.Index.of(files)

    def node_id(self, kind: str, path: Path, extra: str = "") -> str:
        stem = self.rel(path)[: -len(path.suffix)] if path.suffix else self.rel(path)
        parts = [self.repo or "", stem, extra]
        return f"{kind}:" + "-".join(s for s in (slug(p) for p in parts) if s)

    def ref(self, raw: str) -> str:
        named = f"{self.repo}:{raw}"
        if self.repo and code_path(raw, "\0") is not None and code_path(named, self.repo) == code_path(raw):
            return named
        return raw

    def resolve_adr(self, ref: str, base: Path) -> str:
        found = set().union(*(self.adr_index.get(k, set()) for k in self.adr_keys(ref, base)))
        if not found:
            raise LookupError(f"no ADR file matches {ref!r}")
        if len(found) > 1:
            raise LookupError(f"{ref!r} matches more than one ADR: {', '.join(sorted(found))}")
        return found.pop()

    def adr_keys(self, ref: str, base: Path) -> list[str]:
        ref = ref.strip()
        target = ref.split("#", 1)[0]
        if target.lower().endswith(".md") and "://" not in target:
            joined = Path(os.path.normpath(base.parent / target))
            inside = [self.rel(joined).lower()] if joined.is_relative_to(self.root) else []
            return inside + [Path(target).name.lower()]
        if m := NUMBERED.fullmatch(ref):
            return [f"#{int(m.group(1))}"]
        return [ref.lower(), f"{ref.lower()}.md"]


def slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")


def content_hash(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def read_text(tree: Tree, path: Path) -> tuple[str, bytes] | None:
    try:
        data = path.read_bytes()
    except OSError as e:
        tree.problem(path, f"cannot read it: {e.strerror or e}")
        return None
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as e:
        tree.problem(path, f"it is not UTF-8 text (byte {e.start} cannot be decoded)")
        return None
    return text.lstrip("\ufeff").replace("\r\n", "\n"), data


def split_front_matter(text: str) -> tuple[list[str] | None, str]:
    lines = text.split("\n")
    if lines[0].rstrip() != "---":
        return None, text
    for i in range(1, len(lines)):
        if lines[i].rstrip() in ("---", "..."):
            return lines[1:i], "\n".join(lines[i + 1:])
    raise Malformed("the front matter opens with --- on line 1 and never closes")


def front_matter(lines: list[str]) -> dict:
    out: dict = {}
    open_list = None
    for n, line in enumerate(lines, start=2):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if item := LIST_ITEM.match(line):
            if open_list is None:
                raise Malformed(f"front matter line {n}: a list item with no key above it")
            out[open_list].append(list_scalar(item.group(1) or "", n))
            continue
        if line[0].isspace():
            raise Malformed(f"front matter line {n}: nested mappings are not supported")
        m = KEY_LINE.match(line.rstrip())
        if not m:
            raise Malformed(f"front matter line {n}: expected 'key: value'")
        key, raw = m.group(1), (m.group(2) or "").strip()
        if key in out:
            raise Malformed(f"front matter line {n}: {key} is given twice")
        out[key] = [] if not raw or raw.startswith("#") else value(raw, n)
        open_list = key if isinstance(out[key], list) and (not raw or raw.startswith("#")) else None
    return out


def value(raw: str, n: int):
    if raw.startswith("{"):
        return inline_json(raw, n, dict)
    if raw.startswith("["):
        return flow_list(raw, n)
    return scalar(raw, n)


def inline_json(raw: str, n: int, kind: type):
    try:
        parsed, end = json.JSONDecoder().raw_decode(raw)
    except json.JSONDecodeError as e:
        raise Malformed(f"front matter line {n}: inline JSON does not parse ({e.msg})") from None
    rest = raw[end:].strip()
    if rest and not rest.startswith("#"):
        raise Malformed(f"front matter line {n}: text after the inline JSON")
    if not isinstance(parsed, kind):
        raise Malformed(f"front matter line {n}: expected a JSON {kind.__name__}")
    return parsed


def flow_list(raw: str, n: int) -> list[str]:
    try:
        items = inline_json(raw, n, list)
    except Malformed:
        items = plain_list(raw, n)
    if not all(isinstance(i, (str, int)) and not isinstance(i, bool) for i in items):
        raise Malformed(f"front matter line {n}: list items must be text or whole numbers")
    return [str(i) for i in items]


def plain_list(raw: str, n: int) -> list[str]:
    body = re.sub(r"\]\s+#.*$", "]", raw.strip())
    if not body.endswith("]") or re.search(r"[\[\]{}\"']", body[1:-1]):
        raise Malformed(f"front matter line {n}: a [list] holds plain items or is JSON")
    return [scalar(s, n) for s in body[1:-1].split(",") if s.strip()]


def list_scalar(raw: str, n: int) -> str:
    if raw.strip()[:1] in ("[", "{"):
        raise Malformed(f"front matter line {n}: nested lists and mappings are not supported")
    return scalar(raw, n)


def scalar(raw: str, n: int) -> str:
    raw = raw.strip()
    if raw.startswith('"'):
        return inline_json(raw, n, str)
    if raw.startswith("'"):
        m = re.match(r"'((?:[^']|'')*)'\s*(?:#.*)?$", raw)
        if not m:
            raise Malformed(f"front matter line {n}: the single-quoted text does not close")
        return m.group(1).replace("''", "'")
    if raw[:1] in tuple("|>&*!%@`"):
        raise Malformed(f"front matter line {n}: {raw[0]!r} starts YAML this reader does not support (block text, anchors, aliases or tags)")
    text = re.sub(r"\s+#.*$", "", raw).strip()
    if re.search(r":(\s|$)", text):
        raise Malformed(f"front matter line {n}: nested mappings are not supported; quote text that holds ': '")
    return text


def typed(fm: dict) -> dict:
    out = {}
    for key, val in fm.items():
        if key in TEXT_KEYS:
            if not isinstance(val, str) or not val:
                raise Malformed(f"front matter {key} must be one line of text")
            out[key] = val
        elif key in LIST_KEYS:
            if isinstance(val, str):
                val = [s.strip() for s in val.split(",")] if key in ("deciders", "decision-makers") else [val]
            if not isinstance(val, list) or not all(isinstance(v, str) and v for v in val):
                raise Malformed(f"front matter {key} must be text or a list of text")
            out[key] = val
        elif key == "rule":
            if not isinstance(val, dict):
                raise Malformed("front matter rule must be an inline JSON object")
            out[key] = val
    return out


@dataclass
class Doc:
    title: str | None
    preamble: dict[str, str]
    sections: dict[str, list[str]]
    body: str


def markdown(text: str) -> Doc:
    title, preamble, sections, current, fence = None, {}, {}, None, False
    for line in text.split("\n"):
        if line.lstrip().startswith(("```", "~~~")):
            fence = not fence
        elif not fence and line.startswith("# ") and title is None and current is None:
            title = line[2:].strip() or None
            continue
        elif not fence and line.startswith("## "):
            current = line[3:].strip().lower()
            sections.setdefault(current, [])
            continue
        if current is not None:
            sections[current].append(line)
        elif not fence and title is not None and (m := PREAMBLE.match(line)):
            preamble.setdefault(m.group(2).lower(), m.group(3).strip())
    return Doc(title, preamble, sections, text)


def paragraph(lines: list[str]) -> str | None:
    out: list[str] = []
    for line in lines:
        if line.strip():
            out.append(line.strip())
        elif out:
            break
    return " ".join(out) or None


def status_of(lines: list[str]) -> tuple[str | None, list[str], list[str]]:
    status, supersedes, superseded_by = None, [], []
    for line in lines:
        text = line.strip().strip("*_").strip()
        if not text:
            continue
        if m := RELATION.match(text):
            verb = m.group(1).lower().replace("supercede", "supersede")
            targets = LINK.findall(m.group(2)) or [m.group(2).strip()]
            {"supersedes": supersedes, "superseded by": superseded_by}.get(verb, []).extend(t for t in targets if t)
        elif status is None:
            status = text
    if status is None and superseded_by:
        status = "superseded"
    return (normal_status(status) if status else None), supersedes, superseded_by


def normal_status(text: str) -> str:
    return re.sub(r"\s+", " ", LINK.sub("", text)).strip().rstrip(".").lower().replace("supercede", "supersede")


def code_refs(tree: Tree, fm: dict) -> dict[str, list[str]]:
    out = {}
    for key in REF_KEYS:
        refs = fm.get(key, [])
        for r in refs:
            p = code_path(r)
            if r.strip().startswith("/") or p is None or ".." in p.split("/"):
                raise Malformed(f"front matter {key} {r!r} is not a path relative to the repository root")
        if refs:
            out[key] = [tree.ref(r.strip()) for r in refs]
    return out


@dataclass
class Parsed:
    fm: dict
    doc: Doc
    data: bytes
    refs: dict[str, list[str]]


def parse(tree: Tree, path: Path) -> Parsed | None:
    read = read_text(tree, path)
    if read is None:
        return None
    text, data = read
    try:
        lines, body = split_front_matter(text)
        fm = typed(front_matter(lines)) if lines is not None else {}
        doc = markdown(body)
        if not (fm.get("title") or doc.title):
            raise Malformed("it has no title: neither a front matter title nor a '# ' heading")
        refs = code_refs(tree, fm)
    except Malformed as e:
        tree.problem(path, str(e))
        return None
    return Parsed(fm, doc, data, refs)


def base_props(tree: Tree, path: Path, parsed: Parsed) -> dict:
    return {"source_file": tree.rel(path), "content_hash": content_hash(parsed.data)}


def adr_fields(parsed: Parsed) -> tuple[dict, list[str], list[str]]:
    fm, doc = parsed.fm, parsed.doc
    head = status_of([doc.preamble["status"]]) if "status" in doc.preamble else (None, [], [])
    body = status_of(doc.sections.get("status", []))
    front = status_of([fm["status"]]) if "status" in fm else (None, [], [])
    status = front[0] or head[0] or body[0]
    date = fm.get("date") or doc.preamble.get("date")
    deciders = fm.get("deciders") or fm.get("decision-makers") or split_names(doc.preamble.get("deciders") or doc.preamble.get("decision-makers"))
    statement = paragraph(doc.sections.get("decision") or doc.sections.get("decision outcome") or [])
    fields = {"status": status, "date": date, "deciders": deciders, "statement": statement}
    supersedes = fm.get("supersedes", []) + front[1] + head[1] + body[1]
    superseded_by = fm.get("superseded_by", []) + fm.get("superseded-by", []) + front[2] + head[2] + body[2]
    return {k: v for k, v in fields.items() if v}, supersedes, superseded_by


def split_names(text: str | None) -> list[str]:
    return [s.strip() for s in (text or "").split(",") if s.strip()]


def read_adrs(tree: Tree) -> tuple[list[dict], list[dict]]:
    if tree.adr_dir is None and not tree.located(None, ADR_DIRS):
        tree.problem(".", f"no ADR directory: looked in {', '.join(ADR_DIRS)}", NOT_READ)
    nodes, edges = [], {}
    for path in tree.adr_files:
        parsed = parse(tree, path)
        if parsed is None:
            continue
        fields, supersedes, superseded_by = adr_fields(parsed)
        refs = parsed.refs or suggested_refs(tree, path, parsed)
        props = {**base_props(tree, path, parsed), **fields, **refs}
        if "rule" in parsed.fm:
            props["rule"] = parsed.fm["rule"]
        nid = tree.node_id("decision", path)
        nodes.append({"id": nid, "kind": "decision", "title": parsed.fm.get("title") or parsed.doc.title, "props": props})
        if not refs:
            tree.problem(path, "it names no code paths (front matter code_ref, subject_path or also_touches)", KEPT)
        for verb, refs_named in (("supersedes", supersedes), ("is superseded by", superseded_by)):
            for ref in refs_named:
                link(tree, path, nid, verb, ref, edges)
    return nodes, list(edges.values())


def suggested_refs(tree: Tree, path: Path, parsed: Parsed) -> dict:
    if not tree.suggest_refs or tree.path_index is None:
        return {}
    found = suggest.suggest(tree.path_index, parsed.doc.body, tree.rel(path.parent))
    for token in sorted(found.skipped):
        tree.problem(path, f"{found.skipped[token]}; it is not suggested as a code ref", NOT_SUGGESTED)
    if not found.refs:
        return {}
    refs = sorted(found.refs)
    return {"code_ref": [tree.ref(r) for r in refs], "code_ref_evidence": [{"code_ref": tree.ref(r), "sentence": found.refs[r]} for r in refs],
            "code_ref_source": "suggested"}


def link(tree: Tree, path: Path, nid: str, verb: str, ref: str, edges: dict) -> None:
    try:
        other = tree.resolve_adr(ref, path)
    except LookupError as e:
        tree.problem(path, f"it {verb} {ref}, but {e}", NO_EDGE)
        return
    new, old = (nid, other) if verb == "supersedes" else (other, nid)
    if new == old:
        tree.problem(path, f"it {verb} itself ({ref})", NO_EDGE)
        return
    edges.setdefault((new, old), {"source": new, "target": old, "type": "SUPERSEDES", "evidence": f"{tree.rel(path)} says it {verb} {ref}"})


def read_postmortems(tree: Tree) -> tuple[list[dict], list[dict]]:
    nodes, edges = [], {}
    for directory in tree.located(tree.postmortem_dir, POSTMORTEM_DIRS):
        for path in tree.records(directory):
            parsed = parse(tree, path)
            if parsed is None:
                continue
            refs = parsed.refs
            date = parsed.fm.get("date") or parsed.doc.preamble.get("date")
            props = {**base_props(tree, path, parsed), **({"date": date} if date else {}), **refs}
            nid = tree.node_id("record", path)
            nodes.append({"id": nid, "kind": "record", "title": parsed.fm.get("title") or parsed.doc.title, "props": props})
            if not refs:
                tree.problem(path, "it names no code paths (front matter code_ref, subject_path or also_touches)", KEPT)
            for target, ref in named_decisions(tree, path, parsed):
                edges.setdefault((nid, target), {"source": nid, "target": target, "type": "ABOUT", "evidence": f"{tree.rel(path)} names {ref}"})
    return nodes, list(edges.values())


def named_decisions(tree: Tree, path: Path, parsed: Parsed) -> list[tuple[str, str]]:
    out = []
    stated = [(r, True) for r in parsed.fm.get("decisions", [])] + [(f"ADR-{m}", True) for m in MENTION.findall(parsed.doc.body)]
    linked = [(t, False) for t in LINK.findall(parsed.doc.body) if t.split("#", 1)[0].lower().endswith(".md")]
    for ref, must in stated + linked:
        try:
            out.append((tree.resolve_adr(ref, path), ref))
        except LookupError as e:
            if must:
                tree.problem(path, f"it names {ref}, but {e}", NO_EDGE)
    return out


def codeowners_file(tree: Tree) -> Path | None:
    found = []
    for name in CODEOWNERS_FILES:
        path = tree.root / name
        if not path.is_file():
            continue
        if not path.resolve().is_relative_to(tree.root.resolve()):
            tree.problem(path, "it is a link to a file outside the repository")
            continue
        found.append(path)
    for extra in found[1:]:
        tree.problem(extra, f"GitHub reads only the first of {', '.join(CODEOWNERS_FILES)}; this one is {tree.rel(found[0])}", NOT_READ)
    return found[0] if found else None


def owner_rules(tree: Tree, path: Path, text: str) -> list[owners.Rule]:
    rules = []
    for n, line in enumerate(text.split("\n"), start=1):
        entry = re.sub(r"(^|\s)#.*$", "", line).strip().split()
        if not entry:
            continue
        pattern, names = entry[0], tuple(entry[1:])
        bad = [o for o in names if "@" not in o]
        try:
            if bad:
                raise owners.Unsupported(f"{bad[0]} is not @user, @org/team or an email address")
            rules.append(owners.Rule(n, pattern, tuple(sorted(set(names))), owners.compile_pattern(pattern)))
        except owners.Unsupported as e:
            tree.problem(path, f"line {n}: {e}")
    return rules


def read_codeowners(tree: Tree) -> tuple[list[dict], list[dict]]:
    path = codeowners_file(tree)
    read = read_text(tree, path) if path else None
    if read is None:
        return [], []
    rules = owner_rules(tree, path, read[0])
    try:
        files, _ = owners.repository_files(tree.root)
    except owners.TooLarge as e:
        tree.problem(path, f"{e}; owners are not read")
        return [], []
    won = owners.owning_rules(rules, files)
    report_idle_rules(tree, path, rules, files, won)
    sets = owners.cover(files, {f: r.owners for f, r in won.items()})
    lines: dict[tuple[str, ...], set[int]] = {}
    for rule in won.values():
        lines.setdefault(rule.owners, set()).add(rule.line)
    return [owners_concept(tree, path, read[1], names, refs, sorted(lines[names])) for names, refs in sets.items()], []


def report_idle_rules(tree: Tree, path: Path, rules: list[owners.Rule], files: list[str], won: dict[str, owners.Rule]) -> None:
    winning = {r.line for r in won.values()}
    for rule in rules:
        if rule.line in winning or not rule.owners:
            continue
        if any(rule.regex.fullmatch(f) for f in files):
            tree.problem(path, f"line {rule.line}: a later line owns every file the pattern {rule.pattern} matches", NO_EFFECT)
        else:
            tree.problem(path, f"line {rule.line}: the pattern {rule.pattern} matches no file in the repository", NO_EFFECT)


def owners_concept(tree: Tree, path: Path, data: bytes, names: tuple[str, ...], refs: list[str], lines: list[int]) -> dict:
    digest = hashlib.sha256("\n".join(names).encode("utf-8")).hexdigest()[:12]
    nid = "concept:" + "-".join(s for s in (slug(tree.repo or ""), "codeowners", slug(" ".join(names))[:60].strip("-"), digest) if s)
    props = {"source_file": tree.rel(path), "content_hash": content_hash(data), "owners": list(names), "source_lines": lines,
             "code_ref": [tree.ref(r) for r in refs]}
    return {"id": nid, "kind": "concept", "title": "Owned by " + ", ".join(names), "props": props}


READERS: tuple[Reader, ...] = (read_adrs, read_codeowners, read_postmortems)


def build(repo_dir: str | Path, repo: str | None = None, *readers: Reader, adr_dir: str | None = None,
          postmortem_dir: str | None = None, suggest_refs: bool = False) -> dict:
    root = Path(os.path.abspath(repo_dir))
    if not root.is_dir():
        raise ValueError(f"{repo_dir} is not a directory")
    if repo is not None and not REPO_NAME.fullmatch(repo):
        raise ValueError(f"--repo {repo!r} must be letters, digits, '-' or '_'")
    tree = Tree(root, repo, adr_dir, postmortem_dir, suggest_refs=suggest_refs)
    nodes, edges = merge(tree, readers or READERS)
    problems = {(p["file"], p["action"], p["reason"]): p for p in tree.problems}
    meta = {"source": "decisis init", "repo": repo, "nodes": len(nodes), "edges": len(edges), "problems": [problems[k] for k in sorted(problems)]}
    return {"meta": meta, "nodes": nodes, "edges": edges}


def merge(tree: Tree, readers: tuple[Reader, ...]) -> tuple[list[dict], list[dict]]:
    nodes: dict[str, dict] = {}
    edges: dict[tuple[str, str, str], dict] = {}
    for reader in readers:
        found, links = reader(tree)
        for node in found:
            if node["id"] in nodes:
                tree.problem(origin(node), f"its id {node['id']} is already taken by {origin(nodes[node['id']])}")
                continue
            nodes[node["id"]] = node
        for e in links:
            edges.setdefault((e["source"], e["type"], e["target"]), e)
    kept = [e for _, e in sorted(edges.items()) if e["source"] in nodes and e["target"] in nodes]
    return [nodes[k] for k in sorted(nodes)], kept


def origin(node: dict) -> str:
    props = node.get("props") or {}
    return props.get("source_file") or props.get("source") or node["id"]


def dump(snapshot: dict) -> str:
    return json.dumps(snapshot, ensure_ascii=False, indent=1) + "\n"
