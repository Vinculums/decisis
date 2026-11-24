"""The imports a source file makes, read without running any of the repository's code.

Python files are parsed with `ast`. `import a.b`, `from a.b import c` and relative imports are listed, and
`importlib.import_module` and `__import__` calls with a literal name are read like an import. A module name
resolves to a file under the repository root or under `src/` (`a/b.py`, `a/b.pyi`, `a/b/__init__.py`, or the
directory `a/b/` of a namespace package, when it holds a Python file); a relative import resolves from the file's own directory. A module
found under neither root is external (the standard library or an installed package), unless its first part is
in the repository, which makes it unresolved.

JavaScript and TypeScript files are read with a small scanner that skips comments, strings, template literals
and regular expressions, so an import inside any of them is not listed. It lists `import ... from "x"`,
`import "x"`, `export ... from "x"`, and `require("x")` and `import("x")` with a literal specifier. A
relative specifier resolves to the file itself, the file with one of `EXTENSIONS`, a `.ts` file for a `.js`
specifier, or an `index` file in that directory. `paths` and `baseUrl` from the `tsconfig.json` at the
repository root are applied to other specifiers; one that still names no file is an external package, given
the target `node_modules/<specifier>`.

A call whose specifier is not a literal, a relative import that names no file in the repository, and a file
that cannot be parsed are unresolved. Every path is checked to stay inside the repository after symbolic links.
"""
from __future__ import annotations

import ast
import json
import os
import posixpath
from dataclasses import dataclass
from pathlib import Path

PYTHON = (".py", ".pyi")
SCRIPT = (".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts")
EXTENSIONS = (".ts", ".tsx", ".d.ts", ".js", ".jsx", ".mjs", ".cjs", ".mts", ".cts", ".json")
COMPILED = {".js": (".ts", ".tsx"), ".jsx": (".tsx",), ".mjs": (".mts",), ".cjs": (".cts",)}
MAX_BYTES = 2_000_000
REPOSITORY, EXTERNAL, UNRESOLVED = "repository", "external", "unresolved"
COMPUTED = "the specifier is computed at run time"
REGEX_AFTER = {"return", "typeof", "case", "do", "else", "in", "of", "new", "delete", "void", "throw", "instanceof", "yield", "await"}
CLAUSE = set("{},*")


@dataclass(frozen=True)
class Import:
    line: int | None
    specifier: str
    resolution: str
    target: str | None
    why: str = ""


@dataclass(frozen=True)
class Token:
    kind: str
    value: str | None
    line: int


class Repo:
    def __init__(self, root: Path):
        self.root = Path(root)
        self.real = self.root.resolve()
        self.seen: dict[str, str | None] = {}
        self.tsconfig = None

    def kind(self, rel: str) -> str | None:
        if rel not in self.seen:
            self.seen[rel] = self._kind(rel)
        return self.seen[rel]

    def _kind(self, rel: str) -> str | None:
        path = self.root / rel if rel else self.root
        try:
            real = path.resolve()
            real.relative_to(self.real)
        except (OSError, ValueError, RuntimeError):
            return "outside"
        if real.is_file():
            return "file"
        return "dir" if real.is_dir() else None

    def is_file(self, rel: str) -> bool:
        return self.kind(rel) == "file"

    def is_dir(self, rel: str) -> bool:
        return self.kind(rel) == "dir"

    def python_dir(self, rel: str) -> bool:
        if not self.is_dir(rel):
            return False
        try:
            return any(e.name.endswith(PYTHON) and e.is_file() for e in os.scandir(self.root / rel))
        except OSError:
            return False

    def python_roots(self) -> list[str]:
        return ["", "src/"] if self.is_dir("src") else [""]


def source(rel: str) -> str | None:
    if rel.endswith(PYTHON):
        return "python"
    if rel.endswith(SCRIPT):
        return "script"
    return None


def read(repo: Repo, rel: str) -> list[Import]:
    lang = source(rel)
    kind = repo.kind(rel)
    if lang is None or kind is None:
        return []
    if kind == "outside":
        return [Import(None, rel, UNRESOLVED, None, "the file lies outside the repository")]
    if kind != "file":
        return []
    path = repo.root / rel
    try:
        if path.stat().st_size > MAX_BYTES:
            return [Import(None, rel, UNRESOLVED, None, f"the file is larger than {MAX_BYTES} bytes")]
        data = path.read_bytes()
    except OSError as e:
        return [Import(None, rel, UNRESOLVED, None, f"the file cannot be read ({e.strerror or type(e).__name__})")]
    found = python_imports(repo, rel, data) if lang == "python" else script_imports(repo, rel, data.decode("utf-8", "replace"))
    return sorted(set(found), key=lambda i: (i.line or 0, i.specifier, i.target or ""))


def python_imports(repo: Repo, rel: str, data: bytes) -> list[Import]:
    try:
        tree = ast.parse(data, filename=rel)
    except (SyntaxError, ValueError, RecursionError, MemoryError) as e:
        return [Import(None, rel, UNRESOLVED, None, f"the file cannot be parsed ({type(e).__name__})")]
    out: list[Import] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            out += [module_import(repo, node.lineno, f"import {a.name}", a.name) for a in node.names]
        elif isinstance(node, ast.ImportFrom):
            out += from_import(repo, rel, node)
        elif isinstance(node, ast.Call) and dynamic_import(node.func):
            out.append(call_import(repo, node))
    return out


def dynamic_import(func: ast.expr) -> bool:
    if isinstance(func, ast.Name):
        return func.id in ("__import__", "import_module")
    return isinstance(func, ast.Attribute) and func.attr == "import_module"


def call_import(repo: Repo, node: ast.Call) -> Import:
    arg = node.args[0] if node.args else None
    if not isinstance(arg, ast.Constant) or not isinstance(arg.value, str) or not arg.value:
        name = node.func.id if isinstance(node.func, ast.Name) else node.func.attr
        return Import(node.lineno, f"{name}() with a computed name", UNRESOLVED, None, COMPUTED)
    if arg.value.startswith("."):
        return Import(node.lineno, arg.value, UNRESOLVED, None, "a relative name read against a package given at run time")
    return module_import(repo, node.lineno, arg.value, arg.value)


def module_file(repo: Repo, parts: list[str]) -> str | None:
    base = "/".join(parts)
    for candidate in (f"{base}.py", f"{base}.pyi", f"{base}/__init__.py", f"{base}/__init__.pyi"):
        if repo.is_file(candidate):
            return candidate
    return f"{base}/" if base and repo.python_dir(base) else None


def find_module(repo: Repo, parts: list[str]) -> str | None:
    for root in repo.python_roots():
        hit = module_file(repo, [*root.strip("/").split("/"), *parts] if root else parts)
        if hit:
            return hit
    return None


def module_import(repo: Repo, line: int, shown: str, dotted: str) -> Import:
    parts = dotted.split(".")
    hit = find_module(repo, parts)
    if hit:
        return Import(line, shown, REPOSITORY, hit)
    if len(parts) > 1 and find_module(repo, parts[:1]):
        return Import(line, shown, UNRESOLVED, None, f"{parts[0]} is in the repository but {dotted} is not")
    return Import(line, shown, EXTERNAL, None)


def from_import(repo: Repo, rel: str, node: ast.ImportFrom) -> list[Import]:
    module = node.module or ""
    shown = f"from {'.' * node.level}{module} import "
    names = [a.name for a in node.names if a.name != "*"]
    listed = ", ".join(names) or "*"
    if node.level == 0:
        subs = [Import(node.lineno, shown + n, REPOSITORY, hit) for n in names if (hit := find_module(repo, [*module.split("."), n]))]
        return subs if subs and len(subs) == len(names) else subs + [module_import(repo, node.lineno, shown + listed, module)]
    here = rel.split("/")[:-1]
    up = node.level - 1
    if up > len(here):
        return [Import(node.lineno, shown + listed, UNRESOLVED, None, "the relative import goes above the repository")]
    base = here[:len(here) - up] + (module.split(".") if module else [])
    subs = [Import(node.lineno, shown + n, REPOSITORY, hit) for n in names if (hit := module_file(repo, [*base, n]))]
    if subs and len(subs) == len(names):
        return subs
    hit = module_file(repo, base) if base else None
    if hit:
        return subs + [Import(node.lineno, shown + listed, REPOSITORY, hit)]
    return subs + [Import(node.lineno, shown + listed, UNRESOLVED, None, "no file in the repository matches the relative import")]


def name_char(c: str) -> bool:
    return c.isalnum() or c in "_$" or ord(c) > 127


def tokens(text: str) -> list[Token]:
    return list(Scanner(text).run())


class Scanner:
    def __init__(self, text: str):
        self.text = text
        self.i = 0
        self.line = 1
        self.prev: Token | None = None
        self.depths: list[int] = []

    def run(self):
        if self.text.startswith("#!"):
            self.skip_to("\n")
        while self.i < len(self.text):
            token = self.step()
            if token is not None:
                self.prev = token
                yield token

    def skip_to(self, end: str) -> None:
        j = self.text.find(end, self.i)
        j = len(self.text) if j < 0 else j + len(end)
        self.line += self.text.count("\n", self.i, j)
        self.i = j

    def step(self) -> Token | None:
        t, i = self.text, self.i
        c = t[i]
        if c.isspace():
            self.line += c == "\n"
            self.i += 1
            return None
        if t.startswith("//", i) or t.startswith("<!--", i):
            self.skip_to("\n")
            return None
        if t.startswith("/*", i):
            self.skip_to("*/")
            return None
        if c in "'\"":
            return self.string(c)
        if c == "`":
            return self.template(True)
        if c == "/" and self.regex_allowed() and self.regex():
            return None
        if name_char(c):
            return self.word()
        return self.punct(c)

    def punct(self, c: str) -> Token | None:
        self.i += 1
        if c == "{" and self.depths:
            self.depths[-1] += 1
        if c == "}" and self.depths:
            if self.depths[-1] == 0:
                self.depths.pop()
                self.template(False)
                return None
            self.depths[-1] -= 1
        return Token("punct", c, self.line)

    def word(self) -> Token:
        t, j, line = self.text, self.i, self.line
        while j < len(t) and name_char(t[j]):
            j += 1
        value, self.i = t[self.i:j], j
        return Token("num" if value[0].isdigit() else "name", value, line)

    def string(self, quote: str) -> Token:
        t, j, line, out = self.text, self.i + 1, self.line, []
        while j < len(t) and t[j] != quote:
            if t[j] == "\n":
                self.i = j
                return Token("string", None, line)
            if t[j] == "\\":
                out.append(t[j + 1:j + 2] if t[j + 1:j + 2] in ("\\", "'", '"') else "\0")
                self.line += t[j + 1:j + 2] == "\n"
                j += 2
                continue
            out.append(t[j])
            j += 1
        self.i = j + 1
        value = "".join(out)
        return Token("string", None if "\0" in value else value, line)

    def template(self, start: bool) -> Token | None:
        t, j, line, out = self.text, self.i + (1 if start else 0), self.line, []
        while j < len(t):
            if t[j] == "\\":
                out.append("\0")
                self.line += t[j + 1:j + 2] == "\n"
                j += 2
                continue
            if t[j] == "`":
                self.i = j + 1
                return Token("string", "".join(out) if start and "\0" not in out else None, line) if start else None
            if t.startswith("${", j):
                self.i = j + 2
                self.depths.append(0)
                return Token("string", None, line) if start else None
            self.line += t[j] == "\n"
            out.append(t[j])
            j += 1
        self.i = j
        return Token("string", None, line) if start else None

    def regex_allowed(self) -> bool:
        p = self.prev
        if p is None:
            return True
        if p.kind == "punct":
            return p.value not in ")]"
        return p.kind == "name" and p.value in REGEX_AFTER

    def regex(self) -> bool:
        t, j, in_class = self.text, self.i + 1, False
        if t.startswith(("/", "*"), j):
            return False
        while j < len(t) and t[j] != "\n":
            c = t[j]
            if c == "\\":
                j += 2
                continue
            if c == "[":
                in_class = True
            elif c == "]":
                in_class = False
            elif c == "/" and not in_class:
                j += 1
                while j < len(t) and name_char(t[j]):
                    j += 1
                self.i = j
                self.prev = Token("regex", None, self.line)
                return True
            j += 1
        return False


def script_refs(toks: list[Token]) -> list[tuple[int, str | None, str]]:
    out = []
    for i, tok in enumerate(toks):
        if tok.kind != "name" or tok.value not in ("import", "export", "require"):
            continue
        before = toks[i - 1] if i else None
        if before is not None and (before.value == "." or before.value == "function"):
            continue
        nxt = toks[i + 1] if i + 1 < len(toks) else None
        if nxt is not None and nxt.value == "(" and tok.value != "export":
            out.append(call_ref(toks, i))
        elif tok.value == "import" and nxt is not None and nxt.kind == "string":
            out.append((tok.line, nxt.value, "import"))
        elif tok.value != "require" and nxt is not None and nxt.value != ".":
            ref = clause_ref(toks, i)
            if ref is not None:
                out.append(ref)
    return out


def call_ref(toks: list[Token], i: int) -> tuple[int, str | None, str]:
    arg = toks[i + 2] if i + 2 < len(toks) else None
    close = toks[i + 3] if i + 3 < len(toks) else None
    literal = arg is not None and arg.kind == "string" and arg.value is not None and close is not None and close.value in (")", ",")
    return toks[i].line, arg.value if literal else None, f"{toks[i].value}()"


def clause_ref(toks: list[Token], i: int) -> tuple[int, str | None, str] | None:
    for j in range(i + 1, min(len(toks) - 1, i + 4096)):
        tok = toks[j]
        if tok.kind == "name" and tok.value == "from" and toks[j + 1].kind == "string":
            return toks[i].line, toks[j + 1].value, toks[i].value
        if tok.kind == "name" and tok.value not in ("import", "export"):
            continue
        if tok.kind != "punct" or tok.value not in CLAUSE:
            return None
    return None


def script_imports(repo: Repo, rel: str, text: str) -> list[Import]:
    out = []
    for line, spec, how in script_refs(tokens(text)):
        if spec is None:
            out.append(Import(line, f"{how} with a computed specifier", UNRESOLVED, None, COMPUTED))
            continue
        resolution, target, why = script_target(repo, rel, spec)
        out.append(Import(line, spec, resolution, target, why))
    return out


def script_target(repo: Repo, rel: str, spec: str) -> tuple[str, str | None, str]:
    if spec in (".", "..") or spec.startswith(("./", "../")):
        base = posixpath.normpath(posixpath.join(posixpath.dirname(rel), spec))
        if base == ".." or base.startswith("../"):
            return UNRESOLVED, None, "the relative specifier goes above the repository"
        hit = script_file(repo, "" if base == "." else base)
        return (REPOSITORY, hit, "") if hit else (UNRESOLVED, None, "no file in the repository matches the relative specifier")
    if spec.startswith("/"):
        return UNRESOLVED, None, "an absolute path is not read"
    hit = aliased(repo, spec)
    if hit:
        return REPOSITORY, hit, ""
    return EXTERNAL, "node_modules/" + spec, ""


def script_file(repo: Repo, base: str) -> str | None:
    if base and repo.is_file(base):
        return base
    stem, ext = posixpath.splitext(base)
    candidates = [base + e for e in EXTENSIONS] + [stem + e for e in COMPILED.get(ext, ())]
    candidates += [posixpath.join(base, "index" + e) for e in EXTENSIONS]
    return next((c for c in candidates if repo.is_file(c)), None)


def aliased(repo: Repo, spec: str) -> str | None:
    config = tsconfig(repo)
    for pattern, targets in config["paths"]:
        star = wildcard(pattern, spec)
        if star is None:
            continue
        for target in targets:
            hit = inside(repo, posixpath.join(config["paths_base"], target.replace("*", star, 1)))
            if hit:
                return hit
    return inside(repo, posixpath.join(config["base_url"], spec)) if config["base_url"] is not None else None


def inside(repo: Repo, path: str) -> str | None:
    base = posixpath.normpath(path)
    if base == ".." or base.startswith(("../", "/")):
        return None
    return script_file(repo, "" if base == "." else base)


def wildcard(pattern: str, spec: str) -> str | None:
    if "*" not in pattern:
        return "" if pattern == spec else None
    head, tail = pattern.split("*", 1)
    if spec.startswith(head) and spec.endswith(tail) and len(spec) >= len(head) + len(tail):
        return spec[len(head):len(spec) - len(tail)]
    return None


def tsconfig(repo: Repo) -> dict:
    if repo.tsconfig is None:
        repo.tsconfig = read_tsconfig(repo)
    return repo.tsconfig


def read_tsconfig(repo: Repo) -> dict:
    empty = {"paths": [], "paths_base": ".", "base_url": None}
    if not repo.is_file("tsconfig.json"):
        return empty
    try:
        path = repo.root / "tsconfig.json"
        if path.stat().st_size > MAX_BYTES:
            return empty
        options = json.loads(plain_json(path.read_text(encoding="utf-8"))).get("compilerOptions") or {}
    except (OSError, UnicodeDecodeError, ValueError, AttributeError):
        return empty
    base_url = options.get("baseUrl") if isinstance(options.get("baseUrl"), str) else None
    paths = options.get("paths") if isinstance(options.get("paths"), dict) else {}
    usable = [(k, [t for t in v if isinstance(t, str)]) for k, v in paths.items() if isinstance(k, str) and isinstance(v, list)]
    usable.sort(key=lambda kv: -len(kv[0].split("*", 1)[0]))
    return {"paths": usable, "paths_base": base_url or ".", "base_url": base_url}


def plain_json(text: str) -> str:
    out, i, n = [], 0, len(text)
    while i < n:
        c = text[i]
        if c == '"':
            j = i + 1
            while j < n and text[j] != '"':
                j += 2 if text[j] == "\\" else 1
            out.append(text[i:j + 1])
            i = j + 1
        elif text.startswith("//", i):
            i = n if text.find("\n", i) < 0 else text.find("\n", i)
        elif text.startswith("/*", i):
            i = n if text.find("*/", i) < 0 else text.find("*/", i) + 2
        elif c == "," and text[i + 1:].lstrip()[:1] in ("}", "]"):
            i += 1
        else:
            out.append(c)
            i += 1
    return "".join(out)
