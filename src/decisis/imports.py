"""The imports a source file makes, read without running any of the repository's code.

Python files are parsed with `ast`. `import a.b`, `from a.b import c` and relative imports are listed, and
`importlib.import_module` and `__import__` calls with a literal name are read like an import. A module name
is looked up under the root of the file's own package (the first directory above it without an
`__init__.py`), the nearest directory above it with a `pyproject.toml`, `setup.py` or `setup.cfg` and its
`src/`, the repository root and `src/`: `a/b.py`, `a/b.pyi`, `a/b/__init__.py`, or the directory
`a/b/` of a namespace package when it holds a Python file. A relative import resolves from the file's own
directory. A module found under none of those roots is external (the standard library or an installed
package), unless its first part is a package or module somewhere in the repository and not a standard
library name, which makes it unresolved.

JavaScript and TypeScript files are read with a scanner that skips comments, strings, template literals,
regular expressions and, outside `.ts`, `.mts` and `.cts` files, JSX text. It lists `import ... from "x"`,
`import "x"`, `export ... from "x"`, and `require("x")` and `import("x")` with a literal specifier. A
relative specifier resolves to the file itself, the file with one of `EXTENSIONS`, a `.ts` file for a `.js`
specifier, or an `index` file in that directory. `paths` and `baseUrl` from the nearest `tsconfig.json` or
`jsconfig.json` above the file, with its `extends` chain inside the repository, apply to other specifiers;
one that matches a `paths` pattern but names no file is unresolved. Any other specifier is an external
package, given the target `node_modules/<specifier>`.

A plain text search for the same import forms runs over every JavaScript and TypeScript file as well. A
specifier it finds that the scanner did not read as code is listed as unresolved, with the file it would
name, so a scanner mistake can never make an import disappear.

A call whose specifier is not a literal, a relative import that names no file, a file that cannot be parsed
or scanned to its end, and a config that cannot be read or extends a package are unresolved. Every path is
checked to stay inside the repository after symbolic links.
"""
from __future__ import annotations

import ast
import json
import os
import posixpath
import re
import sys
from dataclasses import dataclass
from pathlib import Path

PYTHON = (".py", ".pyi")
SCRIPT = (".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts")
TYPESCRIPT_ONLY = (".ts", ".mts", ".cts")
EXTENSIONS = (".ts", ".tsx", ".d.ts", ".js", ".jsx", ".mjs", ".cjs", ".mts", ".cts", ".json")
COMPILED = {".js": (".ts", ".tsx"), ".jsx": (".tsx",), ".mjs": (".mts",), ".cjs": (".cts",)}
CONFIGS = ("tsconfig.json", "jsconfig.json")
MAX_BYTES = 2_000_000
MAX_EXTENDS = 16
MAX_NESTING = 100
MAX_WALK = 200_000
PROJECT_FILES = ("pyproject.toml", "setup.py", "setup.cfg")
SKIPPED_DIRS = {"node_modules", "__pycache__", "site-packages"}
REPOSITORY, EXTERNAL, UNRESOLVED = "repository", "external", "unresolved"
COMPUTED = "the specifier is computed at run time"
DISAGREE = "a text search finds this specifier where the scanner read a comment, a string or other text; the scanner and the text search disagree"
REGEX_AFTER = {"return", "typeof", "case", "do", "else", "in", "of", "new", "delete", "void", "throw", "instanceof", "yield", "await"}
VALUE_END = (")", "]", "}", "++", "--")
CLAUSE = set("{},*")
SWEEP = re.compile(r"""\b(?:import|require)\s*\(\s*(['"`])([^'"`\n]+?)\1|\bfrom\s*(['"])([^'"\n]+?)\3|\bimport\s*(['"])([^'"\n]+?)\5""")


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


class Broken(Exception):
    pass


class Repo:
    def __init__(self, root: Path):
        self.root = Path(root)
        self.real = self.root.resolve()
        self.seen: dict[str, str | None] = {}
        self.configs: dict[str, dict] = {}
        self.names: set[str] | None = None

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

    def python_roots(self, rel: str) -> list[str]:
        here = rel.split("/")[:-1]
        while here and self.is_file("/".join(here) + "/__init__.py"):
            here.pop()
        project = self.python_project(rel.split("/")[:-1])
        roots = ["/".join(here) + "/" if here else "", *project, "", "src/"]
        return [r for r in dict.fromkeys(roots) if not r or self.is_dir(r.rstrip("/"))]

    def python_project(self, here: list[str]) -> list[str]:
        while here:
            base = "/".join(here)
            if any(self.is_file(f"{base}/{name}") for name in PROJECT_FILES):
                return [base + "/", base + "/src/"]
            here = here[:-1]
        return []

    def python_names(self) -> set[str]:
        if self.names is None:
            self.names = walk_python_names(self.root)
        return self.names


def walk_python_names(root: Path) -> set[str]:
    names: set[str] = set()
    seen = 0
    for dirpath, dirnames, filenames in os.walk(root):
        if "pyvenv.cfg" in filenames:
            dirnames[:] = []
            continue
        dirnames[:] = [d for d in dirnames if not d.startswith(".") and d not in SKIPPED_DIRS]
        modules = [f for f in filenames if f.endswith(PYTHON)]
        if modules and Path(dirpath) != root:
            names.add(Path(dirpath).name)
        names.update(f.rsplit(".", 1)[0] for f in modules if not f.startswith("__"))
        seen += len(filenames)
        if seen > MAX_WALK:
            break
    return names


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
    roots = repo.python_roots(rel)
    out: list[Import] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            out += [module_import(repo, roots, node.lineno, f"import {a.name}", a.name) for a in node.names]
        elif isinstance(node, ast.ImportFrom):
            out += from_import(repo, roots, rel, node)
        elif isinstance(node, ast.Call) and dynamic_import(node.func):
            out.append(call_import(repo, roots, node))
    return out


def dynamic_import(func: ast.expr) -> bool:
    if isinstance(func, ast.Name):
        return func.id in ("__import__", "import_module")
    return isinstance(func, ast.Attribute) and func.attr == "import_module"


def call_import(repo: Repo, roots: list[str], node: ast.Call) -> Import:
    arg = node.args[0] if node.args else None
    if not isinstance(arg, ast.Constant) or not isinstance(arg.value, str) or not arg.value:
        name = node.func.id if isinstance(node.func, ast.Name) else node.func.attr
        return Import(node.lineno, f"{name}() with a computed name", UNRESOLVED, None, COMPUTED)
    if arg.value.startswith("."):
        return Import(node.lineno, arg.value, UNRESOLVED, None, "a relative name read against a package given at run time")
    return module_import(repo, roots, node.lineno, arg.value, arg.value)


def module_file(repo: Repo, parts: list[str]) -> str | None:
    base = "/".join(parts)
    for candidate in (f"{base}.py", f"{base}.pyi", f"{base}/__init__.py", f"{base}/__init__.pyi"):
        if repo.is_file(candidate):
            return candidate
    return f"{base}/" if base and repo.python_dir(base) else None


def find_module(repo: Repo, roots: list[str], parts: list[str]) -> str | None:
    for root in roots:
        hit = module_file(repo, [*root.strip("/").split("/"), *parts] if root else parts)
        if hit:
            return hit
    return None


def module_import(repo: Repo, roots: list[str], line: int, shown: str, dotted: str) -> Import:
    parts = dotted.split(".")
    hit = find_module(repo, roots, parts)
    if hit:
        return Import(line, shown, REPOSITORY, hit)
    if len(parts) > 1 and find_module(repo, roots, parts[:1]):
        return Import(line, shown, UNRESOLVED, None, f"{parts[0]} is in the repository but {dotted} is not")
    if parts[0] in repo.python_names() and parts[0] not in sys.stdlib_module_names:
        where = ", ".join(r or "the repository root" for r in roots)
        return Import(line, shown, UNRESOLVED, None, f"{parts[0]} is a package or module in the repository, but not under {where}")
    return Import(line, shown, EXTERNAL, None)


def from_import(repo: Repo, roots: list[str], rel: str, node: ast.ImportFrom) -> list[Import]:
    module = node.module or ""
    shown = f"from {'.' * node.level}{module} import "
    names = [a.name for a in node.names if a.name != "*"]
    listed = ", ".join(names) or "*"
    if node.level == 0:
        subs = [Import(node.lineno, shown + n, REPOSITORY, hit) for n in names if (hit := find_module(repo, roots, [*module.split("."), n]))]
        return subs if subs and len(subs) == len(names) else subs + [module_import(repo, roots, node.lineno, shown + listed, module)]
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


def tokens(text: str, jsx: bool = False) -> list[Token]:
    return scan(text, jsx)[0]


def scan(text: str, jsx: bool = False) -> tuple[list[Token], str | None]:
    out: list[Token] = []
    try:
        for token in Scanner(text, jsx).run():
            out.append(token)
    except Broken as e:
        return out, str(e)
    except RecursionError:
        return out, "it nests too deep to read"
    return out, None


class Scanner:
    def __init__(self, text: str, jsx: bool):
        self.text = text
        self.jsx = jsx
        self.i = 0
        self.line = 1
        self.prev: Token | None = None
        self.nesting = 0

    def run(self):
        if self.text.startswith("#!"):
            self.skip_line()
        yield from self.code(False)

    def emit(self, kind: str, value: str | None, line: int | None = None) -> Token:
        self.prev = Token(kind, value, self.line if line is None else line)
        return self.prev

    def enter(self) -> None:
        self.nesting += 1
        if self.nesting > MAX_NESTING:
            raise Broken(f"it nests deeper than {MAX_NESTING} levels at line {self.line}")
        self.prev = Token("punct", "{", self.line)

    def skip_line(self) -> None:
        j = self.text.find("\n", self.i)
        self.i = len(self.text) if j < 0 else j

    def block_comment(self) -> None:
        j = self.text.find("*/", self.i + 2)
        if j < 0:
            raise Broken(f"a comment opened at line {self.line} is not closed")
        self.line += self.text.count("\n", self.i, j)
        self.i = j + 2

    def code(self, inner: bool):
        t, depth = self.text, 0
        while self.i < len(t):
            c = t[self.i]
            if c.isspace():
                self.line += c == "\n"
                self.i += 1
            elif t.startswith("//", self.i):
                self.skip_line()
            elif t.startswith("/*", self.i):
                self.block_comment()
            elif c in "'\"":
                yield self.string(c)
            elif c == "`":
                yield from self.template()
            elif c == "/" and self.expression_expected():
                self.regex()
            elif c == "<" and self.jsx and self.expression_expected() and self.jsx_start():
                yield from self.element()
            elif name_char(c):
                yield self.word()
            elif inner and c == "}" and depth == 0:
                self.i += 1
                self.nesting -= 1
                return
            else:
                depth += (c == "{") - (c == "}")
                yield self.punct()
        if inner:
            raise Broken(f"a brace opened before line {self.line} is not closed")

    def expression_expected(self) -> bool:
        p = self.prev
        if p is None:
            return True
        if p.kind == "punct":
            return p.value not in VALUE_END
        return p.kind == "name" and p.value in REGEX_AFTER

    def punct(self) -> Token:
        pair = self.text[self.i:self.i + 2]
        value = pair if pair in ("++", "--") else self.text[self.i]
        self.i += len(value)
        return self.emit("punct", value)

    def word(self) -> Token:
        t, j = self.text, self.i
        while j < len(t) and name_char(t[j]):
            j += 1
        value, self.i = t[self.i:j], j
        return self.emit("num" if value[0].isdigit() else "name", value)

    def string(self, quote: str) -> Token:
        t, j, line, out = self.text, self.i + 1, self.line, []
        while j < len(t) and t[j] != quote:
            if t[j] == "\n":
                raise Broken(f"a string at line {line} is not closed")
            if t[j] == "\\":
                out.append(t[j + 1:j + 2] if t[j + 1:j + 2] in ("\\", "'", '"') else "\0")
                self.line += t[j + 1:j + 2] == "\n"
                j += 2
                continue
            out.append(t[j])
            j += 1
        if j >= len(t):
            raise Broken(f"a string at line {line} is not closed")
        self.i = j + 1
        value = "".join(out)
        return self.emit("string", None if "\0" in value else value, line)

    def template(self):
        t, j, line, out, dynamic = self.text, self.i + 1, self.line, [], False
        while j < len(t):
            if t[j] == "\\":
                out.append("\0")
                self.line += t[j + 1:j + 2] == "\n"
                j += 2
            elif t[j] == "`":
                self.i = j + 1
                if dynamic:
                    self.prev = Token("string", None, line)
                else:
                    yield self.emit("string", None if "\0" in out else "".join(out), line)
                return
            elif t.startswith("${", j):
                self.i = j + 2
                if not dynamic:
                    yield self.emit("string", None, line)
                dynamic = True
                self.enter()
                yield from self.code(True)
                j = self.i
            else:
                self.line += t[j] == "\n"
                out.append(t[j])
                j += 1
        raise Broken(f"a template literal opened at line {line} is not closed")

    def regex(self) -> None:
        t, j, in_class = self.text, self.i + 1, False
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
                self.emit("regex", None)
                return
            j += 1
        raise Broken(f"a regular expression at line {self.line} is not closed")

    def jsx_start(self) -> bool:
        t, j = self.text, self.i + 1
        if t.startswith(">", j):
            return True
        if j >= len(t) or not (t[j].isalpha() or t[j] in "_$"):
            return False
        while j < len(t) and (name_char(t[j]) or t[j] in ".:-"):
            j += 1
        rest = t[j:j + 16].lstrip()
        return not (rest.startswith(",") or rest.startswith("extends "))

    def element(self):
        line = self.line
        self.nesting += 1
        if self.nesting > MAX_NESTING:
            raise Broken(f"JSX nests deeper than {MAX_NESTING} levels at line {line}")
        self.i += 1
        closed = yield from self.tag(line)
        if not closed:
            yield from self.children(line)
        self.nesting -= 1
        self.prev = Token("jsx", None, line)

    def tag(self, line: int):
        t = self.text
        while self.i < len(t):
            c = t[self.i]
            if c in "'\"":
                self.attribute_string(c)
            elif c == "{":
                self.i += 1
                self.enter()
                yield from self.code(True)
            elif t.startswith("/>", self.i):
                self.i += 2
                return True
            elif c == ">":
                self.i += 1
                return False
            elif c.isspace() or name_char(c) or c in ".:-=":
                self.line += c == "\n"
                self.i += 1
            else:
                raise Broken(f"a JSX tag at line {line} cannot be read")
        raise Broken(f"a JSX tag opened at line {line} is not closed")

    def attribute_string(self, quote: str) -> None:
        j = self.text.find(quote, self.i + 1)
        if j < 0:
            raise Broken(f"a JSX attribute at line {self.line} is not closed")
        self.line += self.text.count("\n", self.i, j)
        self.i = j + 1

    def children(self, line: int):
        t = self.text
        while self.i < len(t):
            c = t[self.i]
            if c == "{":
                self.i += 1
                self.enter()
                yield from self.code(True)
            elif t.startswith("</", self.i):
                j = t.find(">", self.i)
                if j < 0:
                    break
                self.line += t.count("\n", self.i, j)
                self.i = j + 1
                return
            elif c == "<":
                yield from self.element()
            else:
                self.line += c == "\n"
                self.i += 1
        raise Broken(f"a JSX element opened at line {line} is not closed")


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
    toks, broken = scan(text, not rel.endswith(TYPESCRIPT_ONLY))
    out, read_specs = [], set()
    for line, spec, how in script_refs(toks):
        if spec is None:
            out.append(Import(line, f"{how} with a computed specifier", UNRESOLVED, None, COMPUTED))
            continue
        read_specs.add(spec)
        resolution, target, why = script_target(repo, rel, spec)
        out.append(Import(line, spec, resolution, target, why))
    if broken:
        out.append(Import(None, rel, UNRESOLVED, None, f"the file cannot be scanned to its end: {broken}"))
    out += [Import(line, spec, UNRESOLVED, script_target(repo, rel, spec)[1], DISAGREE)
            for line, spec in sweep(text) if spec not in read_specs]
    config = script_config(repo, rel)
    out += [Import(None, config["path"], UNRESOLVED, None, note) for note in config["notes"]]
    return out


def sweep(text: str) -> list[tuple[int, str]]:
    out = []
    for m in SWEEP.finditer(text):
        spec = m.group(2) or m.group(4) or m.group(6)
        if "${" not in spec:
            out.append((text.count("\n", 0, m.start()) + 1, spec))
    return out


def script_target(repo: Repo, rel: str, spec: str) -> tuple[str, str | None, str]:
    if spec in (".", "..") or spec.startswith(("./", "../")):
        base = clean(posixpath.join(posixpath.dirname(rel), spec))
        if base is None:
            return UNRESOLVED, None, "the relative specifier goes above the repository"
        hit = script_file(repo, base)
        return (REPOSITORY, hit, "") if hit else (UNRESOLVED, None, "no file in the repository matches the relative specifier")
    if spec.startswith("/"):
        return UNRESOLVED, None, "an absolute path is not read"
    found = aliased(repo, rel, spec)
    if found is not None:
        return found
    return EXTERNAL, "node_modules/" + spec, ""


def clean(path: str) -> str | None:
    base = posixpath.normpath(path) if path else "."
    if base == ".." or base.startswith(("../", "/")):
        return None
    return "" if base == "." else base


def script_file(repo: Repo, base: str) -> str | None:
    if base and repo.is_file(base):
        return base
    stem, ext = posixpath.splitext(base)
    candidates = [base + e for e in EXTENSIONS] + [stem + e for e in COMPILED.get(ext, ())]
    candidates += [posixpath.join(base, "index" + e) for e in EXTENSIONS]
    return next((c for c in candidates if repo.is_file(c)), None)


def aliased(repo: Repo, rel: str, spec: str) -> tuple[str, str | None, str] | None:
    config = script_config(repo, rel)
    for pattern, targets in config["paths"]:
        star = wildcard(pattern, spec)
        if star is None:
            continue
        for target in targets:
            base = clean(posixpath.join(config["paths_base"], target.replace("*", star, 1)))
            hit = script_file(repo, base) if base is not None else None
            if hit:
                return REPOSITORY, hit, ""
        return UNRESOLVED, None, f"the specifier matches the paths pattern {pattern} of {config['path']} but names no file"
    if config["base_url"] is None:
        return None
    base = clean(posixpath.join(config["base_url"], spec))
    hit = script_file(repo, base) if base is not None else None
    return (REPOSITORY, hit, "") if hit else None


def wildcard(pattern: str, spec: str) -> str | None:
    if "*" not in pattern:
        return "" if pattern == spec else None
    head, tail = pattern.split("*", 1)
    if spec.startswith(head) and spec.endswith(tail) and len(spec) >= len(head) + len(tail):
        return spec[len(head):len(spec) - len(tail)]
    return None


def script_config(repo: Repo, rel: str) -> dict:
    here = posixpath.dirname(rel)
    if here not in repo.configs:
        repo.configs[here] = nearest_config(repo, here)
    return repo.configs[here]


def nearest_config(repo: Repo, here: str) -> dict:
    while True:
        for name in CONFIGS:
            path = posixpath.join(here, name) if here else name
            if repo.is_file(path):
                return effective_config(repo, path)
        if not here:
            return {"path": None, "paths": [], "paths_base": "", "base_url": None, "notes": []}
        here = posixpath.dirname(here)


def effective_config(repo: Repo, path: str) -> dict:
    notes: list[str] = []
    options = config_options(repo, path, 0, frozenset(), notes)
    base_url = options.get("base_url")
    paths = sorted(options.get("paths", {}).items(), key=lambda kv: -len(kv[0].split("*", 1)[0]))
    paths_base = base_url if base_url is not None else options.get("paths_dir", "")
    return {"path": path, "paths": paths, "paths_base": paths_base, "base_url": base_url, "notes": notes}


def config_options(repo: Repo, path: str, depth: int, seen: frozenset, notes: list[str]) -> dict:
    if depth > MAX_EXTENDS:
        notes.append(f"{path} is more than {MAX_EXTENDS} extends deep; its paths are not applied")
        return {}
    if path in seen:
        notes.append(f"{path} extends itself in a cycle")
        return {}
    data = read_json(repo, path)
    if not isinstance(data, dict):
        notes.append(f"{path} cannot be read as JSON; its paths are not applied")
        return {}
    merged: dict = {}
    extends = data.get("extends")
    for parent in extends if isinstance(extends, list) else [extends] if extends is not None else []:
        target = extended(repo, path, parent)
        if target is None:
            notes.append(f"{path} extends {parent!r}, which is not a file in the repository; its paths are not applied")
            continue
        merged.update(config_options(repo, target, depth + 1, seen | {path}, notes))
    return {**merged, **own_options(path, data.get("compilerOptions"))}


def own_options(path: str, options) -> dict:
    if not isinstance(options, dict):
        return {}
    here, out = posixpath.dirname(path), {}
    if isinstance(options.get("baseUrl"), str):
        base = clean(posixpath.join(here, options["baseUrl"]))
        if base is not None:
            out["base_url"] = base
    if isinstance(options.get("paths"), dict):
        out["paths"] = {k: [t for t in v if isinstance(t, str)] for k, v in options["paths"].items() if isinstance(k, str) and isinstance(v, list)}
        out["paths_dir"] = here
    return out


def extended(repo: Repo, path: str, parent) -> str | None:
    if not isinstance(parent, str) or not parent.startswith(("./", "../")):
        return None
    base = clean(posixpath.join(posixpath.dirname(path), parent))
    if base is None:
        return None
    return next((c for c in (base, base + ".json") if repo.is_file(c)), None)


def read_json(repo: Repo, path: str):
    try:
        full = repo.root / path
        if full.stat().st_size > MAX_BYTES:
            return None
        return json.loads(plain_json(full.read_text(encoding="utf-8")))
    except (OSError, UnicodeDecodeError, ValueError):
        return None


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
