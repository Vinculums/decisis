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
package, given the target `node_modules/<specifier>`, unless it names a package of an npm, pnpm, Yarn or Bun workspace
of the repository (`workspaces.py`): it then resolves to that package's files through `exports`, `main` and the other
entry fields, and a `workspace:` link of the nearest `package.json` can give the package another name.

Go files are read with a scanner that skips comments, strings and runes. Single and grouped `import`
declarations are listed, with an alias, dot or blank name. A path equal to or under the `module` path of the
nearest `go.mod` names the package directory below it, given with a trailing `/`; the directory and each
`.go` file directly in it are the paths a `to` glob is matched against. Any other path is external; with no
`go.mod`, a path whose first element has a `.` is unresolved.

Rust files are read with a scanner that skips comments (block comments nest), strings, raw, byte and C
strings, and character literals, and tells lifetimes apart. `use` trees are expanded into one path each,
and `mod x;` and `extern crate x;` are listed. The nearest `Cargo.toml` with a `[package]` gives the crate
root, and the crate's modules are the tree of `mod` declarations from it (with `#[path]`, `cfg_attr` paths
and inline modules). Each name of a path is looked up in the module reached so far as a child module, an
item it declares, a name it binds with `use` or `extern crate` (followed to what it binds) or a name a glob
`use` brings in; an item ends the path at its file, and a name found none of those ways is unresolved. A
first name that is none of those is a crate of the repository (by its `Cargo.toml` name, a `path`, a
`package` rename or a workspace dependency) or external. A module file `a/b.rs` is also matched as its
directory `a/b/`.

Java and Kotlin files are read by `jvm.py`: `import a.b.C`, `import a.b.*`, `import static a.b.C.m` and Kotlin
`import a.b.C as D` resolve to the source file of the class, or the package directory for a wildcard, by the
`package` line of each source file and by its path under the source roots; a class of no source file is external,
and one that a package of the repository could hold is unresolved.

A plain text search for the same import forms runs over every JavaScript, TypeScript, Go, Rust, Java and Kotlin file as
well. A specifier it finds that the scanner did not read as code is listed as unresolved, with the file it
would name, so a scanner mistake can never make an import disappear; a Go, Rust, Java or Kotlin hit that would be external
is left out, since it could not be a violation.

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
import tomllib
from dataclasses import dataclass, field, replace
from pathlib import Path

PYTHON = (".py", ".pyi")
SCRIPT = (".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts")
TYPESCRIPT_ONLY = (".ts", ".mts", ".cts")
JVM = (".java", ".kt", ".kts")
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
    also: tuple[str, ...] = ()


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
        self.go_mods: dict[str, tuple[str, str | None, str] | None] = {}
        self.manifests: dict[str, dict | None] = {}
        self.cargo_dirs: dict[str, str | None] = {}
        self.crates: dict[str, str] | None = None
        self.rust_infos: dict[str, dict | str] = {}
        self.rust_ctx: dict[tuple[str, str | None], dict] = {}
        self.rust_found: dict[tuple, tuple[str, object]] = {}
        self.rust_explored: set[tuple] = set()
        self.rust_cuts = 0
        self.rust_local: dict[tuple, tuple[str, object]] = {}
        self.workspaces = None
        self.jvm = None

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
    if rel.endswith(".go"):
        return "go"
    if rel.endswith(".rs"):
        return "rust"
    if rel.endswith(JVM):
        return "jvm"
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
    if lang == "python":
        found = python_imports(repo, rel, data)
    else:
        found = READERS[lang](repo, rel, data.decode("utf-8", "replace").removeprefix("\ufeff"))
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
        resolution, target, why, also = script_target(repo, rel, spec)
        out.append(Import(line, spec, resolution, target, why, also))
    if broken:
        out.append(Import(None, rel, UNRESOLVED, None, f"the file cannot be scanned to its end: {broken}"))
    for line, spec in sweep(text):
        if spec not in read_specs:
            _, target, _, also = script_target(repo, rel, spec)
            out.append(Import(line, spec, UNRESOLVED, target, DISAGREE, also))
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


def script_target(repo: Repo, rel: str, spec: str) -> tuple[str, str | None, str, tuple[str, ...]]:
    if spec in (".", "..") or spec.startswith(("./", "../")):
        base = clean(posixpath.join(posixpath.dirname(rel), spec))
        if base is None:
            return UNRESOLVED, None, "the relative specifier goes above the repository", ()
        hit = script_file(repo, base)
        return (REPOSITORY, hit, "", ()) if hit else (UNRESOLVED, None, "no file in the repository matches the relative specifier", ())
    if spec.startswith("/"):
        return UNRESOLVED, None, "an absolute path is not read", ()
    found = aliased(repo, rel, spec)
    if found is not None:
        return (*found, ())
    workspace = workspaces.resolve(repo, rel, spec)
    if workspace is not None:
        return workspace
    return EXTERNAL, "node_modules/" + spec, "", ()


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
        return json.loads(plain_json(full.read_text(encoding="utf-8").removeprefix("\ufeff")))
    except (OSError, UnicodeDecodeError, ValueError, RecursionError):
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


GO_SWEEP = re.compile(r"""\bimport\s*(?:[A-Za-z_]\w*\s+|[._]\s*)?(["`])([^"`\n]+?)\1""")
GO_BLOCK = re.compile(r"\bimport\s*\(([^)]*)\)")
GO_ITEM = re.compile(r"""(?:^|[\n;(])[ \t]*(?:[A-Za-z_]\w*[ \t]+|[._][ \t]*)?(["`])([^"`\n]+?)\1""")
GO_MODULE_BLOCK = re.compile(r"""^\s*module\s*\(\s*(?:"([^"\n]*)"|`([^`\n]*)`|([^\s"`()]+))\s*\)""", re.M)
GO_MODULE = re.compile(r"""^\s*module\s+(?:"([^"\n]*)"|`([^`\n]*)`|(\S+))""", re.M)
GO_PATH = re.compile(r"[A-Za-z0-9._~+\-]+(?:/[A-Za-z0-9._~+\-]+)*")
RUST_PREFIX = re.compile(r"""(?:b|c)?r(#*)"|(?:b|c)?"|b'""")
RUST_KINDS = ("tests", "examples", "benches")
RUST_TARGETS = {"src/bin": ("bin", "autobins"), "tests": ("test", "autotests"), "examples": ("example", "autoexamples"),
                "benches": ("bench", "autobenches")}
USE_START = ("::", "{", "*")
RUST_DEPENDENCIES = ("dependencies", "dev-dependencies", "build-dependencies")
RUST_SKIPPED_DIRS = SKIPPED_DIRS | {"target"}
MAX_SNIPPET = 4096
MAX_HOPS = 64
MAX_MODULES = 5000
ITEMS = ("fn", "struct", "enum", "trait", "type", "const", "static", "union")
NOT_CONST = ("fn", "unsafe", "async", "extern", "_")
EXTERN_PRELUDE = ("std", "core", "alloc")


def is_punct(tok: Token | None, value: str) -> bool:
    return tok is not None and tok.kind == "punct" and tok.value == value


def at(toks: list[Token], i: int) -> Token | None:
    return toks[i] if 0 <= i < len(toks) else None


def read_small(repo: Repo, rel: str) -> str | None:
    try:
        path = repo.root / rel
        if path.stat().st_size > MAX_BYTES:
            return None
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def lexed(lex, text: str) -> tuple[list[Token], str | None]:
    out: list[Token] = []
    try:
        lex(text, out)
    except Broken as e:
        return out, str(e)
    return out, None


def go_lex(text: str, out: list[Token]) -> None:
    i, line, n = 0, 1, len(text)
    while i < n:
        c = text[i]
        if c == "\n":
            line += 1
            i += 1
        elif c.isspace():
            i += 1
        elif text.startswith("//", i):
            j = text.find("\n", i)
            i = n if j < 0 else j
        elif text.startswith("/*", i):
            j = text.find("*/", i + 2)
            if j < 0:
                raise Broken(f"a comment opened at line {line} is not closed")
            line += text.count("\n", i, j)
            i = j + 2
        elif c == "`":
            j = text.find("`", i + 1)
            if j < 0:
                raise Broken(f"a raw string at line {line} is not closed")
            out.append(Token("string", text[i + 1:j].replace("\r", ""), line))
            line += text.count("\n", i, j)
            i = j + 1
        elif c in "\"'":
            i = go_quoted(text, i, line, out)
        elif name_char(c):
            j = i
            while j < n and name_char(text[j]):
                j += 1
            out.append(Token("num" if c.isdigit() else "name", text[i:j], line))
            i = j
        else:
            out.append(Token("punct", c, line))
            i += 1


def go_quoted(text: str, i: int, line: int, out: list[Token]) -> int:
    quote, j, escaped = text[i], i + 1, False
    what = "string" if quote == '"' else "rune literal"
    while j < len(text) and text[j] != quote:
        if text[j] == "\n" or text[j:j + 2] == "\\\n":
            raise Broken(f"a {what} at line {line} is not closed")
        escaped = escaped or text[j] == "\\"
        j += 2 if text[j] == "\\" else 1
    if j >= len(text):
        raise Broken(f"a {what} at line {line} is not closed")
    out.append(Token("string" if quote == '"' else "rune", None if escaped else text[i + 1:j], line))
    return j + 1


def go_spec(toks: list[Token], i: int) -> tuple[list[tuple[int, str | None, str]], int]:
    tok = toks[i]
    if is_punct(tok, ";"):
        return [], i + 1
    nxt = at(toks, i + 1)
    if (tok.kind == "name" or is_punct(tok, ".")) and nxt is not None and nxt.kind == "string":
        tok, i = nxt, i + 1
    if tok.kind != "string":
        return [(tok.line, None, "the import declaration cannot be read")], i + 1
    if tok.value is None:
        return [(tok.line, None, "the import path has an escape sequence, which is not read")], i + 1
    return [(tok.line, tok.value, "")], i + 1


def go_refs(toks: list[Token]) -> list[tuple[int, str | None, str]]:
    out, i = [], 0
    while i < len(toks):
        tok = toks[i]
        i += 1
        if tok.kind != "name" or tok.value != "import" or i >= len(toks):
            continue
        if not is_punct(toks[i], "("):
            found, i = go_spec(toks, i)
            out += found
            continue
        i += 1
        while i < len(toks) and not is_punct(toks[i], ")"):
            found, i = go_spec(toks, i)
            out += found
        i += 1
    return out


def go_sweep(text: str) -> list[tuple[int, str]]:
    found = [(m.start(2), m.group(2)) for m in GO_SWEEP.finditer(text)]
    for block in GO_BLOCK.finditer(text):
        found += [(block.start(1) + m.start(2), m.group(2)) for m in GO_ITEM.finditer(block.group(1))]
    return sorted({(text.count("\n", 0, at_) + 1, spec) for at_, spec in found})


def go_module(repo: Repo, here: str) -> tuple[str, str | None, str] | None:
    if here not in repo.go_mods:
        path = posixpath.join(here, "go.mod") if here else "go.mod"
        if repo.is_file(path):
            repo.go_mods[here] = (here, go_module_path(read_small(repo, path) or ""), path)
        else:
            repo.go_mods[here] = go_module(repo, posixpath.dirname(here)) if here else None
    return repo.go_mods[here]


def go_mod_line(raw: str) -> str:
    quote = None
    for k, c in enumerate(raw):
        if quote:
            if c == quote and (quote == "`" or raw[k - 1] != "\\"):
                quote = None
        elif c in "\"`":
            quote = c
        elif raw.startswith("//", k):
            return raw[:k]
    return raw


def go_module_path(text: str) -> str | None:
    lines = "\n".join(go_mod_line(raw) for raw in text.splitlines())
    m = GO_MODULE_BLOCK.search(lines) or GO_MODULE.search(lines)
    value = next((g for g in m.groups() if g is not None), None) if m else None
    if value is None or not GO_PATH.fullmatch(value) or any(part in (".", "..") for part in value.split("/")):
        return None
    return value


def go_files(repo: Repo, d: str) -> tuple[str, ...]:
    try:
        names = sorted(e.name for e in os.scandir(repo.root / d) if e.name.endswith(".go"))
    except OSError:
        return ()
    return tuple(p for p in (posixpath.join(d, n) if d else n for n in names) if repo.is_file(p))


def go_target(repo: Repo, rel: str, spec: str) -> tuple[str, str | None, str, tuple[str, ...]]:
    mod = go_module(repo, posixpath.dirname(rel))
    if mod is None:
        if "." in spec.split("/")[0]:
            return UNRESOLVED, None, "no go.mod lies above the file, so it is not known whether the import is in the repository", ()
        return EXTERNAL, None, "", ()
    root, module, gomod = mod
    if module is None:
        return UNRESOLVED, None, f"{gomod} has no module line that can be read", ()
    if spec != module and not spec.startswith(module + "/"):
        return EXTERNAL, None, "", ()
    sub = spec[len(module) + 1:]
    if sub and any(part in ("", ".", "..") for part in sub.split("/")):
        return UNRESOLVED, None, f"the import path is not a clean path under the module path {module}", ()
    d = "/".join(p for p in (root, sub) if p)
    kind = repo.kind(d) if d else "dir"
    if kind == "outside":
        return UNRESOLVED, None, f"{d} leads outside the repository", ()
    if kind != "dir":
        return UNRESOLVED, None, f"the import is under the module path {module} of {gomod}, but {d} is not a directory in the repository", ()
    return REPOSITORY, d + "/" if d else ".", "", ((d,) if d else ()) + go_files(repo, d)


def go_imports(repo: Repo, rel: str, text: str) -> list[Import]:
    toks, broken = lexed(go_lex, text)
    out, read_specs = [], set()
    for line, spec, problem in go_refs(toks):
        if spec is None:
            out.append(Import(line, "import with a path that cannot be read", UNRESOLVED, None, problem))
            continue
        read_specs.add(spec)
        resolution, target, why, also = go_target(repo, rel, spec)
        out.append(Import(line, spec, resolution, target, why, also))
    if broken:
        out.append(Import(None, rel, UNRESOLVED, None, f"the file cannot be scanned to its end: {broken}"))
    for line, spec in go_sweep(text):
        if spec in read_specs:
            continue
        resolution, target, _, also = go_target(repo, rel, spec)
        if resolution != EXTERNAL:
            out.append(Import(line, spec, UNRESOLVED, target, DISAGREE, also))
    return out


def rust_lex(text: str, out: list[Token]) -> None:
    i, line, n = 0, 1, len(text)
    if text.startswith("#!") and not text[2:].lstrip().startswith("["):
        i = n if text.find("\n") < 0 else text.find("\n")
    while i < n:
        c = text[i]
        m = RUST_PREFIX.match(text, i) if c in "\"brc" else None
        if c == "\n":
            line += 1
            i += 1
        elif c.isspace():
            i += 1
        elif text.startswith("//", i):
            j = text.find("\n", i)
            i = n if j < 0 else j
        elif text.startswith("/*", i):
            j = rust_comment(text, i, line)
            line += text.count("\n", i, j)
            i = j
        elif m and m.group(0) == "b'":
            i = rust_char(text, i + 1, line)
        elif m:
            j = rust_string(text, m, line, out)
            line += text.count("\n", i, j)
            i = j
        elif c == "'":
            i = rust_char(text, i, line)
        elif name_char(c):
            j = i + 2 if text.startswith("r#", i) else i
            while j < n and name_char(text[j]):
                j += 1
            out.append(Token("num" if c.isdigit() else "name", text[i:j], line))
            i = j
        elif text.startswith("::", i):
            out.append(Token("punct", "::", line))
            i += 2
        else:
            out.append(Token("punct", c, line))
            i += 1


def rust_comment(text: str, i: int, line: int) -> int:
    depth, j = 1, i + 2
    while depth:
        opened, closed = text.find("/*", j), text.find("*/", j)
        if closed < 0:
            raise Broken(f"a comment opened at line {line} is not closed")
        if 0 <= opened < closed:
            depth, j = depth + 1, opened + 2
        else:
            depth, j = depth - 1, closed + 2
    return j


def rust_string(text: str, m: re.Match, line: int, out: list[Token]) -> int:
    start, hashes = m.end(), m.group(1)
    if hashes is not None:
        close = '"' + hashes
        j = text.find(close, start)
        if j < 0:
            raise Broken(f"a raw string at line {line} is not closed")
        out.append(Token("string", text[start:j], line))
        return j + len(close)
    j, escaped = start, False
    while j < len(text) and text[j] != '"':
        escaped = escaped or text[j] == "\\"
        j += 2 if text[j] == "\\" else 1
    if j >= len(text):
        raise Broken(f"a string at line {line} is not closed")
    out.append(Token("string", None if escaped else text[start:j], line))
    return j + 1


def rust_char(text: str, i: int, line: int) -> int:
    if text.startswith("\\", i + 1):
        j = i + 3
        while j < len(text) and text[j] not in "'\n":
            j += 1
        if j >= len(text) or text[j] != "'":
            raise Broken(f"a character literal at line {line} is not closed")
        return j + 1
    if i + 2 < len(text) and text[i + 2] == "'" and text[i + 1] != "\n":
        return i + 3
    return i + 1


class Unreadable(Exception):
    pass


@dataclass(frozen=True)
class RustRef:
    line: int
    kind: str
    path: tuple[str, ...]
    inline: tuple[str, ...]
    frames: tuple[int, ...] = ()
    attrs: tuple[tuple[str, str | None], ...] = ()
    bind: str | None = None
    glob: bool = False
    id: int = 0


def use_tree(toks: list[Token], j: int, prefix: list[str]) -> tuple[list[tuple[list[str], str | None, bool]], int]:
    seg = list(prefix)
    if is_punct(at(toks, j), "::"):
        seg = seg or ["::"]
        j += 1
    while True:
        tok = at(toks, j)
        if tok is not None and tok.kind == "name" and tok.value.startswith("$") and tok.value != "$crate":
            raise Unreadable
        if tok is not None and tok.kind == "name":
            name = tok.value.removeprefix("r#").removeprefix("$")
            if not (name == "self" and seg):
                seg.append(name)
            j += 1
        elif is_punct(tok, "*"):
            return [(seg, None, True)], j + 1
        elif is_punct(tok, "{"):
            j, paths = j + 1, []
            while not is_punct(at(toks, j), "}"):
                sub, j = use_tree(toks, j, seg)
                paths += sub
                if is_punct(at(toks, j), ","):
                    j += 1
                elif not is_punct(at(toks, j), "}"):
                    raise Unreadable
            return paths or [(seg, None, False)], j + 1
        else:
            raise Unreadable
        if is_punct(at(toks, j), "::"):
            j += 1
            continue
        bind = seg[-1] if seg and seg[-1] not in ("crate", "self", "super", "::") else None
        if getattr(at(toks, j), "value", None) == "as":
            alias = getattr(at(toks, j + 1), "value", None)
            bind = None if alias in (None, "_") else alias.removeprefix("r#")
            j += 2
        return [(seg, bind, False)], j


def use_decl(toks: list[Token], j: int) -> tuple[list[tuple[tuple[str, ...], str | None, bool]] | None, int]:
    try:
        paths, j = use_tree(toks, j, [])
    except (Unreadable, RecursionError):
        return None, j
    if not is_punct(at(toks, j), ";"):
        return None, j
    found = [(tuple(p), bind, glob) for p, bind, glob in paths if p]
    return (found, j + 1) if found else (None, j)


def attr_path(inner: list[Token]) -> tuple[str, str | None] | None:
    if len(inner) == 3 and inner[0].value == "path" and is_punct(inner[1], "=") and inner[2].kind == "string":
        return "path", inner[2].value
    if inner and inner[0].value == "cfg_attr":
        for k in range(1, len(inner) - 2):
            if inner[k].value == "path" and is_punct(inner[k - 1], ",") and is_punct(inner[k + 1], "=") and inner[k + 2].kind == "string":
                return "cfg", inner[k + 2].value
    return None


def mod_attrs(toks: list[Token], i: int) -> tuple[tuple[str, str | None], ...]:
    k, found = i - 1, []
    while k >= 0 and toks[k].value in ("pub", "(", ")", "crate", "super", "self", "in", "::"):
        k -= 1
    while is_punct(at(toks, k), "]"):
        depth, j = 0, k
        while j >= 0:
            depth += is_punct(toks[j], "]") - is_punct(toks[j], "[")
            if depth == 0:
                break
            j -= 1
        attr = attr_path(toks[j + 1:k])
        if attr is not None:
            found.append(attr)
        k = j - 2
    return tuple(reversed(found))


def new_scope() -> dict:
    return {"mods": {}, "items": set(), "binds": [], "globs": []}


def rust_parse(toks: list[Token]) -> dict:
    refs, scopes = [], {(): new_scope()}
    stack, depth, pending, i, frame = [], 0, None, 0, 0
    inline, frames, scope = (), (), scopes[()]
    while i < len(toks):
        tok, nxt, after = toks[i], at(toks, i + 1), at(toks, i + 2)
        word = tok.value if tok.kind == "name" else None
        if is_punct(tok, "{") or is_punct(tok, "}"):
            if tok.value == "{":
                depth += 1
                if pending is not None:
                    stack.append(("mod", pending, depth))
                    pending = None
                elif is_punct(at(toks, i - 1), "!") or (stack and stack[-1][0] == "macro"):
                    stack.append(("macro", 0, depth))
                else:
                    frame += 1
                    stack.append(("other", frame, depth))
            else:
                if stack and stack[-1][2] == depth:
                    stack.pop()
                depth -= 1
            inline = tuple(e[1] for e in stack if e[0] == "mod")
            last = max((n for n, e in enumerate(stack) if e[0] == "mod"), default=-1)
            frames = tuple(e[1] for e in stack[last + 1:] if e[0] == "other")
            if inline not in scopes:
                scopes[inline] = new_scope()
            scope = scopes[inline]
        elif word == "use" and nxt is not None and (nxt.kind == "name" or nxt.value in USE_START):
            paths, j = use_decl(toks, i + 1)
            if paths is None:
                refs.append(RustRef(tok.line, "bad", ("use",), inline, frames, id=len(refs)))
            else:
                for path, bind, glob in paths:
                    ref = RustRef(tok.line, "use", path, inline, frames, bind=bind, glob=glob, id=len(refs))
                    refs.append(ref)
                    if glob or bind:
                        scope["globs" if glob else "binds"].append(ref)
                i = j
                continue
        elif word == "mod" and nxt is not None and nxt.kind == "name":
            name = nxt.value.removeprefix("r#")
            if is_punct(after, ";") and name.startswith("$"):
                refs.append(RustRef(tok.line, "bad", ("mod",), inline, frames, id=len(refs)))
            elif is_punct(after, ";"):
                ref = RustRef(tok.line, "mod", (name,), inline, frames, mod_attrs(toks, i), id=len(refs))
                refs.append(ref)
                if not frames:
                    scope["mods"].setdefault(name, []).append(ref)
            elif is_punct(after, "{"):
                pending = name
                if not frames:
                    scope["mods"].setdefault(name, []).append("inline")
            i += 2
            continue
        elif word == "extern" and getattr(nxt, "value", None) == "crate" and after is not None and after.kind == "name":
            name = after.value.removeprefix("r#")
            alias = toks[i + 4].value if getattr(at(toks, i + 3), "value", None) == "as" and at(toks, i + 4) is not None else None
            bind = name if alias is None else None if alias == "_" else alias
            ref = RustRef(tok.line, "extern", ("::", name), inline, frames, bind=bind, id=len(refs))
            refs.append(ref)
            if bind and name != "self":
                scope["binds"].append(ref)
            i += 5 if alias is not None else 3
            continue
        elif not frames and word in ITEMS and nxt is not None and nxt.kind == "name":
            name = after.value if word == "static" and nxt.value == "mut" and after is not None else nxt.value
            if not (word == "const" and name in NOT_CONST):
                scope["items"].add(name.removeprefix("r#"))
        elif not frames and word == "macro_rules" and is_punct(nxt, "!") and after is not None and after.kind == "name":
            scope["items"].add(after.value.removeprefix("r#"))
        i += 1
    return {"refs": refs, "scopes": scopes}


def rust_shown(ref: RustRef) -> str:
    if ref.kind == "bad":
        return f"{ref.path[0]} declaration that cannot be read"
    if ref.kind == "mod":
        return f"mod {ref.path[0]}"
    if ref.kind == "extern":
        return f"extern crate {ref.path[1]}"
    if ref.path[0] == "::":
        return "use ::" + "::".join(ref.path[1:])
    return "use " + "::".join(ref.path)


def cargo_dir(repo: Repo, here: str) -> str | None:
    if here not in repo.cargo_dirs:
        path = posixpath.join(here, "Cargo.toml") if here else "Cargo.toml"
        if repo.is_file(path):
            repo.cargo_dirs[here] = here
        else:
            repo.cargo_dirs[here] = cargo_dir(repo, posixpath.dirname(here)) if here else None
    return repo.cargo_dirs[here]


def cargo_manifest(repo: Repo, cargo: str) -> dict | None:
    if cargo not in repo.manifests:
        repo.manifests[cargo] = read_manifest(repo, cargo)
    return repo.manifests[cargo]


def read_manifest(repo: Repo, cargo: str) -> dict | None:
    text = read_small(repo, posixpath.join(cargo, "Cargo.toml") if cargo else "Cargo.toml")
    try:
        data = tomllib.loads(text) if text is not None else None
    except tomllib.TOMLDecodeError:
        return None
    if not isinstance(data, dict):
        return None
    package, lib = data.get("package"), data.get("lib")
    package = package if isinstance(package, dict) else None
    lib = lib if isinstance(lib, dict) else {}
    deps = []
    tables = [data.get(t) for t in RUST_DEPENDENCIES]
    targets = data.get("target")
    for target in targets.values() if isinstance(targets, dict) else ():
        tables += [target.get(t) for t in RUST_DEPENDENCIES] if isinstance(target, dict) else []
    for entries in tables:
        for key, value in (entries.items() if isinstance(entries, dict) else ()):
            if isinstance(value, dict):
                deps.append((key.replace("-", "_"), *dependency(cargo, value), value.get("workspace") is True))
    workspace, inherited = data.get("workspace"), None
    if isinstance(workspace, dict):
        entries = workspace.get("dependencies")
        inherited = {key.replace("-", "_"): dependency(cargo, value) for key, value in (entries.items() if isinstance(entries, dict) else ())
                     if isinstance(value, dict)}
    roots, auto = set(), {}
    for kind, (table, flag) in RUST_TARGETS.items():
        auto[kind] = (package or {}).get(flag) is not False
        targets = data.get(table)
        for target in targets if isinstance(targets, list) else ():
            path = clean(posixpath.join(cargo, target["path"])) if isinstance(target, dict) and isinstance(target.get("path"), str) else None
            if path is not None:
                roots.add(path)
    return {"package": package is not None, "name": text_value((package or {}).get("name")),
            "lib_name": text_value(lib.get("name")), "lib_path": text_value(lib.get("path")), "deps": deps,
            "roots": roots, "auto": auto, "workspace": inherited}


def dependency(cargo: str, value: dict) -> tuple[str | None, str | None]:
    path = clean(joined(cargo, value["path"])) if isinstance(value.get("path"), str) else None
    package = value["package"].replace("-", "_") if isinstance(value.get("package"), str) else None
    return path, package


def text_value(value) -> str | None:
    return value if isinstance(value, str) and value else None


def lib_file(repo: Repo, cargo: str, manifest: dict) -> str | None:
    path = clean(posixpath.join(cargo, manifest["lib_path"] or "src/lib.rs"))
    return path if path is not None and repo.is_file(path) else None


def repo_crates(repo: Repo) -> dict[str, str]:
    if repo.crates is None:
        found: dict[str, str] = {}
        seen = 0
        for dirpath, dirnames, filenames in os.walk(repo.root):
            dirnames[:] = sorted(d for d in dirnames if not d.startswith(".") and d not in RUST_SKIPPED_DIRS)
            if "Cargo.toml" in filenames:
                rel = Path(dirpath).relative_to(repo.root).as_posix()
                manifest = cargo_manifest(repo, "" if rel == "." else rel)
                for name in (manifest["name"], manifest["lib_name"]) if manifest else ():
                    if name:
                        found.setdefault(name.replace("-", "_"), "" if rel == "." else rel)
            seen += len(filenames)
            if seen > MAX_WALK:
                break
        repo.crates = found
    return repo.crates


def declared_root(manifest: dict, rel: str, top: str) -> tuple[str, str] | None:
    here = posixpath.dirname(rel)
    while here == top or here.startswith(top + "/") or not top:
        found = sorted(r for r in manifest["roots"] if posixpath.dirname(r) == here)
        if found:
            return here, found[0]
        if here == top or not here:
            return None
        here = posixpath.dirname(here)
    return None


def target_root(repo: Repo, manifest: dict, kind: str, d: str, rest: list[str], rel: str) -> tuple[str, str | None]:
    if manifest["auto"][kind]:
        if len(rest) == 1:
            return d, rel
        main = f"{d}/{rest[0]}/main.rs"
        if repo.is_file(main):
            return f"{d}/{rest[0]}", main
    return declared_root(manifest, rel, d) or (d, None)


def crate_root(repo: Repo, cargo: str, manifest: dict, rel: str) -> tuple[str, str | None]:
    lib = lib_file(repo, cargo, manifest)
    parts = (rel[len(cargo) + 1:] if cargo else rel).split("/")
    base = lambda *p: "/".join(x for x in (cargo, *p) if x)
    if rel == lib or rel in manifest["roots"]:
        return posixpath.dirname(rel), rel
    if parts[0] == "src" and len(parts) == 2 and parts[1] in ("main.rs", "lib.rs"):
        return base("src"), rel
    if parts[0] == "src" and len(parts) > 2 and parts[1] == "bin":
        return target_root(repo, manifest, "src/bin", base("src", "bin"), parts[2:], rel)
    if parts[0] in RUST_KINDS and len(parts) > 1:
        return target_root(repo, manifest, parts[0], base(parts[0]), parts[1:], rel)
    if lib and (not posixpath.dirname(lib) or rel.startswith(posixpath.dirname(lib) + "/")):
        return posixpath.dirname(lib), lib
    if parts[0] == "src" and len(parts) > 1:
        main = base("src", "main.rs")
        return base("src"), main if repo.is_file(main) else None
    return declared_root(manifest, rel, cargo) or (posixpath.dirname(rel), rel)


def module_of(d: str, root: str | None, rel: str) -> list[str]:
    if rel == root:
        return []
    parts = (rel[len(d) + 1:] if d else rel)[:-3].split("/")
    return parts[:-1] if parts[-1] == "mod" else parts


def rust_place(repo: Repo, rel: str) -> dict | str:
    cargo = cargo_dir(repo, posixpath.dirname(rel))
    if cargo is None:
        return "no Cargo.toml lies above the file, so its crate root is not known"
    manifest = cargo_manifest(repo, cargo)
    where = posixpath.join(cargo, "Cargo.toml") if cargo else "Cargo.toml"
    if manifest is None:
        return f"{where} cannot be read as TOML, so the crate root of the file is not known"
    if not manifest["package"]:
        return f"{where} has no [package], so the crate root of the file is not known"
    d, root = crate_root(repo, cargo, manifest, rel)
    return {"cargo": cargo, "dir": d, "root": root, "module": module_of(d, root, rel), "manifest": manifest}


def workspace_deps(repo: Repo, cargo: str) -> dict:
    here = cargo
    while True:
        manifest = cargo_manifest(repo, here) if repo.is_file(joined(here, "Cargo.toml")) else None
        if manifest is not None and manifest["workspace"] is not None:
            return manifest["workspace"]
        if not here:
            return {}
        here = posixpath.dirname(here)


def rust_crates(repo: Repo, cargo: str | None, manifest: dict | None) -> dict[str, str]:
    known = repo_crates(repo)
    crates = dict(known)
    inherited = workspace_deps(repo, cargo) if manifest is not None and cargo is not None else {}
    for name, path, package, workspace in manifest["deps"] if manifest else ():
        if workspace and name in inherited:
            path, package = path or inherited[name][0], package or inherited[name][1]
        if path is not None and repo.is_file(joined(path, "Cargo.toml")):
            crates[name] = path
        elif package is not None and package in known:
            crates[name] = known[package]
    return crates


@dataclass(frozen=True)
class Mod:
    file: str
    inline: tuple[str, ...]
    dir: str
    also: tuple[str, ...] = ()
    parent: Mod | None = field(default=None, compare=False, hash=False)


def joined(*parts: str) -> str:
    return "/".join(p for p in parts if p)


def where_in(m: Mod) -> str:
    return m.file + (f" (inline module {'::'.join(m.inline)})" if m.inline else "")


def rust_info(repo: Repo, rel: str) -> dict | str:
    if rel not in repo.rust_infos:
        kind = repo.kind(rel)
        text = read_small(repo, rel) if kind == "file" else None
        if kind == "outside":
            repo.rust_infos[rel] = f"{rel} leads outside the repository"
        elif text is None:
            repo.rust_infos[rel] = f"{rel} cannot be read"
        else:
            toks, broken = lexed(rust_lex, text)
            repo.rust_infos[rel] = {**rust_parse(toks), "broken": broken}
    return repo.rust_infos[rel]


def scope_of(repo: Repo, m: Mod) -> dict | str:
    info = rust_info(repo, m.file)
    return info if isinstance(info, str) else info["scopes"].get(m.inline, new_scope())


def mod_files(repo: Repo, m: Mod, ref: RustRef) -> list[Mod] | str:
    name = ref.path[0]
    plain = [v for k, v in ref.attrs if k == "path"][-1:]
    cfgs = [v for k, v in ref.attrs if k == "cfg"]
    if None in plain + cfgs:
        return f"a path attribute of mod {name} has an escape sequence, which is not read"
    base = m.dir if m.inline else posixpath.dirname(m.file)
    found, tried = [], []
    for value in plain + cfgs:
        path = clean(joined(base, value))
        if path is None:
            return f"a path attribute of mod {name} goes above the repository"
        tried.append(path)
        kind = repo.kind(path)
        if kind == "outside":
            return f"mod {name} names {path}, which leads outside the repository"
        if kind == "file":
            found.append(Mod(path, (), posixpath.dirname(path), (), m))
    if not plain:
        d = joined(m.dir, name)
        for path, also in ((d + ".rs", (d + "/",)), (d + "/mod.rs", ())):
            tried.append(path)
            kind = repo.kind(path)
            if kind == "outside":
                return f"mod {name} names {path}, which leads outside the repository"
            if kind == "file":
                found.append(Mod(path, (), d, also, m))
                break
    return found or f"mod {name} names no file: none of {', '.join(tried)} is in the repository"


def declared(repo: Repo, m: Mod, name: str, decl) -> list[Mod] | str:
    if decl == "inline":
        return [Mod(m.file, m.inline + (name,), joined(m.dir, name), (), m)]
    return mod_files(repo, m, decl)


def child(repo: Repo, m: Mod, name: str) -> tuple[str, object]:
    scope = scope_of(repo, m)
    if isinstance(scope, str):
        return "unresolved", scope
    decls = scope["mods"].get(name)
    if not decls:
        return "none", None
    found: list[Mod] = []
    for decl in decls:
        files = declared(repo, m, name, decl)
        if isinstance(files, str):
            return "unresolved", files
        found += [f for f in files if f not in found]
    return ("mod", found[0]) if len(found) == 1 else ("multi", [("mod", f) for f in found])


def visible(refs: list[RustRef], frames: tuple[int, ...]) -> list[RustRef]:
    return sorted((r for r in refs if frames[:len(r.frames)] == r.frames), key=lambda r: -len(r.frames))


def lookup(repo: Repo, crate: dict, m: Mod, name: str, frames: tuple[int, ...], seen: frozenset) -> tuple[str, object]:
    key = (crate["cargo"], crate["root"], m, name, frames)
    if key in repo.rust_found:
        return repo.rust_found[key]
    if key in repo.rust_local:
        return repo.rust_local[key]
    if key in repo.rust_explored:
        repo.rust_cuts += 1
        return "none", None
    cuts = repo.rust_cuts
    repo.rust_explored.add(key)
    try:
        found = find(repo, crate, m, name, frames, seen)
    finally:
        repo.rust_explored.discard(key)
    (repo.rust_found if repo.rust_cuts == cuts else repo.rust_local)[key] = found
    return found


def alternatives(kind: str, value) -> list[tuple[str, Mod]]:
    return list(value) if kind == "multi" else [(kind, value)] if kind in ("mod", "item") else []


def combined(results: list[tuple[str, object]]) -> tuple[str, object]:
    bad = next((r for r in results if r[0] == "unresolved"), None)
    if bad is not None:
        return bad
    found: list[tuple[str, Mod]] = []
    for kind, value in results:
        found += [a for a in alternatives(kind, value) if a not in found]
    if not found:
        return next((r for r in results if r[0] == "external"), results[0] if results else ("none", None))
    return found[0] if len(found) == 1 else ("multi", found)


def onward(repo: Repo, crate: dict, kind: str, value, rest: tuple[str, ...], seen: frozenset) -> tuple[str, object]:
    return combined([walk(repo, crate, alt, rest, seen) if k == "mod" else (k, alt) for k, alt in value])


def find(repo: Repo, crate: dict, m: Mod, name: str, frames: tuple[int, ...], seen: frozenset) -> tuple[str, object]:
    results = []
    kind, value = child(repo, m, name)
    if kind != "none":
        results.append((kind, value))
    scope = scope_of(repo, m)
    if isinstance(scope, str):
        return "unresolved", scope
    binds = [r for r in visible(scope["binds"], frames) if r.bind == name and (m.file, r.id) not in seen]
    depth = max((len(r.frames) for r in binds), default=0)
    for ref in binds:
        if len(ref.frames) == depth:
            results.append(resolve(repo, crate, m, ref.path, ref.frames, seen | {(m.file, ref.id)}))
    if results:
        return combined(results)
    if name in scope["items"]:
        return "item", m
    outcome, hits = ("none", None), []
    for ref in visible(scope["globs"], frames):
        if (m.file, ref.id) in seen:
            continue
        inner = seen | {(m.file, ref.id)}
        kind, value = resolve(repo, crate, m, ref.path, ref.frames, inner)
        if kind in ("mod", "multi"):
            kind, value = combined([lookup(repo, crate, alt, name, (), inner) if k == "mod" else ("none", None) for k, alt in alternatives(kind, value)])
        if kind in ("mod", "item", "multi"):
            hits.append((kind, value))
        elif kind == "unresolved" or (kind == "external" and outcome[0] == "none"):
            outcome = kind, value
    return combined(hits) if hits else outcome


def walk(repo: Repo, crate: dict, m: Mod, rest: tuple[str, ...], seen: frozenset) -> tuple[str, object]:
    for k, name in enumerate(rest):
        kind, value = lookup(repo, crate, m, name, (), seen)
        if kind == "multi":
            return onward(repo, crate, kind, value, rest[k + 1:], seen)
        if kind == "mod":
            m = value
        elif kind == "none":
            return "unresolved", f"{name} is no module, item or use in {where_in(m)}"
        else:
            return kind, value
    return "mod", m


def resolve(repo: Repo, crate: dict, m: Mod, path: tuple[str, ...], frames: tuple[int, ...], seen: frozenset) -> tuple[str, object]:
    if len(seen) > MAX_HOPS:
        return "unresolved", f"the path goes through more than {MAX_HOPS} uses"
    first = path[0]
    if first == "::":
        return other_crate(repo, crate, path[1], path[2:], seen) if len(path) > 1 else ("unresolved", "an empty path")
    if first == "crate":
        if crate["root"] is None:
            return "unresolved", crate["why"]
        return walk(repo, crate, crate["root"], path[1:], seen)
    if first == "self":
        return walk(repo, crate, m, path[1:], seen)
    if first == "super":
        ups = next((k for k, s in enumerate(path) if s != "super"), len(path))
        start = m
        for _ in range(ups):
            if start.parent is None:
                if crate["root"] is not None and start == crate["root"]:
                    return "unresolved", "it goes above the crate root"
                return "unresolved", f"{start.file} is not reached from the crate root through mod declarations, so its parent module is not known"
            start = start.parent
        return walk(repo, crate, start, path[ups:], seen)
    kind, value = lookup(repo, crate, m, first, frames, seen)
    if kind in ("none", "external", "unresolved") and first in crate["crates"]:
        return other_crate(repo, crate, first, path[1:], seen)
    if kind == "none" or (kind == "unresolved" and first in EXTERN_PRELUDE):
        return "external", None
    if kind == "multi":
        return onward(repo, crate, kind, value, path[1:], seen)
    if kind == "mod":
        return walk(repo, crate, value, path[1:], seen)
    return kind, value


def crate_ctx(repo: Repo, cargo: str, root: str | None) -> dict:
    key = (cargo, root)
    if key not in repo.rust_ctx:
        manifest = cargo_manifest(repo, cargo)
        top = Mod(root, (), posixpath.dirname(root)) if root and repo.is_file(root) else None
        why = f"the crate at {cargo or '.'} has no root file the scanner finds (src/lib.rs, src/main.rs or a declared target)"
        repo.rust_ctx[key] = {"cargo": cargo, "root": top, "why": why, "crates": rust_crates(repo, cargo, manifest)}
    return repo.rust_ctx[key]


def other_crate(repo: Repo, crate: dict, name: str, rest: tuple[str, ...], seen: frozenset) -> tuple[str, object]:
    cargo = crate["crates"].get(name)
    if cargo is None:
        return "external", None
    manifest = cargo_manifest(repo, cargo)
    lib = lib_file(repo, cargo, manifest) if manifest else None
    if lib is None:
        return "unresolved", f"{name} is the crate at {cargo or '.'} in the repository, but it has no library root that can be read"
    target = crate_ctx(repo, cargo, lib)
    return walk(repo, target, target["root"], rest, seen)


def layout_dir(rel: str) -> str:
    name = posixpath.basename(rel)
    return posixpath.dirname(rel) if name in ("mod.rs", "lib.rs", "main.rs") else rel[:-3]


def reachable(repo: Repo, root: Mod, rel: str) -> Mod | None:
    queue, seen = [root], {root}
    while queue and len(seen) < MAX_MODULES:
        m = queue.pop(0)
        scope = scope_of(repo, m)
        for name in sorted(scope["mods"]) if isinstance(scope, dict) else ():
            found = [f for decl in scope["mods"][name] for f in (lambda x: x if isinstance(x, list) else [])(declared(repo, m, name, decl))]
            for sub in found:
                if sub.file == rel and not sub.inline:
                    return sub
                if sub not in seen:
                    seen.add(sub)
                    queue.append(sub)
    return None


def own_module(repo: Repo, crate: dict, place: dict, rel: str) -> Mod:
    root = crate["root"]
    if root is None:
        return Mod(rel, (), layout_dir(rel))
    if root.file == rel:
        return root
    m = root
    for name in place["module"]:
        kind, value = child(repo, m, name)
        if kind != "mod":
            break
        m = value
    else:
        if m.file == rel and not m.inline:
            return m
    return reachable(repo, root, rel) or Mod(rel, (), layout_dir(rel))


def inner(m: Mod, names: tuple[str, ...]) -> Mod:
    for name in names:
        m = Mod(m.file, m.inline + (name,), joined(m.dir, name), (), m)
    return m


def as_import(kind: str, value) -> tuple[str, str | None, str, tuple[str, ...]]:
    if kind == "multi":
        first = value[0][1]
        rest = tuple(p for _, f in value[1:] for p in (f.file, *f.also) if p != first.file)
        return REPOSITORY, first.file, "", tuple(dict.fromkeys(first.also + rest))
    if kind in ("mod", "item"):
        return REPOSITORY, value.file, "", value.also
    if kind == "external":
        return EXTERNAL, None, "", ()
    return UNRESOLVED, None, value, ()


def rust_target(repo: Repo, crate: dict | None, m0: Mod | None, why: str, ref: RustRef) -> tuple[str, str | None, str, tuple[str, ...]]:
    if ref.kind == "bad":
        return UNRESOLVED, None, f"the {ref.path[0]} declaration cannot be read: its tree is malformed or names a macro variable", ()
    local = ref.kind == "mod" or ref.path[0] in ("crate", "self", "super")
    if crate is None:
        if local:
            return UNRESOLVED, None, why, ()
        names = rust_crates(repo, None, None)
        if ref.path[0] == "::" or ref.path[0] in names:
            name = ref.path[1] if ref.path[0] == "::" else ref.path[0]
            rest = ref.path[2:] if ref.path[0] == "::" else ref.path[1:]
            return as_import(*other_crate(repo, {"crates": names}, name, rest, frozenset()))
        return EXTERNAL, None, "", ()
    m = inner(m0, ref.inline)
    if ref.kind == "mod":
        files = mod_files(repo, m, ref)
        if isinstance(files, str):
            return UNRESOLVED, None, files, ()
        return REPOSITORY, files[0].file, "", files[0].also + tuple(p for f in files[1:] for p in (f.file, *f.also))
    repo.rust_explored, repo.rust_local = set(), {}
    kind, value = resolve(repo, crate, m, ref.path, ref.frames, frozenset({(m.file, ref.id)}))
    return as_import(kind, value)


def rust_context(repo: Repo, rel: str) -> tuple[dict | None, Mod | None, str]:
    place = rust_place(repo, rel)
    if isinstance(place, str):
        return None, None, place
    crate = crate_ctx(repo, place["cargo"], place["root"])
    return crate, own_module(repo, crate, place, rel), ""


def rust_sweep(repo: Repo, rel: str, text: str, ctx: tuple, names: set[str], seen: set[tuple[int, str]]) -> list[Import]:
    heads = ["crate", "self", "super", r"\$crate", *(re.escape(n) for n in sorted(names))]
    pattern = re.compile(r"\b(?:use\s+(?:::\s*)?(?:%s)\s*::|mod\s+(?:r#)?[A-Za-z_]\w*\s*;)" % "|".join(heads))
    lines = {line for line, _ in seen}
    out = []
    for m in pattern.finditer(text):
        line = text.count("\n", 0, m.start()) + 1
        end = text.find(";", m.end() - 1, m.start() + MAX_SNIPPET)
        snippet = text[m.start():end + 1 if end >= 0 else m.start() + MAX_SNIPPET]
        refs = [r for r in rust_parse(lexed(rust_lex, snippet)[0])["refs"] if r.line == 1 and r.kind != "bad"]
        if not refs and line not in lines:
            out.append(Import(line, snippet.splitlines()[0].strip(), UNRESOLVED, None, DISAGREE))
        for ref in refs:
            shown = rust_shown(ref)
            if (line, shown) in seen:
                continue
            resolution, target, _, also = rust_target(repo, *ctx, replace(ref, id=-1))
            if resolution != EXTERNAL:
                out.append(Import(line, shown, UNRESOLVED, target, DISAGREE, also))
    return out


def rust_imports(repo: Repo, rel: str, text: str) -> list[Import]:
    info = repo.rust_infos.get(rel)
    if not isinstance(info, dict):
        toks, broken = lexed(rust_lex, text)
        info = repo.rust_infos[rel] = {**rust_parse(toks), "broken": broken}
    broken = info["broken"]
    ctx = rust_context(repo, rel)
    out, seen = [], set()
    for ref in info["refs"]:
        shown = rust_shown(ref)
        seen.add((ref.line, shown))
        resolution, target, why, also = rust_target(repo, *ctx, ref)
        out.append(Import(ref.line, shown, resolution, target, why, also))
    if broken:
        out.append(Import(None, rel, UNRESOLVED, None, f"the file cannot be scanned to its end: {broken}"))
    crates = ctx[0]["crates"] if ctx[0] is not None else rust_crates(repo, None, None)
    names = set(crates) | {r.bind for s in info["scopes"].values() for r in s["binds"] if r.bind}
    return out + rust_sweep(repo, rel, text, ctx, names, seen)


def jvm_imports(repo: Repo, rel: str, text: str) -> list[Import]:
    return jvm.read(repo, rel, text)


READERS = {"script": script_imports, "go": go_imports, "rust": rust_imports, "jvm": jvm_imports}

from . import jvm, workspaces
