from __future__ import annotations

import os
import posixpath
import re
from dataclasses import dataclass, field

from .imports import (DISAGREE, EXTERNAL, MAX_BYTES, MAX_NESTING, MAX_WALK, REPOSITORY, SKIPPED_DIRS, UNRESOLVED, Broken, Import, Token,
                      at, clean, is_punct, joined, lexed, name_char, read_small, rust_comment)

SOURCES = (".java", ".kt")
SOURCE_SETS = ("java", "kotlin")
BUILD_OUTPUT = {"build": ("build.gradle", "build.gradle.kts"), "target": ("pom.xml",)}
BUILD_FILES = ("build.gradle", "build.gradle.kts", "pom.xml")
HEAD_BYTES = 65536
HEAD_TOKENS = 2000
BOM = "\ufeff"
JVM_SWEEP = re.compile(r"(?m)(?:^|;)[ \t]*import[ \t]+(?:static[ \t]+)?((?:`[^`\n]+`|[A-Za-z_$][\w$]*)"
                       r"(?:[ \t]*\.[ \t]*(?:`[^`\n]+`|[A-Za-z_$][\w$]*|\*))*)")
FILE_ANNOTATION = re.compile(r"@file[ \t]*:[ \t]*(?:\[[^\]\n]{0,2000}\]|\w+(?:[ \t]*\([^)\n]{0,2000}\))?)")
PACKAGE_LINE = re.compile(r"package[ \t]+([\w$.`]+)[ \t]*;?[ \t]*(?://.*)?$")
FACADE = re.compile(r"@file[ \t]*:[ \t]*(?:\[[^\]]*?)?JvmName[ \t]*\([ \t]*\"([^\"\n]+)\"")
KOTLIN_TOP = re.compile(
    r"(?m)^(?:(?:public|internal|private|expect|actual|data|sealed|enum|annotation|inline|value|abstract|open|const|suspend|operator|infix"
    r"|tailrec|external|fun)[ \t]+)*(?:class|interface|object|typealias|fun|val|var)[ \t]+(?:<[^>\n]*>[ \t]*)?(?:[\w.<>?, *]{0,200}\.)?`?(\w+)")
DECLARED = re.compile(r"\b(?:class|interface|enum|record|object|typealias|fun|val|var)\b[ \t]+(?:<[^>\n]{0,200}>[ \t]*)?(?:[\w.<>?, *]{0,200}\.)?`?(\w+)")
PLATFORM = ("java", "javax", "jdk", "kotlin")
STARTS = frozenset({"public", "private", "protected", "internal", "abstract", "final", "open", "sealed", "non", "data", "enum",
                    "class", "interface", "object", "record", "fun", "val", "var", "typealias", "annotation", "inline", "value",
                    "static", "strictfp", "expect", "actual", "external", "const", "lateinit", "suspend", "tailrec", "operator",
                    "infix", "companion", "inner", "override", "native", "synchronized", "transient", "volatile", "default", "module"})
PACKAGE_HEAD = re.compile(r"\bpackage[ \t\r\n]+`?([A-Za-z_$][\w$]*)")
GRADLE_DIRS = re.compile(r"\b(?:srcDirs?|setSrcDirs)\b")
LITERAL = re.compile(r"""(["'])([^"'\n$]+)\1""")
POM_DIRS = re.compile(r"<(sourceDirectory|testSourceDirectory|source)>([^<>]{1,500})</\1>")
BASEDIR = re.compile(r"\$\{(?:project\.)?basedir\}/")


@dataclass(frozen=True)
class Ref:
    line: int
    parts: tuple[str, ...] | None
    static: bool = False
    wildcard: bool = False
    alias: str | None = None
    problem: str = ""


@dataclass
class Index:
    classes: dict[tuple[str, ...], list[str]] = field(default_factory=dict)
    packages: dict[tuple[str, ...], list[str]] = field(default_factory=dict)
    truncated: bool = False
    declared: dict[str, frozenset[str]] = field(default_factory=dict)
    unplaced: list[str] = field(default_factory=list)
    mentioned: dict[str, frozenset[str] | None] = field(default_factory=dict)
    heads: dict[str, frozenset[str] | None] = field(default_factory=dict)


def jvm_tokens(text: str, kotlin: bool):
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
            if kotlin:
                j = rust_comment(text, i, line)
            else:
                j = text.find("*/", i + 2)
                if j < 0:
                    raise Broken(f"a comment opened at line {line} is not closed")
                j += 2
            line += text.count("\n", i, j)
            i = j
        elif c == '"':
            j, value = jvm_string(text, i, line, kotlin, 0)
            yield Token("string", value, line)
            line += text.count("\n", i, j)
            i = j
        elif c == "'":
            i = jvm_char(text, i, line)
        elif c == "`" and kotlin:
            j = text.find("`", i + 1)
            if j < 0 or "\n" in text[i:j]:
                raise Broken(f"a quoted name at line {line} is not closed")
            yield Token("name", text[i + 1:j], line)
            i = j + 1
        elif name_char(c):
            j = i
            while j < n and name_char(text[j]):
                j += 1
            yield Token("num" if c.isdigit() else "name", text[i:j], line)
            i = j
        else:
            yield Token("punct", c, line)
            i += 1


def jvm_lex(text: str, out: list[Token], kotlin: bool) -> None:
    for tok in jvm_tokens(text, kotlin):
        out.append(tok)


def jvm_string(text: str, i: int, line: int, kotlin: bool, depth: int) -> tuple[int, str | None]:
    if text.startswith('"""', i):
        return jvm_block(text, i, line, kotlin), None
    j, plain, out = i + 1, True, []
    while j < len(text) and text[j] != '"':
        c = text[j]
        if c == "\n":
            raise Broken(f"a string at line {line} is not closed")
        if c == "\\":
            plain = False
            j += 2
        elif kotlin and c == "$" and text.startswith("{", j + 1):
            plain = False
            j = jvm_template(text, j + 2, line, depth + 1)
        else:
            out.append(c)
            j += 1
    if j >= len(text):
        raise Broken(f"a string at line {line} is not closed")
    return j + 1, "".join(out) if plain else None


def jvm_block(text: str, i: int, line: int, kotlin: bool) -> int:
    j = i + 3
    while j < len(text):
        if not kotlin and text[j] == "\\":
            j += 2
        elif text.startswith('"""', j):
            j += 3
            while kotlin and j < len(text) and text[j] == '"':
                j += 1
            return j
        else:
            j += 1
    raise Broken(f"a {'raw string' if kotlin else 'text block'} at line {line} is not closed")


def jvm_template(text: str, j: int, line: int, depth: int) -> int:
    if depth > MAX_NESTING:
        raise Broken(f"a string template at line {line} nests deeper than {MAX_NESTING} levels")
    open_braces = 1
    while j < len(text):
        c = text[j]
        if c == "{":
            open_braces += 1
        elif c == "}":
            open_braces -= 1
            if open_braces == 0:
                return j + 1
        elif c == '"':
            j = jvm_string(text, j, line, True, depth)[0]
            continue
        elif c == "'":
            j = jvm_char(text, j, line)
            continue
        elif text.startswith("//", j):
            k = text.find("\n", j)
            j = len(text) if k < 0 else k
            continue
        elif text.startswith("/*", j):
            j = rust_comment(text, j, line)
            continue
        j += 1
    raise Broken(f"a string template opened at line {line} is not closed")


def jvm_char(text: str, i: int, line: int) -> int:
    j = i + (3 if text.startswith("\\", i + 1) else 2)
    while j < len(text) and text[j] != "'":
        if text[j] == "\n":
            raise Broken(f"a character literal at line {line} is not closed")
        j += 1
    if j >= len(text):
        raise Broken(f"a character literal at line {line} is not closed")
    return j + 1


def qualified(toks: list[Token], i: int) -> tuple[list[str], bool, int] | None:
    parts: list[str] = []
    while True:
        tok = at(toks, i)
        if tok is None or tok.kind != "name":
            return None
        parts.append(tok.value)
        i += 1
        if not is_punct(at(toks, i), "."):
            return parts, False, i
        if is_punct(at(toks, i + 1), "*"):
            return parts, True, i + 2
        i += 1


def skip_group(toks: list[Token], i: int, opener: str, closer: str) -> int:
    depth = 0
    while i < len(toks):
        if is_punct(toks[i], opener):
            depth += 1
        elif is_punct(toks[i], closer):
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    return i


def annotation(toks: list[Token], i: int) -> tuple[int, bool, list[str]]:
    start = i
    i += 1
    nxt = at(toks, i)
    if nxt is None or nxt.kind != "name" or nxt.value == "interface":
        return i, False, []
    i += 1
    while True:
        after = at(toks, i + 1)
        if is_punct(at(toks, i), ":") and is_punct(after, "["):
            i += 1
        elif (is_punct(at(toks, i), ":") or is_punct(at(toks, i), ".")) and after is not None and after.kind == "name":
            i += 2
        else:
            break
    if is_punct(at(toks, i), "["):
        i = skip_group(toks, i, "[", "]")
    elif is_punct(at(toks, i), "("):
        i = skip_group(toks, i, "(", ")")
    facades = [toks[j + 2].value for j in range(start, min(i, len(toks)) - 3)
               if toks[j].kind == "name" and toks[j].value == "JvmName" and is_punct(toks[j + 1], "(") and toks[j + 2].kind == "string" and toks[j + 2].value]
    return i, True, facades


@dataclass
class Header:
    refs: list[Ref] = field(default_factory=list)
    package: tuple[str, ...] | None = None
    facades: list[str] = field(default_factory=list)
    readable: bool = True


def header(toks: list[Token], kotlin: bool, complete: bool = True) -> Header:
    out, i, ended, package_ok = Header(), 0, False, True
    while i < len(toks):
        tok = toks[i]
        if is_punct(tok, ";"):
            i += 1
        elif is_punct(tok, "@") and getattr(at(toks, i + 1), "value", None) == "interface":
            ended = True
            break
        elif is_punct(tok, "@"):
            i, ok, facades = annotation(toks, i)
            out.facades += facades
            if not ok:
                ended = True
                package_ok = package_ok and out.package is not None
                break
        elif tok.kind == "name" and tok.value == "package":
            found = qualified(toks, i + 1)
            if found is None or found[1]:
                package_ok = False
                i += 1
            else:
                out.package, i = tuple(found[0]), found[2]
        elif tok.kind == "name" and tok.value == "import":
            ref, i = import_ref(toks, i, kotlin)
            out.refs.append(ref)
        else:
            ended = True
            if out.package is None and not (tok.kind == "name" and tok.value in STARTS):
                package_ok = False
            break
    out.readable = package_ok and (out.package is not None or ended or complete)
    return out


def import_ref(toks: list[Token], i: int, kotlin: bool) -> tuple[Ref, int]:
    line = toks[i].line
    j = i + 1
    nxt, after = at(toks, j), at(toks, j + 1)
    static = nxt is not None and nxt.kind == "name" and nxt.value == "static" and after is not None and after.kind == "name"
    found = qualified(toks, j + 1 if static else j)
    if found is None:
        k = j
        while k < len(toks) and not is_punct(toks[k], ";") and not (toks[k].kind == "name" and toks[k].value == "import" and toks[k].line > line):
            k += 1
        return Ref(line, None, problem="the import declaration cannot be read"), k + (1 if k < len(toks) and is_punct(toks[k], ";") else 0)
    parts, wildcard, j = found
    alias = None
    as_tok, name = at(toks, j), at(toks, j + 1)
    if kotlin and not wildcard and as_tok is not None and as_tok.kind == "name" and as_tok.value == "as" and name is not None and name.kind == "name":
        alias, j = name.value, j + 2
    if is_punct(at(toks, j), ";"):
        j += 1
    return Ref(line, tuple(parts), static, wildcard, alias), j


def shown(ref: Ref) -> str:
    name = ".".join(ref.parts or ()) + (".*" if ref.wildcard else "")
    return f"import {'static ' if ref.static else ''}{name}" + (f" as {ref.alias}" if ref.alias else "")


def scrub(text: str) -> str:
    out, i, n = [], 0, len(text)
    while i < n:
        c = text[i]
        if c in "\"'":
            j = i + 1
            while j < n and text[j] != c and text[j] != "\n":
                j += 2 if text[j] == "\\" else 1
            out.append(text[i:j + 1])
            i = j + 1
        elif text.startswith("//", i):
            j = text.find("\n", i)
            i = n if j < 0 else j
        elif text.startswith("/*", i):
            j = text.find("*/", i + 2)
            i = n if j < 0 else j + 2
        else:
            out.append(c)
            i += 1
    return "".join(out)


def argument(text: str, start: int) -> str:
    j = start
    while j < len(text) and text[j] in " \t=+<":
        j += 1
    if j < len(text) and text[j] in "[(":
        depth, k = 0, j
        while k < len(text):
            depth += text[k] in "[("
            depth -= text[k] in "])"
            if depth == 0:
                return text[j:k + 1]
            k += 1
        return text[j:]
    end = text.find("\n", j)
    return text[j:end if end >= 0 else len(text)]


def declared_roots(repo, build: str) -> list[str]:
    text = read_small(repo, build)
    if text is None:
        return []
    here, found = posixpath.dirname(build), []
    if build.endswith("pom.xml"):
        found = [BASEDIR.sub("", m.group(2).strip(), count=1) for m in POM_DIRS.finditer(text)]
        found = [path for path in found if "$" not in path]
    else:
        body = scrub(text)
        for m in GRADLE_DIRS.finditer(body):
            found += [lit.group(2) for lit in LITERAL.finditer(argument(body, m.end()))]
    roots = []
    for path in found:
        base = clean(posixpath.join(here, path.strip().rstrip("/")))
        if base is not None and repo.is_dir(base):
            roots.append(base)
    return roots


def source_root(parts: list[str]) -> int | None:
    for i in range(len(parts) - 3):
        if parts[i] == "src" and parts[i + 2] in SOURCE_SETS:
            return i + 3
    return None


def read_head(repo, rel: str, size: int) -> tuple[str | None, bool]:
    try:
        with open(repo.root / rel, "rb") as f:
            data = f.read(size + 1)
    except OSError:
        return None, False
    return data[:size].decode("utf-8", "replace").removeprefix(BOM), len(data) <= size


def head_tokens(text: str, kotlin: bool) -> tuple[list[Token], bool]:
    out: list[Token] = []
    try:
        for tok in jvm_tokens(text, kotlin):
            out.append(tok)
            if len(out) >= HEAD_TOKENS:
                return out, False
    except Broken:
        return out, False
    return out, True


def package_info(repo, rel: str) -> Header:
    kotlin = not rel.endswith(".java")
    info = Header(readable=False)
    for size in (HEAD_BYTES, MAX_BYTES):
        text, whole = read_head(repo, rel, size)
        if text is None:
            return info
        if "\x00" in text:
            return Header(readable=False)
        toks, complete = head_tokens(text, kotlin)
        info = header(toks, kotlin, complete and whole)
        if info.readable or whole:
            break
    return info


def file_under(roots: set[str], d: str) -> str | None:
    best = None
    here = d
    while here:
        if here in roots and (best is None or len(here) > len(best)):
            best = here
        here = posixpath.dirname(here)
    return best


def build_index(repo) -> Index:
    index, sources, builds, seen = Index(), [], [], 0
    for dirpath, dirnames, filenames in os.walk(repo.root):
        drop = {d for d, markers in BUILD_OUTPUT.items() if any(m in filenames for m in markers)}
        dirnames[:] = sorted(d for d in dirnames if not d.startswith(".") and d not in SKIPPED_DIRS and d not in drop)
        rel = os.path.relpath(dirpath, repo.root).replace(os.sep, "/")
        rel = "" if rel == "." else rel
        for name in filenames:
            if name.endswith(SOURCES):
                sources.append(joined(rel, name))
            elif name in BUILD_FILES:
                builds.append(joined(rel, name))
        seen += len(filenames)
        if seen > MAX_WALK:
            index.truncated = True
            break
    roots = {root for build in builds for root in declared_roots(repo, build)}
    for rel in sorted(sources):
        if not repo.is_file(rel):
            continue
        d = posixpath.dirname(rel)
        parts = d.split("/") if d else []
        keys: set[tuple[str, ...]] = set()
        start = source_root(posixpath.join(d, "x").split("/"))
        if start is not None:
            keys.add(tuple(parts[start:]))
        under = file_under(roots, d)
        if under is not None:
            keys.add(tuple(d[len(under):].strip("/").split("/")) if d != under else ())
        info = package_info(repo, rel)
        if info.package is not None:
            keys.add(info.package)
        if not info.readable:
            index.unplaced.append(rel)
        stem = posixpath.basename(rel).rsplit(".", 1)[0]
        names = [stem]
        if rel.endswith(".kt"):
            names += [stem + "Kt", *info.facades]
        for key in keys:
            files = index.packages.setdefault(key, [])
            if rel not in files:
                files.append(rel)
            for name in names:
                found = index.classes.setdefault((*key, name), [])
                if rel not in found:
                    found.append(rel)
    return index


def index_of(repo) -> Index:
    if repo.jvm is None:
        repo.jvm = build_index(repo)
    return repo.jvm


def top_level(repo, index: Index, rel: str) -> frozenset[str]:
    if rel not in index.declared:
        text, _ = read_head(repo, rel, MAX_BYTES)
        index.declared[rel] = frozenset(KOTLIN_TOP.findall(text or ""))
    return index.declared[rel]


def mentioned(repo, index: Index, rel: str) -> frozenset[str] | None:
    if rel not in index.mentioned:
        text, whole = read_head(repo, rel, MAX_BYTES)
        stem = posixpath.basename(rel).rsplit(".", 1)[0]
        index.mentioned[rel] = None if text is None or not whole or "\x00" in text else frozenset([stem, stem + "Kt", *DECLARED.findall(text), *FACADE.findall(text)])
    return index.mentioned[rel]


def package_heads(repo, index: Index, rel: str) -> frozenset[str] | None:
    if rel not in index.heads:
        text, whole = read_head(repo, rel, MAX_BYTES)
        index.heads[rel] = None if text is None or not whole or "\x00" in text else frozenset(PACKAGE_HEAD.findall(text))
    return index.heads[rel]


def declaring(repo, index: Index, package: tuple[str, ...], name: str) -> list[str]:
    return [f for f in index.packages.get(package, []) if f.endswith(".kt") and name in top_level(repo, index, f)]


def directories(files: list[str]) -> list[str]:
    return list(dict.fromkeys(posixpath.dirname(f) for f in files))


def package_result(files: list[str], extra: list[str] = ()) -> tuple[str, tuple[str, ...]]:
    dirs = directories(files)
    first = dirs[0] + "/"
    return first, tuple(dict.fromkeys([*dirs, *files, *extra]))


def package_sizes(names: tuple[str, ...], wildcard: bool) -> list[int]:
    sizes = [len(names)] if wildcard else []
    capital = next((i for i, n in enumerate(names) if n[:1].isupper()), None)
    if capital:
        sizes.append(capital)
    sizes.append(len(names) - 1)
    return [k for k in dict.fromkeys(sizes) if 0 < k <= len(names)]


def target_of(repo, ref: Ref) -> tuple[str, str | None, str, tuple[str, ...]]:
    index = index_of(repo)
    names = tuple(ref.parts)
    hits: list[str] = []
    for k in range(len(names), 0, -1):
        prefix = names[:k]
        found = index.classes.get(prefix) or declaring(repo, index, prefix[:-1], prefix[-1])
        hits += [f for f in found if f not in hits]
    package = index.packages.get(names, []) if ref.wildcard else []
    if package:
        target, also = package_result(package, hits)
        return REPOSITORY, target, "", also
    if hits:
        return REPOSITORY, hits[0], "", tuple(hits[1:])
    for size in package_sizes(names, ref.wildcard):
        held = index.packages.get(names[:size])
        if held:
            target, also = package_result(held)
            where = ".".join(names[:size])
            name = names[size] if size < len(names) else "*"
            return UNRESOLVED, target, f"{where} is a package of the repository, but no source file in it declares {name}; it may be generated or live in a library", also
    segments = set(names)
    maybe = [f for f in index.unplaced if (found := mentioned(repo, index, f)) is None or segments & found
             or (ref.wildcard and ((heads := package_heads(repo, index, f)) is None or not heads or names[0] in heads))]
    if maybe:
        why = f"{len(index.unplaced)} source file(s) of the repository have a package line that cannot be read, and {maybe[0]} may declare a name this import uses"
        return UNRESOLVED, maybe[0], why, tuple(maybe[1:])
    if index.truncated and names[0] not in PLATFORM:
        return UNRESOLVED, None, f"the repository has more than {MAX_WALK} files, so its Java and Kotlin sources were not all searched", ()
    return EXTERNAL, None, "", ()


def read(repo, rel: str, text: str) -> list[Import]:
    kotlin = not rel.endswith(".java")
    text = text.removeprefix(BOM)
    toks, broken = lexed(lambda t, out: jvm_lex(t, out, kotlin), text)
    out, read_specs = [], set()
    for ref in header(toks, kotlin).refs:
        if ref.parts is None:
            out.append(Import(ref.line, "import with a name that cannot be read", UNRESOLVED, None, ref.problem))
            continue
        read_specs.add(".".join(ref.parts) + (".*" if ref.wildcard else ""))
        resolution, target, why, also = target_of(repo, ref)
        out.append(Import(ref.line, shown(ref), resolution, target, why, also))
    if broken:
        out.append(Import(None, rel, UNRESOLVED, None, f"the file cannot be scanned to its end: {broken}"))
    for m in JVM_SWEEP.finditer(text):
        name = re.sub(r"[\s`]", "", m.group(1))
        if name in read_specs:
            continue
        wildcard = name.endswith(".*")
        ref = Ref(0, tuple(name[:-2].split(".") if wildcard else name.split(".")), wildcard=wildcard)
        resolution, target, _, also = target_of(repo, ref)
        if resolution != EXTERNAL:
            out.append(Import(text.count("\n", 0, m.start(1)) + 1, f"import {name}", UNRESOLVED, target, DISAGREE, also))
    return out
