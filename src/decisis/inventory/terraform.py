from __future__ import annotations

import re

from .shape import Inventory, package_id, text_digest

FORMAT = "terraform"
SIBLINGS: tuple[str, ...] = ()
ECOSYSTEM = "Terraform"
LOCKFILE = ".terraform.lock.hcl"
ADVISORIES = False
UNRESOLVED = "OSV has no Terraform ecosystem; the provider is checked against decision rules only, not advisories"
NOTES = ("OSV has no Terraform ecosystem (checked 2026-11-24), so Terraform providers are checked against decision rules only, "
         "not against advisories",)
BLOCK = re.compile(r'provider\s+"([^"]+)"\s*\{')
PAIR = re.compile(r"([A-Za-z_][A-Za-z0-9_-]*)\s*=\s*(.+)")
STRING = r'"((?:[^"\\\n]|\\.)*)"'
LIST = re.compile(rf"\[\s*(?:{STRING}\s*,\s*)*(?:{STRING}\s*)?\]")
ITEM = re.compile(rf"{STRING},?")
ADDRESS = re.compile(r"(?:[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+(?::\d+)?/)?[A-Za-z0-9_-]+/[A-Za-z0-9_-]+")
FIRST = re.compile(r'provider\s+"[^"/]+/[^"]+"')


def first_line(text: str) -> str:
    for raw in text.splitlines():
        body = raw.strip()
        if body and not body.startswith(("#", "//")):
            return body
    return ""


def detect(text: str, filename: str) -> bool:
    return filename == LOCKFILE or FIRST.match(first_line(text)) is not None


class _Parser:
    def __init__(self, filename: str):
        self.filename = filename
        self.providers: list[dict] = []
        self.block: dict | None = None
        self.items: list[str] | None = None
        self.key = ""

    def fail(self, n: int, body: str, what: str) -> None:
        raise ValueError(f"{self.filename} line {n}: {what}, got {body!r}; audit reads only the provider blocks of {LOCKFILE}")

    def line(self, n: int, body: str) -> None:
        if self.items is not None:
            self.item(n, body)
        elif self.block is None:
            m = BLOCK.fullmatch(body)
            if m is None:
                self.fail(n, body, 'expected provider "<address>" {')
            self.block = {"address": m[1], "line": n}
        elif body == "}":
            self.close(n, body)
        else:
            self.pair(n, body)

    def item(self, n: int, body: str) -> None:
        if body == "]":
            self.block[self.key], self.items = self.items, None
            return
        m = ITEM.fullmatch(body)
        if m is None:
            self.fail(n, body, "expected a quoted string or ]")
        self.items.append(m[1])

    def pair(self, n: int, body: str) -> None:
        m = PAIR.fullmatch(body)
        if m is None:
            self.fail(n, body, "expected name = value")
        key, value = m[1], m[2].strip()
        if key in self.block:
            self.fail(n, body, f"{key} is set twice")
        if value == "[":
            self.key, self.items = key, []
        elif (s := re.fullmatch(STRING, value)) is not None:
            self.block[key] = s[1]
        elif LIST.fullmatch(value) is not None:
            self.block[key] = re.findall(STRING, value)
        else:
            self.fail(n, body, "expected a quoted string or a list of them")

    def close(self, n: int, body: str) -> None:
        block, self.block = self.block, None
        if not ADDRESS.fullmatch(block["address"]):
            self.fail(block["line"], block["address"], "expected a provider address such as registry.terraform.io/hashicorp/aws")
        if not isinstance(block.get("version"), str) or not block["version"]:
            self.fail(n, body, f"provider {block['address']} has no version")
        if any(p["address"] == block["address"] for p in self.providers):
            self.fail(block["line"], block["address"], "the provider is listed twice")
        self.providers.append(block)


def parse(text: str, filename: str) -> list[dict]:
    parser = _Parser(filename)
    for n, line in enumerate(text.splitlines(), 1):
        body = line.strip()
        if body and not body.startswith(("#", "//")):
            parser.line(n, body)
    if parser.block is not None:
        raise ValueError(f"{filename} ends inside the block of provider {parser.block['address']}")
    return parser.providers


def read(text: str, filename: str, repo: str, siblings: dict[str, str] | None = None) -> tuple[list[dict], list[dict]]:
    inv = Inventory(repo, "terraform-lockfile", text_digest(text))
    for p in parse(text, filename):
        name, version = p["address"], p["version"]
        pkg = {"id": package_id(ECOSYSTEM, name, version), "ecosystem": ECOSYSTEM, "name": name, "version": version, "purl": "",
               "unresolved": UNRESOLVED}
        inv.add(name, pkg, f"{repo}:{filename}#{name}")
        constraints = p.get("constraints")
        inv.depends(None, name, f"{filename} locks {name} {version}" + (f" (constraints {constraints})" if isinstance(constraints, str) else ""))
    return inv.result()
