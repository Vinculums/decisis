from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from urllib.parse import quote, unquote

PURL_TYPE = {"npm": "npm", "PyPI": "pypi", "crates.io": "cargo", "Go": "golang", "Maven": "maven", "NuGet": "nuget",
             "RubyGems": "gem", "Packagist": "composer", "GitHub Actions": "githubactions", "Debian": "deb", "Alpine": "apk"}
NAMED_BY_PATH = {"golang", "composer", "githubactions"}
OPERATORS = {"AND", "OR", "WITH"}
UNKNOWN_LICENSES = {"NOASSERTION", "NONE"}


def now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def digest(obj) -> str:
    return hashlib.sha256(json.dumps(obj, sort_keys=True).encode()).hexdigest()


def text_digest(*texts: str) -> str:
    return hashlib.sha256("\n".join(texts).encode()).hexdigest()


def package_id(ecosystem: str, name: str, version: str) -> str:
    kind = PURL_TYPE.get(ecosystem.split(":")[0], ecosystem.lower())
    return f"pkg:{kind}/{name}@{version}"


def pypi_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def json_object(text: str) -> dict | None:
    if not text.lstrip().startswith("{"):
        return None
    try:
        obj = json.loads(text)
    except json.JSONDecodeError:
        return None
    return obj if isinstance(obj, dict) else None


def license_ids(expression: str) -> list[str]:
    out, skip = [], False
    for token in re.findall(r"[A-Za-z0-9.+:-]+", expression or ""):
        if skip:
            skip = False
        elif token.upper() == "WITH":
            skip = True
        elif token.upper() not in OPERATORS and token not in UNKNOWN_LICENSES and token not in out:
            out.append(token)
    return out


def make_purl(kind: str, name: str, version: str) -> str:
    path = "/".join(quote(part, safe="") for part in name.split("/"))
    return f"pkg:{kind}/{path}@{quote(version, safe='.-_~+')}"


def parse_purl(purl: str) -> dict | None:
    if not isinstance(purl, str) or not purl.startswith("pkg:"):
        return None
    rest = purl[4:].lstrip("/").split("#", 1)[0]
    rest, _, query = rest.partition("?")
    qualifiers = dict(pair.split("=", 1) for pair in query.split("&") if "=" in pair)
    path, _, version = rest.rpartition("@") if "@" in rest else (rest, "", "")
    parts = [unquote(p) for p in path.split("/") if p]
    if len(parts) < 2:
        return None
    return {"type": parts[0].lower(), "namespace": "/".join(parts[1:-1]), "name": parts[-1], "version": unquote(version),
            "qualifiers": {k.lower(): unquote(v) for k, v in qualifiers.items()}}


def _distro(p: dict) -> str:
    distro = p["qualifiers"].get("distro", "")
    if p["type"] == "deb" and p["namespace"] == "debian":
        m = re.fullmatch(r"debian-(\d+)(?:\.\d+)*", distro)
        return f"Debian:{m[1]}" if m else ""
    if p["type"] == "apk" and p["namespace"] == "alpine":
        m = re.fullmatch(r"(?:alpine-)?v?(\d+)\.(\d+)(?:\.\d+)*", distro)
        return f"Alpine:v{m[1]}.{m[2]}" if m else ""
    return ""


def ecosystem_of(p: dict) -> tuple[str, str]:
    kind, ns, name = p["type"], p["namespace"], p["name"]
    if kind == "npm":
        return "npm", f"{ns}/{name}" if ns else name
    if kind == "pypi":
        return "PyPI", pypi_name(name)
    if kind == "maven":
        return ("Maven", f"{ns}:{name}") if ns else ("", name)
    if kind in NAMED_BY_PATH:
        eco = next(e for e, t in PURL_TYPE.items() if t == kind)
        return eco, f"{ns}/{name}" if ns else name
    if kind in ("deb", "apk"):
        return _distro(p), name
    eco = next((e for e, t in PURL_TYPE.items() if t == kind), "")
    return eco, f"{ns}/{name}" if ns and eco else name


def from_purl(purl: str, version: str = "") -> dict | None:
    p = parse_purl(purl)
    if p is None:
        return None
    eco, name = ecosystem_of(p)
    version = version or p["version"]
    if eco == "Go":
        version = version.removeprefix("v")
    full = f"{p['namespace']}/{p['name']}" if p["namespace"] else p["name"]
    pid = package_id(eco, name, version) if eco else f"pkg:{p['type']}/{full}@{version}"
    reason = "" if eco else f"purl type {p['type']} has no OSV ecosystem this reader can name"
    if eco and not version:
        reason = "the inventory gives no version"
    return {"id": pid, "ecosystem": eco, "name": name, "version": version, "purl": purl.split("?", 1)[0].split("#", 1)[0],
            "unresolved": reason}


class Inventory:
    def __init__(self, repo: str, source_system: str, content_hash: str):
        self.fetched = now()
        self.repo_id = f"repo:{repo}"
        self.repo = repo
        self.source_system = source_system
        self.nodes = {self.repo_id: {"id": self.repo_id, "kind": "Repository", "title": repo,
                                     "props": {"source_system": source_system, "source_ref": repo, "fetched_at": self.fetched,
                                               "content_hash": content_hash}}}
        self.keys: dict = {}
        self.marked: set[str] = set()
        self.links: dict[tuple[str, str], tuple[str, bool]] = {}

    def root(self, key) -> None:
        self.keys[key] = self.repo_id

    def add(self, key, pkg: dict, source_ref: str, license: str = "", dev: bool = False) -> str:
        pid = pkg["id"]
        self.keys[key] = pid
        if dev:
            self.marked.add(pid)
        self.nodes.setdefault(pid, {"id": pid, "kind": "Package", "title": f"{pkg['name']}@{pkg['version']}", "props": {
            "ecosystem": pkg["ecosystem"], "name": pkg["name"], "version": pkg["version"], "dev": False,
            "licenses": license_ids(license), "license_expression": license or "", "purl": pkg["purl"],
            "unresolved": pkg.get("unresolved") or "", "source_system": self.source_system, "source_ref": source_ref,
            "fetched_at": self.fetched}})
        return pid

    def depends(self, src_key, dst_key, why: str, dev: bool = False) -> None:
        src = self.repo_id if src_key is None else self.keys.get(src_key)
        dst = self.keys.get(dst_key)
        if src is None or dst is None or src == dst or dst == self.repo_id:
            return
        dev = dev or dst in self.marked
        old = self.links.get((src, dst))
        if old is None or (old[1] and not dev):
            self.links[(src, dst)] = (why, dev)

    def adopt_orphans(self, why: str) -> None:
        targets = {dst for _, dst in self.links}
        for pid, node in sorted(self.nodes.items()):
            if node["kind"] == "Package" and pid not in targets:
                self.links[(self.repo_id, pid)] = (why, pid in self.marked)

    def _reach(self, shipped_only: bool) -> set[str]:
        out: dict[str, list[str]] = {}
        for (src, dst), (_, dev) in self.links.items():
            if not (shipped_only and dev):
                out.setdefault(src, []).append(dst)
        seen, todo = set(), [self.repo_id]
        while todo:
            for dst in out.get(todo.pop(), []):
                if dst not in seen:
                    seen.add(dst)
                    todo.append(dst)
        return seen

    def result(self) -> tuple[list[dict], list[dict]]:
        reached, shipped = self._reach(False), self._reach(True)
        for pid, node in self.nodes.items():
            if node["kind"] == "Package":
                node["props"]["dev"] = pid in self.marked or (pid in reached and pid not in shipped)
        edges = [{"source": src, "target": dst, "type": "DEPENDS_ON", "evidence": why}
                 for (src, dst), (why, _) in sorted(self.links.items())]
        return list(self.nodes.values()), edges
