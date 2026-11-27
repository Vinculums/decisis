from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from importlib import metadata
from typing import Callable, Iterable

HOME = "https://github.com/Vinculums/decisis"
CHECKED, AUDITED = "Checked", "Audited"
LLM_CALLS = "0 LLM calls"
GRAPH_CHECK = "deterministic graph check"
DIGEST_LENGTH = 12
VOLATILE = frozenset(("today", "fetched_at", "extracted_at", "days_left"))
GIT = "git:origin"
FETCHED = {
    "api.osv.dev": "OSV advisories from api.osv.dev",
    "osv-vulnerabilities.storage.googleapis.com": "OSV package names from osv-vulnerabilities.storage.googleapis.com",
    "api.github.com": "pull request reviews from api.github.com",
    GIT: "git history from the origin remote",
}


def version() -> str:
    try:
        return metadata.version("decisis")
    except metadata.PackageNotFoundError:
        return "unknown"


def stable(value):
    if isinstance(value, dict):
        return {k: stable(v) for k, v in value.items() if k not in VOLATILE}
    if isinstance(value, (list, tuple)):
        return [stable(v) for v in value]
    return value


def digest(reports: Iterable) -> str:
    text = json.dumps(stable(list(reports)), sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(text.encode("ascii")).hexdigest()[:DIGEST_LENGTH]


def phrases(hosts: Iterable[str]) -> tuple[str, ...]:
    return tuple(FETCHED.get(h) or f"data from {h}" for h in dict.fromkeys(hosts))


@dataclass(frozen=True)
class Signature:
    verb: str
    version: str
    digest: str
    fetched: tuple[str, ...] | None = None

    def line(self, link: Callable[[str, str], str], plain: Callable[[str], str], mono: Callable[[str], str]) -> str:
        where = " locally" if self.fetched == () else ""
        facts = " · ".join([LLM_CALLS, GRAPH_CHECK, *(plain(f) for f in self.fetched or ()), f"digest: {mono(self.digest)}"])
        return f"{plain(self.verb)}{where} with {link(HOME, 'decisis ' + self.version)} ({facts})"


def of(verb: str, reports: Iterable, hosts: Iterable[str] | None, release: str | None = None) -> Signature:
    return Signature(verb, release or version(), digest(reports), None if hosts is None else phrases(hosts))
