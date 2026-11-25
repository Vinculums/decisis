"""Run `check`, and `audit` when an inventory is given, on a pull request in GitHub Actions and post one comment.

`main` reads the action's inputs from `DECISIS_*` variables and the pull request from the event payload, so no
input or pull request text passes through a shell. The changed files are `git diff BASE...HEAD` with the base
SHA from the payload. The reviewers given to `check` are the users other than the author whose latest review
approves the pull request; requested reviewers are listed in the comment and not counted. The comment starts
with `MARKER`; the first comment by `DECISIS_COMMENT_AUTHOR` that starts with it is updated, else a new one is
created. A pull request is a fork when its head repository is missing or is not the base repository. Every
title, path and reason is escaped before it reaches Markdown, and the body is cut to fit GitHub's limit.
The body is always written to the job summary; on a fork pull request, or when GitHub refuses the write,
it is written only there.

`DECISIS_INVENTORY` holds one path or `auto` per line. A path is read as `decisis audit` reads it, and a path that
cannot be audited stops the step. `auto` stands for the inventories in the root of the working directory: the
files in `LOCKFILES`, any `requirements*.txt`, and `.github/workflows` when it holds a workflow. No other directory
is searched. A found file is read only when it resolves inside the working directory, with its siblings bounded the
same way; one that cannot be audited gets a section that says why and does not stop the step. Each inventory has
its own audit section, and the audit violations of all of them are added to the check's.

`DECISIS_DECISIONS_FROM` is `base` (the default) or `head`. With `base` the decisions come from the base commit's
tree, read by `committed`, so a pull request is judged by the decisions it would merge into, not by ones it brings.
When the pull request changes a file the decisions come from, the comment lists those files, and the decisions and
waivers that change when both sides can be read; they change no verdict in this run. When the base commit has no
decisions, nothing is judged. With `head` the decisions come from the checkout, as before.
"""
from __future__ import annotations

import html
import json
import os
import subprocess
import sys
import unicodedata
import urllib.error
from dataclasses import dataclass, field
from importlib import metadata
from pathlib import Path
from typing import Callable, Mapping

from . import audit, check, codeowners, committed, external, init, inventory, render, rules
from . import checkout as co
from . import github as gh
from .inventory import actions as workflows
from .inventory.siblings import clean, directory_reader, directory_resolver
from .sandbox import LimitExceeded

MARKER = "<!-- decisis -->"
MAX_BODY = 65_536
ATTEMPTS = ((50, True), (50, False), (20, False), (5, False), (0, False))
AUTHOR = "github-actions[bot]"
MAX_COMMENTS = 3000
FETCH_SECONDS = 600
HEX = frozenset("0123456789abcdef")
ESCAPED = frozenset("\\`*_{}[]()#+-!|~$:")
JOINER = "⁠"
TRUE = ("true", "yes", "1")
FALSE = ("false", "no", "0", "")
BASE, HEAD = "base", "head"
AUTO = "auto"
WORKFLOWS = ".github/workflows"
LOCKFILES = frozenset(("package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml", "yarn.lock", "bun.lock", "uv.lock", "poetry.lock",
                       "Cargo.lock", "go.mod", "gradle.lockfile", "pom.xml", ".terraform.lock.hcl"))


class ReadOnly(Exception):
    pass


class TooManyComments(Exception):
    pass


@dataclass(frozen=True)
class Pull:
    repo: str
    number: int
    base: str
    fork: bool
    requested: tuple[str, ...] = ()
    author: str | None = None


@dataclass(frozen=True)
class Audited:
    inventory: str
    report: dict | None = None
    problem: str | None = None


@dataclass(frozen=True)
class Pending:
    files: list[str]
    changes: list[dict] | None = None


@dataclass
class Outcome:
    report: dict
    pull: Pull
    approved: list[str]
    version: str
    snapshot: str
    audits: list[Audited] | None = None
    notes: list[str] = field(default_factory=list)
    pending: Pending | None = None
    nothing: str | None = None


def flag(env: Mapping[str, str], name: str) -> bool:
    value = env.get(name, "").strip().lower()
    if value in TRUE:
        return True
    if value in FALSE:
        return False
    raise ValueError(f"{name} must be true or false, not {value!r}")


def sha(value) -> str:
    if not isinstance(value, str) or len(value) not in (40, 64) or not set(value) <= HEX:
        raise ValueError("the event payload gives no commit SHA for the pull request's base")
    return value


def handles(people, key: str, prefix: str = "") -> list[str]:
    out = []
    for p in people or []:
        if isinstance(p, dict) and isinstance(p.get(key), str):
            out.append("@" + prefix + p[key])
    return out


def pull_of(event: dict, repository: str) -> Pull | None:
    pr = event.get("pull_request") if isinstance(event, dict) else None
    if not isinstance(pr, dict):
        return None
    gh.repository(repository)
    number = pr.get("number")
    if not isinstance(number, int) or isinstance(number, bool) or number < 1:
        raise ValueError("the event payload gives no pull request number")
    base, head = pr.get("base") or {}, pr.get("head") or {}
    base_repo, head_repo = base.get("repo") or {}, head.get("repo")
    fork = not isinstance(head_repo, dict) or head_repo.get("full_name") != base_repo.get("full_name", repository)
    owner = repository.split("/")[0]
    requested = handles(pr.get("requested_reviewers"), "login") + handles(pr.get("requested_teams"), "slug", owner + "/")
    return Pull(repository, number, sha(base.get("sha")), fork, tuple(sorted(set(requested))), gh.login(pr.get("user")))


def text(value) -> str:
    plain = "".join(" " if c.isspace() or unicodedata.category(c) in ("Cc", "Cf", "Co", "Cs") else c for c in str(value))
    out = []
    for c in html.escape(" ".join(plain.split()), quote=False):
        if c in ESCAPED:
            out.append("\\" + c)
        elif c == "@":
            out.append("@" + JOINER)
        else:
            out.append(c)
    return "".join(out)


def code(value) -> str:
    return f"<code>{text(value)}</code>"


def table(head: list[str], rows: list[list[str]]) -> list[str]:
    return ["| " + " | ".join(head) + " |", "|" + "---|" * len(head), *("| " + " | ".join(r) + " |" for r in rows), ""]


def cut(items: list, rows: int, what: str) -> tuple[list, list[str]]:
    rest = len(items) - min(len(items), rows)
    return items[:rows], ([f"{rest} more {what} not shown here; `decisis check` locally lists them all.", ""] if rest else [])


def where(r: dict) -> str:
    return f"{r['file']}:{r['line']}" if r.get("line") else r["file"]


def results(heading: str, found: list[dict], rows: int) -> list[str]:
    if not found:
        return []
    shown, rest = cut(found, rows, "results")
    body = table(["File", "Decision", "Rule", "Why"], [[code(where(r)), code(r["decision"]), code(r["rule"]), text(r["why"])] for r in shown])
    return [f"#### {heading} ({len(found)})", "", *(body if shown else []), *rest]


def expiry(w: dict) -> str:
    return text(f"{w.get('expires')}, approved by {w.get('approved_by')}: {w.get('reason')}")


def waived_results(found: list[dict], rows: int) -> list[str]:
    if not found:
        return []
    shown, rest = cut(found, rows, "waived results")
    body = table(["File", "Decision", "Rule", "Why", "Waived until"],
                 [[code(where(r)), code(r["decision"]), code(r["rule"]), text(r["why"]), expiry(r.get("waiver") or {})] for r in shown])
    return [f"#### Waived, not counted as violations ({len(found)})", "", *(body if shown else []), *rest]


def files_cell(files: list[str]) -> str:
    shown = ", ".join(code(f) for f in files[:5])
    return shown + (f" and {len(files) - 5} more" if len(files) > 5 else "")


def decisions(report: dict, rows: int) -> list[str]:
    gov = report["governing"]
    out = [f"#### Decisions touched ({len(gov)})", ""]
    if not gov:
        return out + ["No decision in the snapshot governs a changed file.", ""]
    shown, rest = cut(gov, rows, "decisions")
    if shown:
        out += table(["Decision", "Title", "Changed files"], [[code(g["decision"]), text(g["title"]), files_cell(g["files"])] for g in shown])
    out += rest
    sup = report.get("superseded") or []
    if sup:
        shown, rest = cut(sup, rows, "superseded decisions")
        out += [f"Superseded, not judged: {', '.join(code(g['decision']) for g in shown)}", "", *rest]
    return out


def problems(found: list[dict], rows: int) -> list[str]:
    if not found:
        return []
    shown, rest = cut(found, rows, "rule problems")
    return [f"#### Rules that cannot be checked ({len(found)})", "",
            *(f"- {code(p['decision'])} {code(p.get('rule') or 'rule')}: {text(p['problem'])}" for p in shown), "", *rest]


def unread(found: list[dict], rows: int) -> list[str]:
    if not found:
        return []
    shown, rest = cut(found, rows, "decision files not read")
    return [f"#### Decision files not read ({len(found)})", "",
            "These ADRs are not in the snapshot, so their rules are not judged. Fix each file and run again.", "",
            *(f"- {code(u['file'])}: {text(u['reason'])}" for u in shown), "", *rest]


def audit_rows(report: dict, verdict: str = "violated") -> list[list[str]]:
    out = []
    for f in report.get("findings", []):
        what = f.get("advisory") or f"{f.get('kind') or 'package'} rule"
        for p in f.get("policies", []):
            if p.get("verdict") == verdict:
                row = [code(f["package"]), code(what), code(p.get("decision")), text(p.get("why") or "")]
                out.append(row + [expiry(p.get("waiver") or {})] if verdict == rules.WAIVED else row)
    return out


def audit_section(a: Audited, rows: int) -> list[str]:
    out = [f"#### Audit of {code(a.inventory)}", ""]
    if a.report is None:
        return out + [text(f"Not audited: {a.problem}"), ""]
    s = a.report.get("summary") or {}
    out += [text(f"{s.get('affected', 0)} affected, {s.get('unresolved', 0)} unresolved, {s.get('not_affected', 0)} not affected; "
                 f"{a.report.get('violations', 0)} violation(s) of a decision."), ""]
    shown, rest = cut(audit_rows(a.report), rows, "audit violations")
    if shown:
        out += table(["Package", "Advisory or rule", "Decision", "Why"], shown)
    out += rest
    excused = audit_rows(a.report, rules.WAIVED)
    if excused:
        shown, rest = cut(excused, rows, "waived audit findings")
        out += [f"Waived, not counted as violations ({len(excused)}):", ""]
        out += (table(["Package", "Advisory or rule", "Decision", "Why", "Waived until"], shown) if shown else []) + rest
    return out + problems(a.report.get("rule_problems") or [], rows)


def audit_violations(audits: list[Audited] | None) -> int:
    return sum(a.report.get("violations", 0) for a in audits or [] if a.report is not None)


def graphs(o: Outcome) -> list[str]:
    governed = [r for r in o.report["impact"] if r.get("governing") or r.get("superseded")]
    out = ["<details><summary>Path graph</summary>", "", render.mermaid("check", {**o.report, "impact": governed})]
    out += [render.mermaid("audit", a.report) for a in o.audits or [] if a.report is not None]
    return out + ["</details>", ""]


def reviewers_line(o: Outcome, rows: int) -> list[str]:
    shown, _ = cut(o.approved, rows, "")
    counted = ", ".join(code(h) for h in shown) or ("none" if not o.approved else f"{len(o.approved)}, not listed")
    if shown and len(o.approved) > len(shown):
        counted += f" and {len(o.approved) - len(shown)} more"
    line = f"Reviewers counted (latest review approves): {counted}."
    if o.pull.requested:
        req, _ = cut(list(o.pull.requested), rows, "")
        more = f" and {len(o.pull.requested) - len(req)} more" if len(o.pull.requested) > len(req) else ""
        line += f" Requested, not counted until they approve: {', '.join(code(h) for h in req) or 'not shown'}{more}."
    return [line, ""]


def pending(o: Outcome, rows: int) -> list[str]:
    p = o.pending
    if p is None:
        return []
    shown, rest = cut(p.files, rows, "files")
    out = [f"#### Decision changes that take effect once merged ({len(p.files)})", "",
           "This pull request changes files the decisions come from. This run read the decisions from the base commit, so "
           "these changes take effect once the pull request is merged and change no verdict here.", "",
           *(f"- {code(f)}" for f in shown), *([""] if shown else []), *rest]
    if p.changes is None:
        return out + ["The decisions cannot be read on both sides, so the decisions and waivers that change are not named.", ""]
    if not p.changes:
        return out + ["No decision or waiver is added, changed or removed.", ""]
    shown, rest = cut(p.changes, rows, "decision changes")
    if shown:
        out += table(["Decision", "Waiver", "Change"],
                     [[code(c["decision"]), code(c["waiver"]) if c.get("waiver") else "", text(c["change"])] for c in shown])
    return out + rest


def nothing_judged(o: Outcome, rows: int) -> str:
    lines = [MARKER, "### decisis", "",
             f"**No decisions exist on the base commit {code(o.pull.base[:12])} yet**, so nothing was judged in "
             f"{len(o.report['changed'])} changed file(s).", "", text(o.nothing), ""]
    lines += [f"> {text(n)}" for n in o.notes] + ([""] if o.notes else [])
    lines += pending(o, rows)
    lines.append(f"<sub>decisis {text(o.version)}, snapshot {code(o.snapshot)}. This comment is updated on each run.</sub>")
    return "\n".join(lines) + "\n"


def compose(o: Outcome, rows: int, graph: bool) -> str:
    if o.nothing is not None:
        return nothing_judged(o, rows)
    r = o.report
    head = (f"**{len(r['governing'])} decision(s) touched, {len(r['violations'])} violation(s)"
            + (f", {audit_violations(o.audits)} audit violation(s)" if o.audits is not None else "")
            + f", {len(r['unresolved'])} that cannot be judged"
            + (f", {len(r['waived'])} waived" if r.get("waived") else "")
            + (f", {len(r['unread_decisions'])} decision file(s) not read" if r.get("unread_decisions") else "")
            + f"** in {len(r['changed'])} changed file(s) against {code(o.pull.base[:12])}.")
    lines = [MARKER, "### decisis", "", head, "", *reviewers_line(o, rows)]
    if (rows, graph) != ATTEMPTS[0]:
        lines += [f"Cut to fit GitHub's {MAX_BODY:,}-character limit for a comment: "
                  + ("the graph is left out and " if not graph else "") + f"each list shows at most {rows} rows.", ""]
    lines += [f"> {text(n)}" for n in o.notes] + ([""] if o.notes else [])
    lines += pending(o, rows)
    lines += results("Violations", r["violations"], rows)
    lines += waived_results(r.get("waived") or [], rows)
    lines += decisions(r, rows)
    lines += results("Cannot be judged", r["unresolved"], rows)
    lines += problems(r.get("rule_problems") or [], rows)
    lines += unread(r.get("unread_decisions") or [], rows)
    for a in o.audits or []:
        lines += audit_section(a, rows)
    if graph:
        lines += graphs(o)
    lines.append(f"<sub>decisis {text(o.version)}, snapshot {code(o.snapshot)}. This comment is updated on each run.</sub>")
    return "\n".join(lines) + "\n"


def body(o: Outcome) -> str:
    for rows, graph in ATTEMPTS:
        out = compose(o, rows, graph)
        if len(out) <= MAX_BODY:
            return out
    tail = "\n\nThe comment was cut at GitHub's limit.\n"
    return out[:MAX_BODY - len(tail)].rpartition("\n")[0] + tail


def approvals(client: gh.Client, pull: Pull) -> tuple[list[str], str | None]:
    reviews, cut_note = [], None
    for review in client.pages(f"{gh.API}/repos/{pull.repo}/pulls/{pull.number}/reviews?per_page={gh.PER_PAGE}", gh.MAX_REVIEWS):
        if review is None:
            cut_note = (f"The pull request has more than {gh.MAX_REVIEWS:,} reviews, so decisis did not read them all and counts "
                        "no approval: a later review could withdraw one. A review rule shows a violation until a reviewer checks it.")
            return [], cut_note
        reviews.append(review)
    return ["@" + who for who in gh.approvers(reviews, pull.author)], cut_note


def existing(client: gh.Client, pull: Pull, author: str) -> int | None:
    for c in client.pages(f"{gh.API}/repos/{pull.repo}/issues/{pull.number}/comments?per_page={gh.PER_PAGE}", MAX_COMMENTS):
        if c is None:
            raise TooManyComments(f"the pull request has more than {MAX_COMMENTS:,} comments; decisis did not look further for its "
                                  "own comment and did not post a new one")
        body_text, cid = c.get("body"), c.get("id")
        if gh.login(c.get("user")) == author and isinstance(body_text, str) and body_text.startswith(MARKER) \
                and isinstance(cid, int) and not isinstance(cid, bool):
            return cid
    return None


def send(client: gh.Client, method: str, url: str, payload: dict) -> dict:
    req = client.request(url)
    req.method = method
    req.data = json.dumps(payload).encode("utf-8")
    req.add_header("Content-Type", "application/json")
    try:
        with (client.opener or gh.default_opener())(req, timeout=gh.TIMEOUT) as resp:
            data = resp.read(gh.MAX_BYTES + 1)
    except urllib.error.HTTPError as e:
        limited = (e.headers or {}).get("x-ratelimit-remaining") == "0"
        if e.code in (403, 404) and not limited:
            raise ReadOnly(client.redact(f"GitHub answered {method} {url} with HTTP {e.code} {e.reason}")) from None
        raise client.http_error(url, e) from None
    except gh.GitHubFailed as e:
        raise client.fail(str(e)) from None
    except (OSError, ValueError) as e:
        raise client.fail(f"could not reach GitHub at {url} ({getattr(e, 'reason', None) or str(e) or type(e).__name__})") from None
    try:
        answer = json.loads(data)
    except (ValueError, UnicodeDecodeError):
        raise client.fail(f"GitHub's answer to {method} {url} is not JSON") from None
    return answer if isinstance(answer, dict) else {}


def post(client: gh.Client, pull: Pull, text_body: str, author: str = AUTHOR) -> str:
    cid = existing(client, pull, author)
    if cid is None:
        answer = send(client, "POST", f"{gh.API}/repos/{pull.repo}/issues/{pull.number}/comments", {"body": text_body})
    else:
        answer = send(client, "PATCH", f"{gh.API}/repos/{pull.repo}/issues/comments/{cid}", {"body": text_body})
    link = answer.get("html_url")
    return link if isinstance(link, str) else ""


def fetch_base(root: Path, base: str) -> None:
    shallow = codeowners.git(root, "rev-parse", "--is-shallow-repository", timeout=check.GIT_SECONDS)
    if shallow.returncode == 0 and shallow.stdout.strip() == b"true":
        done = codeowners.git(root, "fetch", "--no-tags", "--quiet", "--unshallow", "origin", timeout=FETCH_SECONDS)
    elif codeowners.git(root, "cat-file", "-e", f"{base}^{{commit}}", timeout=check.GIT_SECONDS).returncode != 0:
        done = codeowners.git(root, "fetch", "--no-tags", "--quiet", "origin", base, timeout=FETCH_SECONDS)
    else:
        return
    if done.returncode != 0:
        raise ValueError(f"git fetch of the base commit {base} failed in {root}; check out with fetch-depth: 0")


def given(env: Mapping[str, str]) -> str:
    path, built = env.get("DECISIS_SNAPSHOT", "").strip(), flag(env, "DECISIS_INIT")
    if bool(path) == built:
        raise ValueError("give the snapshot input or init: true, not both and not neither")
    return path


def decisions_from(env: Mapping[str, str]) -> str:
    value = env.get("DECISIS_DECISIONS_FROM", "").strip().lower() or BASE
    if value not in (BASE, HEAD):
        raise ValueError(f"DECISIS_DECISIONS_FROM must be base or head, not {value!r}")
    return value


def snapshot_of(env: Mapping[str, str], root: Path, repo: str | None) -> tuple[object, str]:
    path = given(env)
    if not path:
        return co.load(init.dump(init.build(root, repo))), "built with decisis init"
    return co.load(Path(path).read_text(encoding="utf-8")), path


def listing(root: Path, base: str) -> list[str]:
    head = codeowners.git_files(root)
    return sorted(set(committed.names(root, base)) | set(head if head is not None else codeowners.walk_files(root)))


def at(root: Path, commit: str, snapshot: str, repo: str | None, files: list[str] | None):
    if snapshot:
        return committed.stored(root, commit, snapshot)
    return committed.built(root, commit, repo, files or [])


def from_base(env: Mapping[str, str], root: Path, repo: str | None, base: str, changed: list[str]):
    path = given(env)
    snapshot = committed.inside(root, path) if path else ""
    files = None if snapshot else listing(root, base)
    graph = at(root, base, snapshot, repo, files)
    source = f"{snapshot} at the base commit" if snapshot else "built with decisis init from the base commit"
    sources = committed.source_files(changed, snapshot or None)
    if not sources:
        return graph, source, None
    try:
        head = at(root, "HEAD", snapshot, repo, files)
    except (ValueError, KeyError, TypeError, OSError, subprocess.TimeoutExpired) as e:
        say(f"the decisions in HEAD cannot be read, so their changes are not named: {reason(e)}")
        head = None
    return graph, source, Pending(sources, committed.changes(graph, head) if graph is not None and head is not None else None)


def no_decisions(env: Mapping[str, str], graph) -> str:
    if graph is None:
        return (f"The base commit has no snapshot file at {env.get('DECISIS_SNAPSHOT', '').strip()}. Decisions are read from the "
                "base commit, so they apply once a pull request that adds them is merged.")
    return ("The base commit has no ADR with a decision. Decisions are read from the base commit, so they apply once a pull "
            "request that adds them is merged.")


def reason(e: Exception) -> str:
    return " ".join(str(e).split()) or type(e).__name__


def identity(path: Path) -> Path:
    try:
        return path.resolve()
    except RuntimeError:
        return Path(os.path.abspath(path))


def lockfile(name: str) -> bool:
    return name in LOCKFILES or (name.startswith("requirements") and name.endswith(".txt"))


def workflow_in(root: Path) -> str | None:
    folder = Path(directory_resolver(root, root)(WORKFLOWS))
    if not folder.is_dir():
        return None
    read = directory_reader(root / WORKFLOWS, root)
    for name in sorted(p.name for p in folder.iterdir() if p.name.endswith(workflows.SUFFIXES)):
        try:
            body = read(name)
        except (ValueError, OSError):
            continue
        if body is not None and name not in workflows.ACTION_FILES and workflows.workflow(clean(body)):
            return f"{WORKFLOWS}/{name}"
    return None


def found(root: Path) -> list[tuple[str, str | None, str | None]]:
    out: list[tuple[str, str | None, str | None]] = [(name, name, None) for name in sorted(p.name for p in root.iterdir() if lockfile(p.name))]
    try:
        first = workflow_in(root)
    except (ValueError, OSError) as e:
        return out + [(WORKFLOWS, None, reason(e))]
    return out + ([(WORKFLOWS, first, None)] if first else [])


def audit_file(graph, path: Path, repo: str, advisories, root: Path | None = None, day=None) -> dict:
    lock_text, siblings = inventory.load(path, root=root)
    return audit.run(graph, lock_text, repo, advisories=advisories, filename=path.name, siblings=siblings, day=day)


def audit_found(graph, root: Path, name: str, repo: str, advisories, day=None) -> dict:
    real = Path(directory_resolver(root, root)(name))
    if not real.is_file():
        raise ValueError(f"{name} is not a file")
    return audit_file(graph, root / name, repo, advisories, root, day)


def audits(env: Mapping[str, str], graph, repo: str, root: Path, day=None) -> tuple[list[Audited] | None, bool]:
    lines = [line.strip() for line in env.get("DECISIS_INVENTORY", "").splitlines() if line.strip()]
    if not lines:
        return None, False
    advisories = external.fetch_advisories
    cache = env.get("DECISIS_OSV_CACHE", "").strip()
    if cache:
        advisories = external.cached_advisories(external.read_osv_cache(Path(cache).read_text(encoding="utf-8")))
    out: list[Audited] = []
    seen: set[Path] = set()
    empty = False
    for line in lines:
        if line != AUTO:
            if identity(Path(line)) not in seen:
                seen.add(identity(Path(line)))
                out.append(Audited(line, audit_file(graph, Path(line), repo, advisories, day=day)))
            continue
        here = found(root)
        empty = empty or not here
        for label, name, problem in here:
            key = identity(root / (name or label))
            if key in seen:
                continue
            seen.add(key)
            if problem is None:
                try:
                    out.append(Audited(label, audit_found(graph, root, name, repo, advisories, day)))
                    continue
                except (ValueError, OSError) as e:
                    problem = reason(e)
            out.append(Audited(label, problem=problem))
            say(f"{label} was not audited: {problem}")
    return out, empty


def version() -> str:
    try:
        return metadata.version("decisis")
    except metadata.PackageNotFoundError:
        return "unknown"


def say(message: str) -> None:
    print("decisis: " + " ".join("".join(" " if unicodedata.category(c)[0] == "C" else c for c in message).split()), flush=True)


def append(path: str | None, content: str) -> None:
    if path:
        with open(path, "a", encoding="utf-8") as f:
            f.write(content)


def run(env: Mapping[str, str], opener: Callable | None = None) -> int:
    if not env.get("GITHUB_EVENT_PATH"):
        raise ValueError("GITHUB_EVENT_PATH is not set; decisis.action runs inside a GitHub Actions job")
    payload = json.loads(Path(env["GITHUB_EVENT_PATH"]).read_text(encoding="utf-8"))
    pull = pull_of(payload, env.get("GITHUB_REPOSITORY", ""))
    if pull is None:
        append(env.get("GITHUB_STEP_SUMMARY"), "decisis comments on pull_request events; this run has no pull request.\n")
        say("this event has no pull request; nothing was checked")
        return 0
    root = Path(env.get("DECISIS_WORKING_DIRECTORY", "").strip() or ".")
    if not root.is_dir():
        raise ValueError(f"working-directory {root} is not a directory")
    repo = env.get("DECISIS_REPO", "").strip() or None
    mode, waiting = decisions_from(env), None
    if mode == HEAD:
        graph, source = snapshot_of(env, root, repo)
        fetch_base(root, pull.base)
        changed = check.changed_since(root, pull.base)
    else:
        given(env)
        fetch_base(root, pull.base)
        changed = check.changed_since(root, pull.base)
        graph, source, waiting = from_base(env, root, repo, pull.base, changed)
    client = gh.Client(gh.clean_token(env.get("DECISIS_TOKEN")), opener)
    day = rules.today(env.get("DECISIS_TODAY", "").strip() or None)
    if waiting is not None:
        say(f"{len(waiting.files)} changed file(s) hold decisions; they take effect once merged")
    if mode == BASE and not committed.has_decisions(graph):
        return unjudged(env, client, Outcome({"changed": changed}, pull, [], version(), source, pending=waiting,
                                             nothing=no_decisions(env, graph)))
    approved, review_note = approvals(client, pull)
    report = check.run(graph, changed, root, approved, repo=repo, base=pull.base, day=day)
    done, empty = audits(env, graph, repo or pull.repo.split("/")[1], root, day)
    outcome = Outcome(report, pull, approved, version(), source, done, pending=waiting)
    if review_note:
        outcome.notes.append(review_note)
    if empty:
        outcome.notes.append("inventory: auto found no inventory in the repository root, so it audited nothing there.")
    link = publish(env, client, outcome)
    violations = len(report["violations"]) + audit_violations(done)
    append(env.get("GITHUB_OUTPUT"), f"violations={violations}\ncomment-url={link}\n")
    say(f"{len(report['governing'])} decision(s) touched, {violations} violation(s)")
    return 1 if violations and flag(env, "DECISIS_FAIL_ON_VIOLATION") else 0


def unjudged(env: Mapping[str, str], client: gh.Client, outcome: Outcome) -> int:
    flag(env, "DECISIS_FAIL_ON_VIOLATION")
    link = publish(env, client, outcome)
    append(env.get("GITHUB_OUTPUT"), f"violations=0\ncomment-url={link}\n")
    say("the base commit has no decisions yet; nothing was judged")
    return 0


def publish(env: Mapping[str, str], client: gh.Client, outcome: Outcome) -> str:
    pull = outcome.pull
    if pull.fork:
        outcome.notes.append("This pull request comes from a fork, so its token cannot comment; the result is in the job summary.")
    text_body = body(outcome)
    append(env.get("GITHUB_STEP_SUMMARY"), text_body)
    link = ""
    if not pull.fork:
        try:
            link = post(client, pull, text_body, env.get("DECISIS_COMMENT_AUTHOR", "").strip() or AUTHOR)
            say(f"comment {link or 'written'}")
        except ReadOnly as e:
            say(f"{e}; the token cannot comment, so the result is only in the job summary")
        except TooManyComments as e:
            append(env.get("GITHUB_STEP_SUMMARY"), f"\n> {text(e)}.\n")
            say(f"{e}; the result is only in the job summary")
    else:
        say("fork pull request; the result is in the job summary")
    return link


def main(env: Mapping[str, str] | None = None, opener: Callable | None = None) -> int:
    env = os.environ if env is None else env
    try:
        return run(env, opener)
    except (ValueError, OSError, subprocess.TimeoutExpired, gh.GitHubFailed, gh.RateLimited,
            external.NetworkRefused, external.NetworkFailed, LimitExceeded) as e:
        message = f"error: {e}"
        append(env.get("GITHUB_STEP_SUMMARY"), f"decisis could not check this pull request: {text(e)}\n")
        say(message)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
