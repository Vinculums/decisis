"""Read decisions from a repository's merged pull requests through the GitHub REST API.

`PullReader` binds `read_pulls` to one repository and its options and is an `init` reader: it takes a `Tree`
and returns `(nodes, edges)`. Its repr leaves out the token. It sends only GET requests, only to api.github.com, and sends
the token only in the Authorization header. A rate limit stops the read; what was read before it is kept
and the stop is listed in `meta.problems`. docs/data-model.md lists the fields each pull request gives.
"""
from __future__ import annotations

import hashlib
import http.client
import json
import re
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from datetime import date, datetime, timezone
from typing import Callable, Iterator

from .impact import code_path
from .init import KEPT, NOT_READ, SKIPPED, Tree, markdown, slug

HOST = "api.github.com"
API = f"https://{HOST}"
API_VERSION = "2022-11-28"
PER_PAGE = 100
DEFAULT_LIMIT = 100
MAX_LIMIT = 5000
MAX_FILES = 3000
MAX_REVIEWS = 1000
MAX_BYTES = 20 * 1024 * 1024
TIMEOUT = 30
OWNER = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})")
NAME = re.compile(r"[A-Za-z0-9._-]{1,100}")
TOKEN = re.compile(r"[\x21-\x7e]+")
NEXT = re.compile(r'<([^>]+)>\s*;\s*rel="next"')
COMMENT = re.compile(r"<!--.*?(?:-->|$)", re.S)
DECISION_SECTIONS = ("decision", "decision outcome")
REVIEW_STATES = ("APPROVED", "CHANGES_REQUESTED", "DISMISSED")


class GitHubFailed(RuntimeError):
    pass


class RateLimited(Exception):
    pass


def repository(text: str) -> tuple[str, str]:
    owner, sep, name = text.partition("/")
    if not sep or not OWNER.fullmatch(owner) or not NAME.fullmatch(name) or name in (".", ".."):
        raise ValueError(f"--github {text!r} must be OWNER/REPO, for example Vinculums/decisis")
    return owner, name


def since_date(text: str) -> date:
    try:
        return date.fromisoformat(text)
    except ValueError:
        raise ValueError(f"--since {text!r} must be a date such as 2026-01-31") from None


def clean_token(token: str | None) -> str | None:
    token = (token or "").strip()
    if not token:
        return None
    if not TOKEN.fullmatch(token):
        raise GitHubFailed("GITHUB_TOKEN holds a space, a line break or a character outside printable ASCII; "
                           "its value is not shown")
    return token


def on_api(url: str) -> bool:
    parts = urllib.parse.urlsplit(url)
    try:
        port = parts.port
    except ValueError:
        return False
    return parts.scheme == "https" and parts.hostname == HOST and port in (None, 443) and not parts.username and not parts.password


class SameHost(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        target = urllib.parse.urljoin(req.full_url, newurl)
        if not on_api(target):
            raise GitHubFailed(f"GitHub redirected {req.full_url} to another host ({urllib.parse.urlsplit(target).hostname}); "
                               "the redirect was not followed")
        return super().redirect_request(req, fp, code, msg, headers, target)


def default_opener() -> Callable:
    return urllib.request.build_opener(SameHost()).open


@dataclass
class Client:
    token: str | None = field(default=None, repr=False)
    opener: Callable | None = None

    def redact(self, text: str) -> str:
        return text.replace(self.token, "[token]") if self.token else text

    def fail(self, message: str) -> GitHubFailed:
        return GitHubFailed(self.redact(message))

    def request(self, url: str) -> urllib.request.Request:
        if not on_api(url):
            raise self.fail(f"refused to send a request to {url}: decisis sends requests only to {API}")
        headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": API_VERSION, "User-Agent": "decisis"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        return urllib.request.Request(url, headers=headers, method="GET")

    def get(self, url: str) -> tuple[object, str | None]:
        req = self.request(url)
        try:
            with (self.opener or default_opener())(req, timeout=TIMEOUT) as resp:
                final = resp.geturl()
                if final and not on_api(final):
                    raise self.fail(f"GitHub answered {url} from another host; the answer was not read")
                data = resp.read(MAX_BYTES + 1)
                link = resp.headers.get("Link")
        except urllib.error.HTTPError as e:
            raise self.http_error(url, e) from None
        except GitHubFailed as e:
            raise self.fail(str(e)) from None
        except (OSError, ValueError, http.client.HTTPException) as e:
            raise self.fail(f"could not reach GitHub at {url} ({getattr(e, 'reason', None) or str(e) or type(e).__name__})") from None
        if len(data) > MAX_BYTES:
            raise self.fail(f"GitHub's answer to {url} is over {MAX_BYTES} bytes; it was not read")
        try:
            return json.loads(data), next_page(link)
        except (ValueError, UnicodeDecodeError):
            raise self.fail(f"GitHub's answer to {url} is not JSON") from None
        except RecursionError:
            raise self.fail(f"GitHub's answer to {url} is JSON nested too deeply to read") from None

    def http_error(self, url: str, e: urllib.error.HTTPError) -> Exception:
        headers = e.headers or {}
        limited = headers.get("x-ratelimit-remaining") == "0" or headers.get("retry-after")
        if e.code == 429 or (e.code == 403 and limited):
            return RateLimited(self.redact(rate_message(url, headers, bool(self.token))))
        hints = {401: "GitHub refused the token in GITHUB_TOKEN",
                 404: "GitHub has no such repository or pull request, or the token cannot see it"}
        return self.fail(f"GitHub answered {url} with HTTP {e.code} {e.reason}" + (f": {hints[e.code]}" if e.code in hints else ""))

    def pages(self, url: str, cap: int) -> Iterator[dict | None]:
        seen = 0
        while url:
            items, url = self.get(url)
            if not isinstance(items, list) or not all(isinstance(i, dict) for i in items):
                raise self.fail("GitHub returned something other than a list of objects")
            room = cap - seen
            yield from items[:room]
            seen += min(len(items), room)
            if len(items) > room or (url and seen >= cap):
                yield None
                return


def next_page(link: str | None) -> str | None:
    m = NEXT.search(link or "")
    return m.group(1) if m else None


def rate_message(url: str, headers, has_token: bool) -> str:
    reset = headers.get("x-ratelimit-reset")
    when = ""
    if reset and reset.isdigit():
        when = "; it resets at " + datetime.fromtimestamp(int(reset), timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    elif headers.get("retry-after"):
        when = f"; GitHub asks to wait {headers.get('retry-after')} seconds"
    hint = "" if has_token else "; set GITHUB_TOKEN for a higher limit"
    return f"GitHub's rate limit stopped the read at {url}{when}{hint}"


def label_names(pr: dict) -> list[str]:
    return sorted(lbl["name"] for lbl in pr.get("labels") or [] if isinstance(lbl, dict) and isinstance(lbl.get("name"), str))


def selected(pr: dict, label: str) -> bool:
    return label.lower() in {n.lower() for n in label_names(pr)} or decision_text(pr.get("body")) is not None


def decision_text(body) -> str | None:
    if not isinstance(body, str):
        return None
    sections = markdown(COMMENT.sub("", body.replace("\r\n", "\n"))).sections
    for name in DECISION_SECTIONS:
        text = "\n".join(line.rstrip() for line in sections.get(name, [])).strip()
        if text:
            return text
    return None


def login(user) -> str | None:
    return user.get("login") if isinstance(user, dict) and isinstance(user.get("login"), str) else None


def approvers(reviews: list[dict], author: str | None) -> list[str]:
    last: dict[str, str] = {}
    for review in reviews:
        who, state = login(review.get("user")), review.get("state")
        if who and state in REVIEW_STATES:
            last[who] = state
    return sorted(who for who, state in last.items() if state == "APPROVED" and who != author)


@dataclass
class Pulls:
    owner: str
    name: str
    client: Client
    tree: Tree

    @property
    def key(self) -> str:
        return repo_key(self.owner, self.name)

    @property
    def where(self) -> str:
        return f"github:{self.owner}/{self.name}"

    def at(self, pr: dict) -> str:
        return f"{self.where}#{pr['number']}"

    def url(self, path: str, **query) -> str:
        base = f"{API}/repos/{urllib.parse.quote(self.owner)}/{urllib.parse.quote(self.name)}{path}"
        return base + ("?" + urllib.parse.urlencode(query) if query else "")

    def merged(self, label: str, since: date | None, limit: int) -> Iterator[dict]:
        url = self.url("/pulls", state="closed", sort="updated", direction="desc", per_page=min(PER_PAGE, limit))
        floor = since.isoformat() if since else ""
        for pr in self.client.pages(url, limit):
            if pr is None:
                self.tree.problem(self.where, f"stopped after {limit} closed pull requests (--limit); older ones were not read", NOT_READ)
                return
            if str(pr.get("updated_at") or "")[:10] < floor:
                return
            merged_at = pr.get("merged_at")
            if not isinstance(pr.get("number"), int) or not isinstance(merged_at, str) or merged_at[:10] < floor:
                continue
            if selected(pr, label):
                yield pr

    def files(self, pr: dict) -> list[str]:
        listed = [f.get("filename") for f in self.client.pages(self.url(f"/pulls/{pr['number']}/files", per_page=PER_PAGE), MAX_FILES) if f]
        if len(listed) >= MAX_FILES:
            self.tree.problem(self.at(pr), f"GitHub lists at most {MAX_FILES} changed files of a pull request; files past that are not in code_ref", KEPT)
        return sorted({f for f in listed if isinstance(f, str)})

    def reviews(self, pr: dict) -> list[dict]:
        listed = list(self.client.pages(self.url(f"/pulls/{pr['number']}/reviews", per_page=PER_PAGE), MAX_REVIEWS))
        if None in listed:
            self.tree.problem(self.at(pr), f"decisis reads at most {MAX_REVIEWS} reviews of a pull request; reviews past that "
                                           "are not read, so deciders can miss an approval", NOT_READ)
        return [r for r in listed if r]

    def node(self, pr: dict) -> dict:
        files, reviews = self.files(pr), self.reviews(pr)
        author = login(pr.get("user"))
        refs = []
        for path in files:
            p = code_path(path)
            if ":" in path:
                self.tree.problem(self.at(pr), f"its changed file {path!r} has a colon, which a code_ref reads as a repository "
                                               "prefix or as the end of the path; it is not in code_ref", SKIPPED)
                continue
            if path.startswith("/") or p is None or ".." in p.split("/"):
                self.tree.problem(self.at(pr), f"its changed file {path!r} is not a path relative to the repository root", SKIPPED)
                continue
            refs.append(self.tree.ref(path))
        source = f"https://github.com/{self.owner}/{self.name}/pull/{pr['number']}"
        props = {"source": source, "valid_from": pr["merged_at"], "content_hash": digest(pr, files, reviews)}
        if statement := decision_text(pr.get("body")):
            props["statement"] = statement
        deciders = ([author] if author else []) + approvers(reviews, author)
        if deciders:
            props["deciders"] = ["@" + d for d in deciders]
        if refs:
            props["code_ref"] = refs
        else:
            self.tree.problem(self.at(pr), "it changes no file GitHub listed", KEPT)
        title = pr.get("title") if isinstance(pr.get("title"), str) and pr["title"].strip() else f"Pull request #{pr['number']}"
        nid = f"decision:github-{slug(self.owner)}-{slug(self.name)}-{self.key}-pr-{pr['number']}"
        return {"id": nid, "kind": "decision", "title": title, "props": props}


def repo_key(owner: str, name: str) -> str:
    return hashlib.sha256(f"{owner}/{name}".lower().encode("utf-8")).hexdigest()[:8]


def digest(pr: dict, files: list[str], reviews: list[dict]) -> str:
    keep = {k: pr.get(k) for k in ("number", "title", "body", "merged_at", "merge_commit_sha")}
    keep["labels"] = label_names(pr)
    keep["user"] = login(pr.get("user"))
    keep["files"] = files
    keep["reviews"] = [[login(r.get("user")), r.get("state")] for r in reviews]
    data = json.dumps(keep, ensure_ascii=False, sort_keys=True).encode("utf-8")
    return "sha256:" + hashlib.sha256(data).hexdigest()


def read_pulls(tree: Tree, repo: str, token: str | None = None, label: str = "decision", since: date | None = None,
               limit: int = DEFAULT_LIMIT, opener: Callable | None = None) -> tuple[list[dict], list[dict]]:
    owner, name = repository(repo)
    if not 1 <= limit <= MAX_LIMIT:
        raise ValueError(f"--limit {limit} is outside 1 to {MAX_LIMIT}")
    pulls = Pulls(owner, name, Client(clean_token(token), opener), tree)
    nodes: list[dict] = []
    try:
        for pr in pulls.merged(label, since, limit):
            nodes.append(pulls.node(pr))
    except RateLimited as e:
        tree.problem(pulls.where, f"{e}; kept the {len(nodes)} pull request(s) read before it", NOT_READ)
    except RecursionError:
        raise GitHubFailed(f"GitHub's answers for {pulls.where} hold JSON nested too deeply to read") from None
    return nodes, []


@dataclass(frozen=True)
class PullReader:
    repo: str
    token: str | None = field(default=None, repr=False)
    label: str = "decision"
    since: date | None = None
    limit: int = DEFAULT_LIMIT
    opener: Callable | None = None

    def __call__(self, tree: Tree) -> tuple[list[dict], list[dict]]:
        return read_pulls(tree, self.repo, self.token, self.label, self.since, self.limit, self.opener)
