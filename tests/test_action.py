from __future__ import annotations

import email.message
import io
import json
import re
import shutil
import subprocess
import urllib.error
from pathlib import Path

import pytest
import yaml

from test_audit import no_network
from decisis import action, check
from decisis import checkout as co
from decisis import github as gh

ROOT = Path(__file__).resolve().parents[1]
REPO = "acme/shop"
API = f"https://api.github.com/repos/{REPO}"
TOKEN = "ghs_" + "Q7" * 18
HOSTILE = ("<script>alert(1)</script> | **bold** [click](javascript:alert(1)) @everyone ```\n## heading\n"
           "<!-- decisis --> $x$ :shipit: ‮drow \x00 <img src=x onerror=alert(1)>")
HOSTILE_PATH = "src/a|b`<img src=x>@everyone[x](y).py"


class Answer(io.BytesIO):
    def __init__(self, body: bytes, url: str, link: str | None = None):
        super().__init__(body)
        self.url = url
        self.headers = email.message.Message()
        if link:
            self.headers["Link"] = link

    def geturl(self) -> str:
        return self.url


class FakeGitHub:
    def __init__(self, reviews=(), pages=((),), refuse_writes: int | None = None):
        self.reviews = list(reviews)
        self.pages = [list(p) for p in pages]
        self.refuse_writes = refuse_writes
        self.sent: list[tuple[str, str, dict | None, dict]] = []

    def __call__(self, req, timeout=None):
        data = json.loads(req.data) if req.data else None
        self.sent.append((req.get_method(), req.full_url, data, dict(req.header_items())))
        url = req.full_url
        if url == f"{API}/pulls/7/reviews?per_page=100":
            return Answer(json.dumps(self.reviews).encode(), url)
        if url.startswith(f"{API}/issues/7/comments?per_page=100"):
            page = int(url.rpartition("&page=")[2]) if "&page=" in url else 1
            more = f'<{API}/issues/7/comments?per_page=100&page={page + 1}>; rel="next"' if page < len(self.pages) else None
            return Answer(json.dumps(self.pages[page - 1]).encode(), url, more)
        if req.get_method() in ("POST", "PATCH"):
            if self.refuse_writes:
                raise urllib.error.HTTPError(url, self.refuse_writes, "Forbidden", email.message.Message(),
                                             io.BytesIO(b'{"message": "Resource not accessible by integration"}'))
            return Answer(json.dumps({"id": 99, "html_url": "https://github.com/acme/shop/pull/7#issuecomment-99"}).encode(), url)
        raise AssertionError(f"unexpected request {req.get_method()} {url}")

    def writes(self) -> list[tuple[str, str, dict | None]]:
        return [(m, u, d) for m, u, d, _ in self.sent if m != "GET"]


def git(root: Path, *args: str) -> None:
    subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@example.com", "-c", "commit.gpgsign=false", "-C", str(root), *args],
                   check=True, capture_output=True)


def shop(tmp_path: Path) -> tuple[Path, str]:
    root = tmp_path / "shop"
    root.mkdir()
    git(root, "init", "-q", "-b", "main")
    (root / "README.md").write_text("shop\n")
    git(root, "add", "-A")
    git(root, "commit", "-q", "-m", "base")
    base = subprocess.run(["git", "-C", str(root), "rev-parse", "HEAD"], capture_output=True, text=True, check=True).stdout.strip()
    shutil.copytree(ROOT / "fixtures" / "check" / "repo", root, dirs_exist_ok=True)
    git(root, "add", "-A")
    git(root, "commit", "-q", "-m", "change")
    return root, base


def event(tmp_path: Path, base: str, fork: bool = False, requested=("ana",)) -> Path:
    head = {"full_name": "someone/shop" if fork else REPO, "fork": fork}
    payload = {"pull_request": {"number": 7, "base": {"sha": base, "repo": {"full_name": REPO}}, "head": {"repo": head},
                                "requested_reviewers": [{"login": r} for r in requested],
                                "requested_teams": [{"slug": "payments"}], "title": HOSTILE}}
    path = tmp_path / "event.json"
    path.write_text(json.dumps(payload))
    return path


def environment(tmp_path: Path, root: Path, base: str, **extra) -> dict:
    env = {"GITHUB_EVENT_PATH": str(event(tmp_path, base, extra.pop("fork", False))), "GITHUB_REPOSITORY": REPO,
           "GITHUB_STEP_SUMMARY": str(tmp_path / "summary.md"), "GITHUB_OUTPUT": str(tmp_path / "output.txt"),
           "DECISIS_SNAPSHOT": str(ROOT / "fixtures" / "check" / "vinc.json"), "DECISIS_WORKING_DIRECTORY": str(root),
           "DECISIS_TOKEN": TOKEN, "DECISIS_DECISIONS_FROM": "head"}
    env.update(extra)
    return env


def pull(**kw) -> action.Pull:
    return action.Pull(REPO, 7, "a" * 40, False, **kw)


def hostile_outcome() -> action.Outcome:
    snap = {"meta": {"space": "synthetic"},
            "nodes": [{"id": "concept:src", "kind": "concept", "title": HOSTILE, "props": {"code_ref": ["src/"]}},
                      {"id": "decision:hostile", "kind": "decision", "title": HOSTILE,
                       "props": {"rule": {"review_required": {"paths": ["src/**"], "reviewers": ["@payments"]}}}}],
            "edges": [{"source": "decision:hostile", "target": "concept:src", "type": "ABOUT", "evidence": HOSTILE}]}
    report = check.run(co.load(json.dumps(snap)), [HOSTILE_PATH], ROOT, ["@bob"])
    return action.Outcome(report, pull(requested=("@ana",)), ["@bob"], "0.1.1", "snap|shot.json", notes=[HOSTILE])


def unescaped_pipes(line: str) -> int:
    return len(re.findall(r"(?<!\\)\|", line))


def test_a_hostile_title_and_path_reach_the_comment_only_as_escaped_text(no_network):
    out = action.body(hostile_outcome())
    assert out.startswith(action.MARKER + "\n") and out.count("<!--") == 1
    assert out.count("```") == 2
    start = out.index("```mermaid\n")
    end = out.index("```", start + 3)
    prose, graph = out[len(action.MARKER):start] + out[end + 3:], out[start + len("```mermaid\n"):end]
    for raw in ("<script", "<img", "<!--", "@everyone", "](", "**bold**", "‮", "\x00", ":shipit:", "$x$"):
        assert raw not in prose
    for raw in ("<script", "<img", "<!--", "`", "‮", "\x00"):
        assert raw not in graph
    assert all(not line.startswith("#") or line == "### decisis" or line.startswith("#### ") for line in prose.splitlines())
    rows = [line for line in out.splitlines() if line.startswith("| ")]
    widths = {unescaped_pipes(line) for line in rows if "Decision" in line or "decision\\:hostile" in line}
    assert widths == {4, 5}
    for line in rows:
        assert unescaped_pipes(line) in (4, 5)
    assert "&lt;script&gt;alert\\(1\\)&lt;/script&gt;" in out
    assert "@⁠everyone" in out
    assert "<code>@⁠bob</code>" in out and "<code>@⁠ana</code>" in out


def test_the_body_stays_under_githubs_limit_and_says_what_was_cut(no_network):
    many = [{"file": f"src/{'x' * 200}{i}.py", "line": i, "decision": f"decision:d{i}", "rule": "imports_forbidden",
             "verdict": "violated", "why": "w" * 300, "import": "db", "target": "db.py"} for i in range(3000)]
    report = {"changed": [r["file"] for r in many], "governing": [], "superseded": [], "violations": many, "unresolved": [],
              "impact": [], "rules": []}
    out = action.body(action.Outcome(report, pull(), [], "0.1.1", "s.json"))
    assert len(out) <= action.MAX_BODY
    assert "Cut to fit GitHub's 65,536-character limit" in out and "the graph is left out" in out
    assert "more results not shown here" in out
    small = action.body(action.Outcome({**report, "violations": many[:3], "changed": []}, pull(), [], "0.1.1", "s.json"))
    assert "Cut to fit" not in small and "```mermaid" in small


def test_the_latest_review_of_each_user_counts_and_only_an_approval_is_a_reviewer(no_network):
    reviews = [{"user": {"login": "ana"}, "state": "APPROVED"}, {"user": {"login": "ana"}, "state": "CHANGES_REQUESTED"},
               {"user": {"login": "bob"}, "state": "COMMENTED"}, {"user": {"login": "bob"}, "state": "APPROVED"},
               {"user": {"login": "bob"}, "state": "COMMENTED"}, {"user": {"login": "carol"}, "state": "APPROVED"},
               {"user": {"login": "carol"}, "state": "DISMISSED"}, {"user": {"login": "dan"}, "state": "COMMENTED"}, {"user": None},
               {"user": {"login": "erin"}, "state": "APPROVED"}]
    assert action.approvals(gh.Client(TOKEN, FakeGitHub(reviews)), pull(author="erin")) == (["@bob"], None)


def test_reviews_past_the_cap_are_not_counted_and_the_comment_says_so(tmp_path, monkeypatch, no_network):
    monkeypatch.setattr(gh, "MAX_REVIEWS", 2)
    reviews = [{"user": {"login": "ana"}, "state": "COMMENTED"}, {"user": {"login": "bob"}, "state": "COMMENTED"},
               {"user": {"login": "alice"}, "state": "APPROVED"}]
    approved, note = action.approvals(gh.Client(TOKEN, FakeGitHub(reviews)), pull())
    assert approved == [] and "more than 2 reviews" in note and "counts no approval" in note
    root, base = shop(tmp_path)
    fake = FakeGitHub(reviews)
    assert action.main(environment(tmp_path, root, base), fake) == 0
    (_, _, data), = fake.writes()
    assert "counts no approval" in data["body"]


def test_past_the_comment_cap_no_new_comment_is_posted_and_the_summary_says_so(tmp_path, monkeypatch, capsys, no_network):
    monkeypatch.setattr(action, "MAX_COMMENTS", 2)
    others = [{"id": i, "user": {"login": "mallory"}, "body": "hi"} for i in range(3)]
    with pytest.raises(action.TooManyComments):
        action.post(gh.Client(TOKEN, FakeGitHub(pages=(others,))), pull(), action.MARKER)
    root, base = shop(tmp_path)
    fake = FakeGitHub(pages=(others,))
    assert action.main(environment(tmp_path, root, base), fake) == 0
    assert fake.writes() == []
    assert "did not post a new one" in (tmp_path / "summary.md").read_text() and "did not post a new one" in capsys.readouterr().out


def test_the_bots_marked_comment_is_found_across_pages_and_updated(no_network):
    human = {"id": 1, "user": {"login": "mallory"}, "body": action.MARKER + " fake"}
    other = {"id": 2, "user": {"login": "github-actions[bot]"}, "body": "another bot comment"}
    ours = {"id": 3, "user": {"login": "github-actions[bot]"}, "body": action.MARKER + "\nold"}
    fake = FakeGitHub(pages=([human, other], [ours]))
    link = action.post(gh.Client(TOKEN, fake), pull(), action.MARKER + "\nnew")
    assert link.endswith("#issuecomment-99")
    assert fake.writes() == [("PATCH", f"{API}/issues/comments/3", {"body": action.MARKER + "\nnew"})]
    for method, url, _, headers in fake.sent:
        assert url.startswith("https://api.github.com/") and headers["Authorization"] == f"Bearer {TOKEN}"
        assert TOKEN not in url


def test_without_a_marked_comment_one_is_created(no_network):
    fake = FakeGitHub(pages=([{"id": 1, "user": {"login": "mallory"}, "body": action.MARKER}],))
    action.post(gh.Client(TOKEN, fake), pull(), action.MARKER + "\nnew")
    assert fake.writes() == [("POST", f"{API}/issues/7/comments", {"body": action.MARKER + "\nnew"})]


def test_a_pull_request_run_comments_writes_the_summary_and_the_outputs(tmp_path, no_network):
    root, base = shop(tmp_path)
    fake = FakeGitHub(reviews=[{"user": {"login": "alice"}, "state": "APPROVED"}])
    assert action.main(environment(tmp_path, root, base), fake) == 0
    (method, url, data), = fake.writes()
    assert (method, url) == ("POST", f"{API}/issues/7/comments")
    summary = (tmp_path / "summary.md").read_text()
    assert summary == data["body"]
    assert "decision\\:ui\\-does\\-not\\-import\\-db" in summary and "<code>@⁠alice</code>" in summary
    assert "<code>@⁠ana</code>" in summary and "<code>@⁠acme/payments</code>" in summary
    assert "```mermaid" in summary and "src/shop/ui/view.py" in summary
    assert "<script" not in summary
    out = (tmp_path / "output.txt").read_text()
    assert re.search(r"^violations=[1-9]\d*$", out, re.M) and "comment-url=https://github.com/acme/shop/pull/7#issuecomment-99" in out


def test_fail_on_violation_fails_the_step_after_the_comment(tmp_path, no_network):
    root, base = shop(tmp_path)
    fake = FakeGitHub()
    assert action.main(environment(tmp_path, root, base, DECISIS_FAIL_ON_VIOLATION="true"), fake) == 1
    assert [m for m, _, _ in fake.writes()] == ["POST"]


def test_a_fork_pull_request_writes_only_the_job_summary(tmp_path, no_network):
    root, base = shop(tmp_path)
    fake = FakeGitHub()
    assert action.main(environment(tmp_path, root, base, fork=True), fake) == 0
    assert fake.writes() == [] and not any("/comments" in u for _, u, _, _ in fake.sent)
    summary = (tmp_path / "summary.md").read_text()
    assert summary.startswith(action.MARKER) and "comes from a fork" in summary
    assert "comment-url=\n" in (tmp_path / "output.txt").read_text()


@pytest.mark.parametrize("code", [403, 404])
def test_a_read_only_token_falls_back_to_the_job_summary(tmp_path, code, capsys, no_network):
    root, base = shop(tmp_path)
    fake = FakeGitHub(refuse_writes=code)
    assert action.main(environment(tmp_path, root, base), fake) == 0
    assert (tmp_path / "summary.md").read_text().startswith(action.MARKER)
    assert "only in the job summary" in capsys.readouterr().out


def test_init_builds_the_snapshot_from_the_repositorys_adrs(tmp_path, no_network):
    root, base = shop(tmp_path)
    adr = root / "docs" / "adr"
    adr.mkdir(parents=True)
    (adr / "0001-ui.md").write_text(f"# 1. {HOSTILE.splitlines()[0]}\n\n## Status\n\nAccepted\n\n## Decision\n\nUI code lives in `src/shop/ui/`.\n")
    git(root, "add", "-A")
    git(root, "commit", "-q", "-m", "adr")
    env = environment(tmp_path, root, base, DECISIS_INIT="true")
    del env["DECISIS_SNAPSHOT"]
    assert action.main(env, FakeGitHub()) == 0
    summary = (tmp_path / "summary.md").read_text()
    assert "built with decisis init" in summary and "<script" not in summary and "@everyone" not in summary


def test_an_event_without_a_pull_request_checks_nothing(tmp_path, no_network):
    path = tmp_path / "event.json"
    path.write_text(json.dumps({"ref": "refs/heads/main"}))
    fake = FakeGitHub()
    env = {"GITHUB_EVENT_PATH": str(path), "GITHUB_REPOSITORY": REPO, "GITHUB_STEP_SUMMARY": str(tmp_path / "s.md")}
    assert action.main(env, fake) == 0 and fake.sent == []


@pytest.mark.parametrize("change", [{"DECISIS_INIT": "true"}, {"DECISIS_SNAPSHOT": ""}, {"DECISIS_FAIL_ON_VIOLATION": "maybe"}])
def test_bad_inputs_stop_the_step_with_an_error_and_no_request(tmp_path, change, capsys, no_network):
    root, base = shop(tmp_path)
    fake = FakeGitHub()
    env = {**environment(tmp_path, root, base), **change}
    if "DECISIS_FAIL_ON_VIOLATION" in change:
        assert action.main(env, fake) == 2
        assert "DECISIS_FAIL_ON_VIOLATION must be true or false" in capsys.readouterr().out
    else:
        assert action.main(env, fake) == 2 and fake.sent == []
        assert "not both and not neither" in capsys.readouterr().out


@pytest.mark.parametrize("sha", ["", "HEAD", "--output=/tmp/x", "a" * 39, "A" * 40, None])
def test_the_base_must_be_a_commit_sha_from_the_payload(sha):
    with pytest.raises(ValueError):
        action.pull_of({"pull_request": {"number": 7, "base": {"sha": sha}, "head": {"repo": {"full_name": REPO}}}}, REPO)


def test_a_missing_or_foreign_head_repository_is_a_fork():
    def of(head):
        return action.pull_of({"pull_request": {"number": 7, "base": {"sha": "b" * 40, "repo": {"full_name": REPO}}, "head": {"repo": head}}}, REPO)
    assert of(None).fork and of({"full_name": "x/shop", "fork": True}).fork and of({"full_name": "x/shop"}).fork
    assert not of({"full_name": REPO, "fork": False}).fork


def test_same_full_name_with_fork_true_is_not_a_fork():
    payload = {"pull_request": {"number": 7, "user": {"login": "erin"}, "base": {"sha": "b" * 40, "repo": {"full_name": REPO, "fork": True}},
                                "head": {"repo": {"full_name": REPO, "fork": True}}}}
    found = action.pull_of(payload, REPO)
    assert not found.fork and found.author == "erin"


def steps(doc: dict) -> list[dict]:
    if "runs" in doc:
        return doc["runs"]["steps"]
    return [s for job in doc["jobs"].values() for s in job["steps"]]


@pytest.mark.parametrize("name", ["action.yml", ".github/workflows/decisis.yml"])
def test_third_party_actions_are_pinned_and_no_expression_reaches_a_shell(name):
    doc = yaml.safe_load((ROOT / name).read_text(encoding="utf-8"))
    for step in steps(doc):
        if "uses" in step and not step["uses"].startswith("./"):
            assert re.fullmatch(r"[\w.-]+/[\w.-]+@[0-9a-f]{40}", step["uses"]), step["uses"]
        if "run" in step:
            assert "${{" not in step["run"]
            for call in re.findall(r'"\$(?:PY|py|PYTHON)"[^\n]*', step["run"]):
                assert " -I " in call, call


def test_the_action_has_its_inputs_and_the_workflow_asks_for_the_least_permission():
    doc = yaml.safe_load((ROOT / "action.yml").read_text(encoding="utf-8"))
    assert doc["runs"]["using"] == "composite"
    assert {"snapshot", "init", "github-token", "inventory", "fail-on-violation", "decisis-version", "decisions-from"} <= set(doc["inputs"])
    assert doc["inputs"]["fail-on-violation"]["default"] == "false"
    flow = yaml.safe_load((ROOT / ".github" / "workflows" / "decisis.yml").read_text(encoding="utf-8"))
    assert flow["permissions"] == {}
    job, = flow["jobs"].values()
    assert job["permissions"] == {"contents": "read", "pull-requests": "write"}
    assert list(flow[True]) == ["pull_request"]
    assert not any(s.get("with", {}).get("fail-on-violation") for s in job["steps"])


def test_an_approval_withdrawn_after_a_flood_of_reviews_is_not_counted(tmp_path, monkeypatch, no_network):
    monkeypatch.setattr(gh, "MAX_REVIEWS", 3)
    reviews = ([{"user": {"login": "alice"}, "state": "APPROVED"}]
               + [{"user": {"login": "mallory"}, "state": "COMMENTED"}] * 3
               + [{"user": {"login": "alice"}, "state": "CHANGES_REQUESTED"}])
    approved, note = action.approvals(gh.Client(TOKEN, FakeGitHub(reviews)), pull())
    assert approved == [] and "counts no approval" in note
    root, base = shop(tmp_path)
    fake = FakeGitHub(reviews)
    action.main(environment(tmp_path, root, base), fake)
    (_, _, data), = fake.writes()
    assert "payments-need-a-payments-review" in data["body"]


WORKFLOW = "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n"
DEMO_LOCK = ROOT / "fixtures" / "audit" / "demo-lockfile.json"


def osv_cache(tmp_path: Path) -> Path:
    cache = json.loads((ROOT / "fixtures" / "audit" / "osv-cache.json").read_text(encoding="utf-8"))
    cache["queries"]["pkg:pypi/requests@2.31.0"] = []
    cache["names"] = {"GitHub Actions": {"fetched_at": cache["fetched_at"], "names": []}}
    path = tmp_path / "osv-cache.json"
    path.write_text(json.dumps(cache))
    return path


def audit_env(tmp_path: Path, root: Path, base: str, inventory: str, **extra) -> dict:
    return environment(tmp_path, root, base, DECISIS_SNAPSHOT=str(ROOT / "fixtures" / "action" / "vinc.json"), DECISIS_REPO="Demo",
                       DECISIS_INVENTORY=inventory, DECISIS_OSV_CACHE=str(osv_cache(tmp_path)), **extra)


def outputs(tmp_path: Path) -> dict:
    return dict(line.split("=", 1) for line in (tmp_path / "output.txt").read_text().splitlines())


def sections(body: str) -> list[str]:
    return re.findall(r"^#### Audit of <code>(.*)</code>$", body, re.M)


def one_lockfile_violations(tmp_path: Path, root: Path, base: str) -> int:
    lone = tmp_path / "lone"
    lone.mkdir()
    env = audit_env(lone, root, base, str(DEMO_LOCK))
    assert action.main(env, FakeGitHub()) == 0
    return int(outputs(lone)["violations"])


def test_inventory_auto_finds_the_known_names_in_the_root_and_nothing_else(tmp_path):
    root = tmp_path / "repo"
    (root / ".github" / "workflows").mkdir(parents=True)
    names = sorted(action.LOCKFILES | {"requirements.txt", "requirements-dev.txt"})
    for name in names + ["package.json", "dev-requirements.txt", "notes.txt", "lockfile.json"]:
        (root / name).write_text("x\n")
    for nested in ("fixtures/package-lock.json", "vendor/lib/Cargo.lock", "web/yarn.lock", "fixtures/.github/workflows/ci.yml"):
        (root / nested).parent.mkdir(parents=True, exist_ok=True)
        (root / nested).write_text(WORKFLOW)
    assert action.found(root) == [(n, n, None) for n in names]
    (root / ".github" / "workflows" / "a.yml").write_text("name: not a workflow\n")
    (root / ".github" / "workflows" / "ci.yml").write_text(WORKFLOW)
    assert action.found(root)[-1] == (".github/workflows", ".github/workflows/ci.yml", None)


def test_inventory_auto_audits_every_found_inventory_in_its_own_section_and_sums_the_violations(tmp_path, no_network):
    root, base = shop(tmp_path)
    shutil.copy(DEMO_LOCK, root / "package-lock.json")
    shutil.copy(DEMO_LOCK, root / "npm-shrinkwrap.json")
    (root / "requirements-dev.txt").write_text("requests==2.31.0\n")
    (root / ".github" / "workflows").mkdir(parents=True)
    (root / ".github" / "workflows" / "ci.yml").write_text(WORKFLOW)
    (root / "fixtures").mkdir()
    (root / "fixtures" / "package-lock.json").write_text("not json\n")
    (root / "vendor" / "lib").mkdir(parents=True)
    (root / "vendor" / "lib" / "yarn.lock").write_text("not a lockfile\n")
    one = one_lockfile_violations(tmp_path, root, base)
    assert one > 0
    fake = FakeGitHub()
    assert action.main(audit_env(tmp_path, root, base, "auto", DECISIS_FAIL_ON_VIOLATION="true"), fake) == 1
    (_, _, data), = fake.writes()
    summary = (tmp_path / "summary.md").read_text()
    assert summary == data["body"]
    assert sections(summary) == ["npm\\-shrinkwrap.json", "package\\-lock.json", "requirements\\-dev.txt", ".github/workflows"]
    assert "fixtures" not in "".join(sections(summary)) and "vendor" not in summary and "Not audited" not in summary
    assert f"{2 * one} audit violation(s)" in summary
    assert summary.count("```mermaid") == 5
    assert int(outputs(tmp_path)["violations"]) == 2 * one


def test_found_files_that_lead_outside_the_root_are_not_read(tmp_path, no_network):
    root, base = shop(tmp_path)
    outside = tmp_path / "outside"
    (outside / "workflows").mkdir(parents=True)
    shutil.copy(DEMO_LOCK, outside / "package-lock.json")
    (outside / "workflows" / "ci.yml").write_text(WORKFLOW)
    (outside / "go.sum").write_text("secret go.sum\n")
    (root / "package-lock.json").symlink_to(outside / "package-lock.json")
    (root / ".github").symlink_to(outside)
    (root / "locks").mkdir()
    shutil.copy(DEMO_LOCK, root / "locks" / "demo.json")
    (root / "npm-shrinkwrap.json").symlink_to(root / "locks" / "demo.json")
    (root / "go.mod").write_text("module example.com/m\n\ngo 1.22\n\nrequire example.com/dep v1.0.0\n")
    (root / "go.sum").symlink_to(outside / "go.sum")
    one = one_lockfile_violations(tmp_path, root, base)
    fake = FakeGitHub()
    assert action.main(audit_env(tmp_path, root, base, "auto"), fake) == 0
    summary = (tmp_path / "summary.md").read_text()
    assert sections(summary) == ["go.mod", "npm\\-shrinkwrap.json", "package\\-lock.json", ".github/workflows"]
    go, shrinkwrap, lock, flows = summary.split("#### Audit of ")[1:]
    assert "Not audited" in lock and "leads outside" in lock
    assert "Not audited" in flows and "leads outside" in flows
    assert "Not audited" not in shrinkwrap and "Not audited" in go and "go.sum" in go and "secret" not in summary
    assert int(outputs(tmp_path)["violations"]) == one


def test_inventory_auto_that_finds_nothing_says_so_and_does_not_fail(tmp_path, no_network):
    root, base = shop(tmp_path)
    (root / "web" / "package-lock.json").write_text(DEMO_LOCK.read_text())
    (root / ".github" / "workflows").mkdir(parents=True)
    (root / ".github" / "workflows" / "README.md").write_text("no workflow here\n")
    fake = FakeGitHub()
    assert action.main(audit_env(tmp_path, root, base, "auto", DECISIS_FAIL_ON_VIOLATION="true"), fake) == 0
    (_, _, data), = fake.writes()
    assert "found no inventory in the repository root" in data["body"] and sections(data["body"]) == []
    assert "0 audit violation(s)" in data["body"]
    assert outputs(tmp_path)["violations"] == "0"


def test_one_explicit_inventory_is_audited_as_before(tmp_path, no_network):
    root, base = shop(tmp_path)
    shutil.copy(DEMO_LOCK, root / "package-lock.json")
    lock = str(DEMO_LOCK)
    fake = FakeGitHub()
    assert action.main(audit_env(tmp_path, root, base, lock, DECISIS_FAIL_ON_VIOLATION="true"), fake) == 1
    (_, _, data), = fake.writes()
    assert sections(data["body"]) == [action.text(lock)]
    assert data["body"].count("```mermaid") == 2 and "found no inventory" not in data["body"]
    violations = int(outputs(tmp_path)["violations"])
    assert violations > 0 and f"{violations} audit violation(s)" in data["body"]
    missing = audit_env(tmp_path, root, base, str(root / "missing.json"))
    assert action.main(missing, FakeGitHub()) == 2


def test_several_paths_one_per_line_each_get_a_section(tmp_path, no_network):
    root, base = shop(tmp_path)
    shutil.copy(DEMO_LOCK, root / "package-lock.json")
    (root / "web" / "requirements.txt").write_text("requests==2.31.0\n")
    one = one_lockfile_violations(tmp_path, root, base)
    paths = f"{root / 'package-lock.json'}\n\n  {root / 'web' / 'requirements.txt'}  \nauto\n"
    fake = FakeGitHub()
    assert action.main(audit_env(tmp_path, root, base, paths), fake) == 0
    (_, _, data), = fake.writes()
    assert sections(data["body"]) == [action.text(root / "package-lock.json"), action.text(root / "web" / "requirements.txt")]
    assert int(outputs(tmp_path)["violations"]) == one


def test_an_explicit_inventory_that_is_a_symlink_loop_stops_the_step_with_the_error(tmp_path, no_network):
    root, base = shop(tmp_path)
    (root / "loop.json").symlink_to("loop.json")
    fake = FakeGitHub()
    assert action.main(audit_env(tmp_path, root, base, str(root / "loop.json")), fake) == 2
    assert fake.writes() == []
    summary = (tmp_path / "summary.md").read_text()
    assert summary.startswith("decisis could not check this pull request") and "symbolic links" in summary


@pytest.mark.parametrize("loop", ["package-lock.json", ".github"])
def test_a_symlink_loop_that_auto_finds_gets_a_section_and_the_comment_is_written(tmp_path, loop, no_network):
    root, base = shop(tmp_path)
    shutil.copy(DEMO_LOCK, root / "npm-shrinkwrap.json")
    (root / loop).symlink_to(loop)
    one = one_lockfile_violations(tmp_path, root, base)
    fake = FakeGitHub()
    assert action.main(audit_env(tmp_path, root, base, "auto"), fake) == 0
    (_, _, data), = fake.writes()
    label = {"package-lock.json": "package\\-lock.json", ".github": ".github/workflows"}[loop]
    assert sections(data["body"]) == ["npm\\-shrinkwrap.json", label]
    shown = data["body"].split(f"#### Audit of <code>{label}</code>")[1]
    assert "Not audited" in shown and "symbolic link loop" in shown
    assert (tmp_path / "summary.md").read_text() == data["body"]
    assert int(outputs(tmp_path)["violations"]) == one
