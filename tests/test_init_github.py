from __future__ import annotations

import argparse
import email.message
import http.client
import io
import json
import re
import urllib.error
import urllib.parse
import urllib.request
from datetime import date
from functools import partial
from pathlib import Path

import pytest

from test_audit import no_network
from decisis import checkout as co
from decisis import cli, impact, init
from decisis import github as gh

ROOT = Path(__file__).resolve().parents[1]
SHOP = ROOT / "fixtures" / "init" / "shop"
RECORDING = json.loads((ROOT / "fixtures" / "init" / "github" / "acme-shop.json").read_text(encoding="utf-8"))
API = "https://api.github.com/repos/acme/shop"
PR = f"decision:github-acme-shop-{gh.repo_key('acme', 'shop')}-pr-"
ADR = "decision:shop-docs-adr-"
TOKEN = "ghp_" + "Z9" * 18


def key(url: str) -> str:
    parts = urllib.parse.urlsplit(url)
    query = [(k, v) for k, v in urllib.parse.parse_qsl(parts.query) if k != "per_page"]
    return urllib.parse.urlunsplit(parts._replace(query=urllib.parse.urlencode(query)))


class Answer(io.BytesIO):
    def __init__(self, body: bytes, headers, url: str):
        super().__init__(body)
        self.headers, self.url = headers, url

    def geturl(self) -> str:
        return self.url


class Recorded:
    def __init__(self, *overrides: dict, raise_for: dict | None = None):
        self.answers = {key(e["url"]): e for e in (*RECORDING["exchanges"], *overrides)}
        self.raise_for = raise_for or {}
        self.sent: list[urllib.request.Request] = []

    def __call__(self, req: urllib.request.Request, timeout=None):
        self.sent.append(req)
        if key(req.full_url) in self.raise_for:
            raise self.raise_for[key(req.full_url)]
        e = self.answers.get(key(req.full_url))
        if e is None:
            raise AssertionError(f"no recorded answer for {req.full_url}")
        headers = email.message.Message()
        for k, v in e.get("headers", {}).items():
            headers[k] = v
        body = e["body"].encode("utf-8") if isinstance(e["body"], str) else json.dumps(e["body"]).encode("utf-8")
        if e["status"] >= 400:
            raise urllib.error.HTTPError(req.full_url, e["status"], e.get("reason", "Forbidden"), headers, io.BytesIO(body))
        return Answer(body, headers, e.get("final_url", req.full_url))

    def urls(self) -> list[str]:
        return [key(r.full_url) for r in self.sent]


def read(fake: Recorded, **options) -> dict:
    return init.build(SHOP, "Shop", partial(gh.read_pulls, repo="acme/shop", opener=fake, **options))


def by_id(snap: dict) -> dict:
    return {n["id"]: n for n in snap["nodes"]}


def test_a_pull_request_is_selected_by_its_label_or_by_a_decision_section(no_network):
    snap = read(Recorded())
    assert [n["id"] for n in snap["nodes"]] == [f"{PR}15", f"{PR}17", f"{PR}21"]
    assert snap["meta"]["problems"] == []


def test_a_selected_pull_request_becomes_a_decision_with_its_statement_date_deciders_and_files(no_network):
    nodes = by_id(read(Recorded()))
    refund = nodes[f"{PR}21"]
    assert refund["kind"] == "decision" and refund["title"] == "Refund through the gateway's idempotent endpoint"
    props = refund["props"]
    assert props["statement"] == "Refunds go through the gateway's idempotent endpoint and are never retried by hand."
    assert props["valid_from"] == "2026-06-10T09:30:00Z"
    assert props["deciders"] == ["@ana", "@dan"]
    assert props["code_ref"] == ["Shop:src/payments/gateway.py", "Shop:src/payments/refund.py"]
    assert props["source"] == "https://github.com/acme/shop/pull/21"
    assert props["content_hash"].startswith("sha256:")
    assert nodes[f"{PR}15"]["props"]["statement"] == ("Card numbers never reach logs: redact them before formatting.\n\n"
                                                      "- Applies to every logger.")
    assert "statement" not in nodes[f"{PR}17"]["props"]
    assert nodes[f"{PR}17"]["props"]["deciders"] == ["@ben", "@ana"]
    assert nodes[f"{PR}15"]["props"]["deciders"] == ["@cy"]


def test_a_decision_section_that_holds_only_a_template_comment_does_not_select(no_network):
    assert gh.decision_text("## Decision\n\n<!-- Fill in the decision. -->\n") is None
    assert gh.decision_text("## Decision\n<!-- note -->\nUse one queue.\n## Next\nx") == "Use one queue."
    assert not gh.selected({"labels": [{"name": "chore"}], "body": None}, "decision")
    assert gh.selected({"labels": [{"name": "ADR"}], "body": ""}, "adr")


def test_the_last_review_of_each_reviewer_counts_and_the_author_is_not_an_approver():
    reviews = [{"user": {"login": "a"}, "state": "APPROVED"}, {"user": {"login": "a"}, "state": "DISMISSED"},
               {"user": {"login": "b"}, "state": "CHANGES_REQUESTED"}, {"user": {"login": "b"}, "state": "COMMENTED"},
               {"user": {"login": "c"}, "state": "APPROVED"}, {"user": {"login": "c"}, "state": "COMMENTED"},
               {"user": {"login": "me"}, "state": "APPROVED"}]
    assert gh.approvers(reviews, "me") == ["c"]


def test_it_sends_only_get_requests_to_api_github_com_and_follows_link_headers(no_network):
    fake = Recorded()
    read(fake)
    assert {r.get_method() for r in fake.sent} == {"GET"}
    assert {urllib.parse.urlsplit(r.full_url).hostname for r in fake.sent} == {"api.github.com"}
    assert all(r.data is None for r in fake.sent)
    listing = [u for u in fake.urls() if "/pulls?" in u]
    assert listing == [key(f"{API}/pulls?state=closed&sort=updated&direction=desc"),
                       key(f"{API}/pulls?state=closed&sort=updated&direction=desc&page=2")]
    assert key(f"{API}/pulls/21/files?page=2") in fake.urls()
    assert not [r for r in fake.sent if r.has_header("Authorization")]


def test_a_hard_limit_stops_the_listing_and_says_so(no_network):
    fake = Recorded()
    snap = read(fake, limit=2)
    assert [n["id"] for n in snap["nodes"]] == [f"{PR}21"]
    assert snap["meta"]["problems"] == [{"file": "github:acme/shop", "action": "not read",
                                         "reason": "stopped after 2 closed pull requests (--limit); older ones were not read"}]
    assert fake.sent[0].full_url.endswith("per_page=2")
    assert key(f"{API}/pulls?state=closed&sort=updated&direction=desc&page=2") not in fake.urls()
    assert [n["id"] for n in read(Recorded(), limit=3)["nodes"]] == [f"{PR}21"]
    assert read(Recorded(), limit=6)["meta"]["problems"] == []


def test_since_keeps_pull_requests_merged_on_or_after_the_date_and_stops_paging(no_network):
    fake = Recorded()
    snap = read(fake, since=date(2026, 3, 1))
    assert [n["id"] for n in snap["nodes"]] == [f"{PR}17", f"{PR}21"]
    assert key(f"{API}/pulls/15/files") not in fake.urls()


@pytest.mark.parametrize("status,headers,said", [
    (403, {"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": "1781000000"}, "it resets at 2026-06-09T10:13:20Z"),
    (429, {"Retry-After": "60"}, "GitHub asks to wait 60 seconds"),
    (403, {"Retry-After": "30"}, "GitHub asks to wait 30 seconds"),
])
def test_a_rate_limit_stops_the_read_and_keeps_what_was_read(no_network, status, headers, said):
    limited = {"url": f"{API}/pulls/17/files", "status": status, "headers": headers, "body": {"message": "API rate limit exceeded"}}
    fake = Recorded(limited)
    snap = read(fake)
    assert [n["id"] for n in snap["nodes"]] == [f"{PR}21"]
    [problem] = snap["meta"]["problems"]
    assert problem["file"] == "github:acme/shop" and problem["action"] == "not read"
    assert said in problem["reason"] and "kept the 1 pull request(s) read before it" in problem["reason"]
    assert "set GITHUB_TOKEN" in problem["reason"]
    assert fake.urls()[-1] == key(f"{API}/pulls/17/files")


def test_a_forbidden_answer_without_rate_limit_headers_fails_the_command(no_network):
    fake = Recorded({"url": f"{API}/pulls/21/reviews", "status": 403, "headers": {"X-RateLimit-Remaining": "40"}, "body": {}})
    with pytest.raises(gh.GitHubFailed, match="HTTP 403"):
        read(fake)


def test_the_token_goes_only_in_the_authorization_header_and_never_into_an_error(no_network):
    fake = Recorded()
    snap = read(fake, token=TOKEN)
    assert all(r.get_header("Authorization") == f"Bearer {TOKEN}" for r in fake.sent)
    assert TOKEN not in json.dumps(snap) and all(TOKEN not in r.full_url for r in fake.sent)
    refused = Recorded({"url": f"{API}/pulls?state=closed&sort=updated&direction=desc", "status": 401, "reason": "Unauthorized",
                        "headers": {}, "body": {"message": "Bad credentials"}})
    with pytest.raises(gh.GitHubFailed) as e:
        read(refused, token=TOKEN)
    assert "refused the token" in str(e.value) and TOKEN not in str(e.value)
    leaky = Recorded(raise_for={key(f"{API}/pulls?state=closed&sort=updated&direction=desc"):
                                urllib.error.URLError(f"proxy said Authorization: Bearer {TOKEN}")})
    with pytest.raises(gh.GitHubFailed) as e:
        read(leaky, token=TOKEN)
    assert TOKEN not in str(e.value) and "[token]" in str(e.value)
    limited = Recorded({"url": f"{API}/pulls/21/files", "status": 429, "headers": {}, "body": {}})
    snap = read(limited, token=TOKEN)
    assert TOKEN not in json.dumps(snap) and "set GITHUB_TOKEN" not in json.dumps(snap)


def test_a_token_a_header_cannot_carry_is_refused_without_showing_it():
    with pytest.raises(gh.GitHubFailed) as e:
        gh.clean_token(f"{TOKEN}\nX-Injected: 1")
    assert TOKEN not in str(e.value)
    assert gh.clean_token(f" {TOKEN}\n") == TOKEN
    assert gh.clean_token("") is None and gh.clean_token(None) is None


def test_a_next_page_or_an_answer_on_another_host_is_refused(no_network):
    first = f"{API}/pulls?state=closed&sort=updated&direction=desc"
    elsewhere = Recorded({"url": first, "status": 200, "headers": {"Link": '<https://evil.example/pulls?page=2>; rel="next"'},
                          "body": RECORDING["exchanges"][0]["body"]})
    with pytest.raises(gh.GitHubFailed, match="only to https://api.github.com"):
        read(elsewhere)
    assert {urllib.parse.urlsplit(r.full_url).hostname for r in elsewhere.sent} == {"api.github.com"}
    moved = Recorded({"url": first, "status": 200, "headers": {}, "body": [], "final_url": "https://evil.example/pulls"})
    with pytest.raises(gh.GitHubFailed, match="another host"):
        read(moved)
    for url in ("http://api.github.com/x", "https://api.github.com:8443/x", "https://user@api.github.com/x",
                "https://api.github.com.evil.example/x", "https://evil.example/api.github.com"):
        assert not gh.on_api(url), url


def test_a_redirect_to_another_host_is_not_followed():
    handler = gh.SameHost()
    req = urllib.request.Request(f"{API}/pulls", headers={"Authorization": f"Bearer {TOKEN}"})
    with pytest.raises(gh.GitHubFailed, match="evil.example"):
        handler.redirect_request(req, io.BytesIO(), 302, "Found", email.message.Message(), "https://evil.example/steal")
    same = handler.redirect_request(req, io.BytesIO(), 301, "Moved", email.message.Message(), "/repositories/1/pulls")
    assert same.full_url == "https://api.github.com/repositories/1/pulls"


def test_a_file_list_at_github_s_cap_is_kept_and_reported(no_network, monkeypatch):
    monkeypatch.setattr(gh, "MAX_FILES", 1)
    snap = read(Recorded())
    assert by_id(snap)[f"{PR}21"]["props"]["code_ref"] == ["Shop:src/payments/refund.py"]
    assert {"file": "github:acme/shop#21", "action": "kept without code paths",
            "reason": "GitHub lists at most 1 changed files of a pull request; files past that are not in code_ref"} in snap["meta"]["problems"]


def test_options_are_checked_before_any_request():
    with pytest.raises(ValueError, match="OWNER/REPO"):
        gh.repository("acme")
    with pytest.raises(ValueError, match="OWNER/REPO"):
        gh.repository("acme/../x")
    with pytest.raises(ValueError, match="2026-01-31"):
        gh.since_date("last week")
    with pytest.raises(ValueError, match="outside 1 to"):
        gh.read_pulls(init.Tree(SHOP), "acme/shop", limit=0, opener=Recorded())


def run_cli(capsys, monkeypatch, fake: Recorded, *args: str) -> tuple[int, str, str]:
    monkeypatch.setattr(gh, "default_opener", lambda: fake)
    capsys.readouterr()
    try:
        code = cli.main(["init", *args])
    except SystemExit as e:
        code = e.code
    out = capsys.readouterr()
    return code, out.out, out.err


def test_init_merges_pull_requests_with_the_adrs_into_one_snapshot_with_stable_ids(no_network, tmp_path, capsys, monkeypatch):
    outs = []
    for i in range(2):
        out = tmp_path / f"snapshot{i}.json"
        code, printed, _ = run_cli(capsys, monkeypatch, Recorded(), "--repo-dir", str(SHOP), "--repo", "Shop", "--github", "acme/shop",
                                   "--out", str(out))
        assert code == 0
        outs.append(out.read_bytes())
    assert outs[0] == outs[1]
    snap = json.loads(outs[0])
    files_only = init.build(SHOP, "Shop")
    assert {n["id"] for n in snap["nodes"]} == {n["id"] for n in files_only["nodes"]} | {f"{PR}15", f"{PR}17", f"{PR}21"}
    assert snap["edges"] == files_only["edges"]
    graph = co.load(outs[0].decode("utf-8"))
    box = tmp_path / "box"
    box.mkdir()
    report = impact.run(graph, ["src/payments/retry.py"], repo="Shop", root=box)
    governing = {g["id"] for g in report["impact"][0]["governing"]}
    assert {f"{ADR}0003-retry-payment-calls-once", f"{PR}17"} <= governing
    assert [g["id"] for g in report["impact"][0]["superseded"]] == [f"{ADR}0002-retry-payment-calls-three-times"]


def test_init_with_github_alone_reads_no_files(no_network, tmp_path, capsys, monkeypatch):
    monkeypatch.chdir(tmp_path)
    out = tmp_path / "snapshot.json"
    code, printed, _ = run_cli(capsys, monkeypatch, Recorded(), "--github", "acme/shop", "--out", str(out))
    assert code == 0 and json.loads(printed)["nodes"] == 3
    snap = json.loads(out.read_text(encoding="utf-8"))
    assert [n["id"] for n in snap["nodes"]] == [f"{PR}15", f"{PR}17", f"{PR}21"]
    assert snap["meta"]["problems"] == []
    assert by_id(snap)[f"{PR}15"]["props"]["code_ref"] == ["src/logging/redact.py"]


def test_init_never_prints_the_token(no_network, tmp_path, capsys, monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", TOKEN)
    out = tmp_path / "snapshot.json"
    code, printed, err = run_cli(capsys, monkeypatch, Recorded(), "--github", "acme/shop", "--repo-dir", str(SHOP), "--out", str(out))
    assert code == 0 and TOKEN not in printed + err + out.read_text(encoding="utf-8")
    refused = Recorded({"url": f"{API}/pulls?state=closed&sort=updated&direction=desc", "status": 401, "reason": "Unauthorized",
                        "headers": {}, "body": {}})
    code, printed, err = run_cli(capsys, monkeypatch, refused, "--github", "acme/shop", "--out", str(tmp_path / "x.json"))
    assert code == 1 and "refused the token" in err and TOKEN not in printed + err
    monkeypatch.setenv("GITHUB_TOKEN", TOKEN + "\n\tX: 1")
    code, printed, err = run_cli(capsys, monkeypatch, Recorded(), "--github", "acme/shop", "--out", str(tmp_path / "y.json"))
    assert code == 1 and "GITHUB_TOKEN" in err and TOKEN not in printed + err


@pytest.mark.parametrize("args,said", [
    (["--label", "adr"], "go with --github"),
    (["--limit", "5"], "go with --github"),
    (["--github", "acme/shop", "--adr-dir", "docs/adr"], "need --repo-dir"),
    (["--github", "acme/shop", "--label", " "], "must name a label"),
    (["--github", "acme", "--repo-dir", "."], "OWNER/REPO"),
    (["--github", "acme/shop", "--since", "soon"], "2026-01-31"),
    (["--github", "acme/shop", "--limit", "0"], "--limit"),
])
def test_init_github_flags_are_checked(no_network, tmp_path, capsys, monkeypatch, args, said):
    code, _, err = run_cli(capsys, monkeypatch, Recorded(), *args, "--out", str(tmp_path / "s.json"))
    assert code == 2 and said in err
    assert not (tmp_path / "s.json").exists()


def test_the_docs_name_the_flags_and_fields_and_cite_tests_that_exist():
    model = (ROOT / "docs" / "data-model.md").read_text(encoding="utf-8")
    for name in ("--github OWNER/REPO", "--label NAME", "--since DATE", "--limit N", "valid_from", "deciders", "source"):
        assert f"`{name}`" in model, name
    threat = (ROOT / "docs" / "threat-model.md").read_text(encoding="utf-8")
    part = threat[threat.index("**Outbound requests to GitHub.**"):threat.index("**A read-only MCP server.**")]
    cited = re.findall(r"`(test_[a-z_]+)`", part)
    assert cited and all(callable(globals().get(name)) for name in cited), cited


class Cut(Answer):
    def read(self, *args):
        raise http.client.IncompleteRead(b'[{"number": 2', 4096)


def broken_at_read(req, timeout=None):
    return Cut(b"", email.message.Message(), req.full_url)


def broken_status(req, timeout=None):
    raise http.client.BadStatusLine("HTTP/9.9 ???")


def too_deep(req, timeout=None):
    return Answer(b"[" * 100000 + b"]" * 100000, email.message.Message(), req.full_url)


@pytest.mark.parametrize("opener,said", [
    (broken_at_read, "IncompleteRead"),
    (broken_status, "HTTP/9.9"),
    (too_deep, "nested too deeply"),
])
def test_a_broken_answer_fails_the_command_with_a_message_and_no_traceback(no_network, tmp_path, capsys, monkeypatch, opener, said):
    monkeypatch.setenv("GITHUB_TOKEN", TOKEN)
    out = tmp_path / "snapshot.json"
    code, printed, err = run_cli(capsys, monkeypatch, opener, "--github", "acme/shop", "--out", str(out))
    assert code == 1 and err.startswith("decisis: error: ") and said in err
    assert f"{API}/pulls?" in err and "Traceback" not in printed + err and TOKEN not in printed + err
    assert not out.exists()
    with pytest.raises(gh.GitHubFailed):
        read(opener)


def test_json_deep_enough_to_fail_after_it_was_read_still_fails_cleanly(no_network, monkeypatch):
    def deep(*args):
        raise RecursionError("maximum recursion depth exceeded")
    monkeypatch.setattr(gh, "digest", deep)
    with pytest.raises(gh.GitHubFailed, match="nested too deeply"):
        read(Recorded())


def test_a_changed_file_with_a_colon_is_skipped_and_never_read_as_another_repository(no_network):
    files = {"url": f"{API}/pulls/15/files", "status": 200, "headers": {},
             "body": [{"filename": "src/logging/redact.py"}, {"filename": "C:/win"}, {"filename": "a:b/c.py"},
                      {"filename": "src/x:y.py"}]}
    snap = read(Recorded(files))
    assert by_id(snap)[f"{PR}15"]["props"]["code_ref"] == ["Shop:src/logging/redact.py"]
    skipped = [p for p in snap["meta"]["problems"] if p["file"] == "github:acme/shop#15"]
    assert sorted(p["reason"].split("'")[1] for p in skipped) == ["C:/win", "a:b/c.py", "src/x:y.py"]
    assert all(p["action"] == "skipped" and "colon" in p["reason"] for p in skipped)
    for node in snap["nodes"]:
        for ref in node["props"].get("code_ref", []):
            assert impact.code_path(ref, "Shop") is not None, ref
    alone = init.build(SHOP, None, partial(gh.read_pulls, repo="acme/shop", opener=Recorded(files)))
    assert by_id(alone)[f"{PR}15"]["props"]["code_ref"] == ["src/logging/redact.py"]


def test_the_repr_of_the_client_and_the_bound_reader_never_holds_the_token(monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", TOKEN)
    a = argparse.Namespace(github="acme/shop", label=None, since=None, limit=None, repo_dir=None, adr_dir=None, postmortem_dir=None)
    [reader] = cli.init_readers(a)
    assert reader.token == TOKEN
    client = gh.Client(TOKEN)
    pulls = gh.Pulls("acme", "shop", client, init.Tree(SHOP))
    for thing in (client, reader, pulls, gh.PullReader("acme/shop", TOKEN)):
        assert TOKEN not in repr(thing) and TOKEN not in str(thing), type(thing)
    assert "acme/shop" in repr(reader)


def test_the_bound_reader_reads_as_read_pulls_does(no_network):
    assert init.build(SHOP, "Shop", gh.PullReader("acme/shop", opener=Recorded())) == read(Recorded())


def test_reviews_past_the_cap_are_reported(no_network, monkeypatch):
    monkeypatch.setattr(gh, "MAX_REVIEWS", 2)
    snap = read(Recorded())
    assert {"file": "github:acme/shop#21", "action": "not read",
            "reason": "decisis reads at most 2 reviews of a pull request; reviews past that are not read, "
                      "so deciders can miss an approval"} in snap["meta"]["problems"]
    assert [p["file"] for p in snap["meta"]["problems"]] == ["github:acme/shop#21"]
    assert by_id(snap)[f"{PR}21"]["props"]["deciders"] == ["@ana"]


def one_pull(req, timeout=None):
    path = urllib.parse.urlsplit(req.full_url).path
    body = RECORDING["exchanges"][0]["body"][:1] if path.endswith("/pulls") else []
    return Answer(json.dumps(body).encode("utf-8"), email.message.Message(), req.full_url)


def test_pull_request_ids_stay_unique_across_repositories_whose_names_slug_alike(no_network):
    repos = ["a-b/c", "a/b-c", "acme/foo.bar", "acme/foo-bar", "acme/foo_bar", "acme/shop"]
    ids = [gh.read_pulls(init.Tree(SHOP), repo, opener=one_pull)[0][0]["id"] for repo in repos]
    assert len(set(ids)) == len(repos), ids
    assert ids[-1] == f"{PR}21" and re.fullmatch(r"decision:github-acme-shop-[0-9a-f]{8}-pr-21", ids[-1])
    assert gh.read_pulls(init.Tree(SHOP), "Acme/Shop", opener=one_pull)[0][0]["id"] == ids[-1]
    assert gh.repo_key("acme", "shop") == "d21b2cdf"
