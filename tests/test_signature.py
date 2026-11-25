from __future__ import annotations

import hashlib
import io
import json
import re
import subprocess
import urllib.request
from pathlib import Path

import pytest
import yaml

from test_action import HOSTILE, ROOT, FakeGitHub, audit_env, environment, hostile_outcome, outputs, pull, shop
from test_audit import no_network
from test_base_decisions import ADR, adr, env_for, repository
from test_check import CHANGED, REPO as CHECK_REPO, SNAPSHOT as CHECK_SNAPSHOT
from test_inventory_ci import EXPORT, WORKFLOW, read_path
from decisis import action, cli, external, render, signature

FIX = ROOT / "fixtures"
GOLDEN = ROOT / "tests" / "golden"
DOCS = {name: (ROOT / "docs" / f"{name}.md").read_text(encoding="utf-8") for name in ("action", "commands", "data-model")}
DAY = "2026-11-25"
CACHE = FIX / "audit" / "osv-cache.json"
FACTS = "0 LLM calls · deterministic graph check"
LINK = '<a class="tool" href="https://github.com/Vinculums/decisis" rel="noopener noreferrer">decisis 9.9.9</a>'
LINE = re.compile(r'<footer class="signature" style="[^"]*">(.*?)</footer>\n', re.S)


@pytest.fixture(autouse=True)
def release(monkeypatch):
    monkeypatch.setattr(signature, "version", lambda: "9.9.9")


def check_args(files=CHANGED, today: str = DAY) -> list[str]:
    return ["check", str(CHECK_SNAPSHOT), "--repo-dir", str(CHECK_REPO), "--changed", *files, "--reviewers", "bob", "--today", today]


def audit_args(cache: Path | None = CACHE, snapshot: Path = FIX / "audit" / "vinc.json", today: str = DAY) -> list[str]:
    return ["audit", str(snapshot), str(FIX / "audit" / "demo-lockfile.json"), "--repo", "Demo", "--today", today,
            *(["--osv-cache", str(cache)] if cache else [])]


def go(capsys, args: list[str]) -> tuple[int, str]:
    capsys.readouterr()
    return cli.main(args), capsys.readouterr().out


def page_of(capsys, args: list[str]) -> str:
    return go(capsys, [*args, "--format", "html"])[1]


def footer_of(page: str) -> str:
    assert page.count("<footer") == 1 and page.endswith("</footer>\n</main>\n</body>\n</html>\n")
    return LINE.search(page).group(1)


def without_line(page: str) -> str:
    return LINE.sub("", page)


def volatile_free(value):
    if isinstance(value, dict):
        return {k: volatile_free(v) for k, v in value.items() if k not in ("today", "fetched_at", "extracted_at", "days_left")}
    if isinstance(value, list):
        return [volatile_free(v) for v in value]
    return value


def documented_digest(reports: list) -> str:
    text = json.dumps(volatile_free(reports), sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(text.encode("ascii")).hexdigest()[:12]


def digest_of(page: str) -> str:
    return re.search(r"digest: <code>([0-9a-f]{12})</code>", page).group(1)


def live_osv(monkeypatch) -> None:
    monkeypatch.setattr(urllib.request, "urlopen", external.cache_opener(json.loads(CACHE.read_text(encoding="utf-8"))))


def test_the_check_html_ends_with_one_line_that_says_locally_because_check_fetches_nothing(capsys, no_network):
    page = page_of(capsys, check_args())
    digest = documented_digest([json.loads(go(capsys, check_args())[1])])
    assert footer_of(page) == f"Checked locally with {LINK} ({FACTS} · digest: <code>{digest}</code>)"
    assert page.count("0 LLM calls") == 1


def test_the_audit_html_from_a_cache_says_audited_locally_with_no_request(capsys, no_network):
    page = page_of(capsys, audit_args())
    digest = documented_digest([json.loads(go(capsys, audit_args())[1])])
    assert footer_of(page) == f"Audited locally with {LINK} ({FACTS} · digest: <code>{digest}</code>)"


def test_a_live_audit_names_what_it_fetched_and_does_not_say_locally(monkeypatch, capsys, no_network):
    live_osv(monkeypatch)
    page = page_of(capsys, audit_args(cache=None))
    assert footer_of(page) == f"Audited with {LINK} ({FACTS} · OSV advisories from api.osv.dev · digest: <code>{digest_of(page)}</code>)"
    assert "locally" not in page


def test_the_digest_of_a_live_audit_and_of_a_cached_audit_of_the_same_advisories_is_the_same(monkeypatch, capsys, no_network):
    cached = digest_of(page_of(capsys, audit_args()))
    live_osv(monkeypatch)
    assert digest_of(page_of(capsys, audit_args(cache=None))) == cached


def test_a_live_audit_that_asks_for_the_actions_export_names_that_host_too():
    traffic = external.Traffic()

    def opener(req, timeout=None):
        if req.full_url == external.OSV_NAMES.format(ecosystem="GitHub%20Actions"):
            return io.BytesIO(EXPORT)
        return io.BytesIO(json.dumps({"results": [{} for _ in json.loads(req.data)["queries"]]}).encode())

    external.fetch_advisories([n for n in read_path(WORKFLOW)[0] if n["kind"] == "Package"], opener=traffic.wrap(opener))
    assert traffic.hosts == ["osv-vulnerabilities.storage.googleapis.com", "api.osv.dev"]
    assert signature.phrases(traffic.hosts) == ("OSV package names from osv-vulnerabilities.storage.googleapis.com",
                                                "OSV advisories from api.osv.dev")


def test_a_run_whose_traffic_was_not_recorded_says_neither_locally_nor_what_it_fetched():
    def line(fetched, verb="Checked") -> str:
        return signature.Signature(verb, "9.9.9", "abc", fetched).line(lambda url, label: label, str, str)

    assert line(None) == f"Checked with decisis 9.9.9 ({FACTS} · digest: abc)"
    assert line(()) == f"Checked locally with decisis 9.9.9 ({FACTS} · digest: abc)"
    assert line(signature.phrases(["osv.example"]), "Audited") == f"Audited with decisis 9.9.9 ({FACTS} · data from osv.example · digest: abc)"


def test_the_digest_leaves_out_times_and_the_day_and_nothing_else():
    a = [{"today": "2026-01-01", "meta": {"extracted_at": "t1", "repo": "R"}, "findings": [{"fetched_at": "t1", "id": 1, "days_left": 3}]}]
    b = [{"findings": [{"days_left": 9, "id": 1, "fetched_at": "t2"}], "meta": {"repo": "R", "extracted_at": "t2"}, "today": "2027-01-01"}]
    assert signature.digest(a) == signature.digest(b) == documented_digest(a)
    assert re.fullmatch(r"[0-9a-f]{12}", signature.digest(a))
    for other in ([{**a[0], "meta": {"repo": "S"}}], [{**a[0], "findings": [{"id": 2}]}], a + a, []):
        assert signature.digest(other) != signature.digest(a)


def test_the_same_inputs_give_the_same_digest_on_any_day_with_any_fetch_time_and_a_changed_result_changes_it(tmp_path, capsys, no_network):
    first = digest_of(page_of(capsys, audit_args()))
    assert digest_of(page_of(capsys, audit_args())) == first
    assert digest_of(page_of(capsys, audit_args(today="2027-02-02"))) == first
    cache = json.loads(CACHE.read_text(encoding="utf-8"))
    cache["fetched_at"] = "2030-01-01T00:00:00Z"
    later = tmp_path / "later.json"
    later.write_text(json.dumps(cache), encoding="utf-8")
    assert digest_of(page_of(capsys, audit_args(cache=later))) == first
    snap = json.loads((FIX / "audit" / "vinc.json").read_text(encoding="utf-8"))
    snap["meta"]["extracted_at"] = "2030-01-01T00:00:00Z"
    moved = tmp_path / "moved.json"
    moved.write_text(json.dumps(snap), encoding="utf-8")
    assert digest_of(page_of(capsys, audit_args(snapshot=moved))) == first
    for node in snap["nodes"]:
        node.get("props", {}).pop("rule", None)
    bare = tmp_path / "bare.json"
    bare.write_text(json.dumps(snap), encoding="utf-8")
    assert digest_of(page_of(capsys, audit_args(snapshot=bare))) != first


def test_the_check_digest_follows_the_result_and_not_the_day(capsys, no_network):
    first = digest_of(page_of(capsys, check_args()))
    assert digest_of(page_of(capsys, check_args(today="2027-03-03"))) == first
    assert digest_of(page_of(capsys, check_args(files=CHANGED[:2]))) != first


@pytest.mark.parametrize("name,args,code", [("check", check_args(), 1), ("audit", audit_args(), 0)])
def test_with_the_flag_the_html_is_the_page_without_the_line_and_nothing_else_changes(name, args, code, capsys, no_network):
    signed = go(capsys, [*args, "--format", "html"])
    plain = go(capsys, [*args, "--format", "html", "--no-signature"])
    assert signed[0] == plain[0] == code
    assert "signature" not in plain[1] and "0 LLM calls" not in plain[1] and "github.com/Vinculums" not in plain[1]
    assert without_line(signed[1]) == plain[1] and signed[1] != plain[1]


@pytest.mark.parametrize("name", ["check", "audit"])
def test_the_page_with_the_line_is_the_committed_golden_page_and_the_line(name, capsys, no_network):
    golden = (GOLDEN / f"{name}.html").read_text(encoding="utf-8")
    args = check_args(today=DAY) if name == "check" else audit_args()
    page = page_of(capsys, args)
    assert without_line(page) == golden
    assert page == golden.replace("</main>", f"{LINE.search(page).group(0)}</main>")


OTHER_FORMATS = [(name, args, code, fmt) for name, args, code in (("check", check_args(), 1), ("audit", audit_args(), 0))
                 for fmt in ("json", "sarif", "mermaid", *(("text",) if name == "check" else ()))]


@pytest.mark.parametrize("name,args,code,fmt", OTHER_FORMATS)
def test_no_other_format_changes_with_the_flag_and_none_has_a_signature(name, args, code, fmt, capsys, no_network):
    on = go(capsys, [*args, "--format", fmt])
    off = go(capsys, [*args, "--format", fmt, "--no-signature"])
    assert on == off and on[0] == code
    assert "0 LLM calls" not in on[1] and "digest:" not in on[1]
    if fmt in ("json", "sarif"):
        assert "signature" not in on[1].lower() and "decisis 9.9.9" not in on[1]


def test_the_flag_is_on_check_and_audit_only_and_the_help_names_it(capsys):
    for command in ("check", "audit"):
        with pytest.raises(SystemExit):
            cli.main([command, "--help"])
        assert "--no-signature" in capsys.readouterr().out
    with pytest.raises(SystemExit) as e:
        cli.main(["impact", str(FIX / "impact" / "vinc.json"), "reports/export.py", "--format", "html", "--no-signature"])
    assert e.value.code == 2


def test_the_html_escapes_a_hostile_version_and_a_hostile_host_and_links_only_to_the_tool():
    sig = signature.Signature("Checked", HOSTILE, "abc123", signature.phrases([HOSTILE]))
    page = render.html("paths", {"loaded": {"nodes": 0, "edges": 0}, "paths": []}, sig)
    assert "<script" not in page.lower() and "<img" not in page.lower()
    assert "&lt;script&gt;" in footer_of(page)
    assert re.findall(r'<a [^>]*href="([^"]*)"', page) == [signature.HOME]


def comment(tmp_path: Path, repository: tuple[Path, str] | None = None, **extra) -> tuple[int, str, FakeGitHub]:
    root, base = repository or shop(tmp_path)
    fake = FakeGitHub()
    code = action.main(environment(tmp_path, root, base, **extra), fake)
    (_, _, data), = fake.writes()
    return code, data["body"], fake


def snapshot_text() -> str:
    return action.code(str(FIX / "check" / "vinc.json"))


def last_line(body: str) -> str:
    return body.rstrip("\n").splitlines()[-1]


def test_the_comment_ends_with_one_footer_that_holds_the_signature_the_snapshot_and_the_update_note(tmp_path, no_network):
    _, body, fake = comment(tmp_path)
    digest = digest_of(last_line(body))
    assert last_line(body) == ('<sub>Checked with <a href="https://github.com/Vinculums/decisis">decisis 9.9.9</a> '
                               f"({FACTS} · pull request reviews from api.github.com · digest: <code>{digest}</code>), "
                               f"snapshot {snapshot_text()}. This comment is updated on each run.</sub>")
    assert body.count("<sub>") == 1 and body.count("0 LLM calls") == 1 and "locally" not in body
    assert [u for m, u, _, _ in fake.sent if m == "GET" and "/reviews" in u]


def test_the_comment_digest_is_the_same_for_the_same_inputs_on_another_day_and_changes_with_the_result(tmp_path, no_network):
    (tmp_path / "repo").mkdir()
    held = shop(tmp_path / "repo")

    def digest(where: str, **extra) -> str:
        (tmp_path / where).mkdir()
        return digest_of(last_line(comment(tmp_path / where, held, **extra)[1]))

    first = digest("a")
    assert digest("b", DECISIS_TODAY="2027-05-05") == first
    assert digest("c", DECISIS_SNAPSHOT=str(FIX / "action" / "vinc.json")) != first


def test_a_comment_with_an_audit_says_audited_and_one_whose_audit_found_nothing_says_checked(tmp_path, no_network):
    root, base = shop(tmp_path)
    fake = FakeGitHub()
    assert action.main(audit_env(tmp_path, root, base, str(FIX / "audit" / "demo-lockfile.json")), fake) == 0
    (_, _, data), = fake.writes()
    assert last_line(data["body"]).startswith("<sub>Audited with <a href=") and "api.osv.dev" not in data["body"]
    other = tmp_path / "other"
    other.mkdir()
    root, base = shop(other)
    fake = FakeGitHub()
    assert action.main(audit_env(other, root, base, action.AUTO), fake) == 0
    (_, _, data), = fake.writes()
    assert last_line(data["body"]).startswith("<sub>Checked with <a href=")


def test_a_comment_whose_audit_fetched_from_osv_names_both_hosts(tmp_path, monkeypatch, no_network):
    live_osv(monkeypatch)
    root, base = shop(tmp_path)
    env = audit_env(tmp_path, root, base, str(FIX / "audit" / "demo-lockfile.json"))
    env["DECISIS_OSV_CACHE"] = ""
    fake = FakeGitHub()
    assert action.main(env, fake) == 0
    (_, _, data), = fake.writes()
    last = last_line(data["body"])
    assert f"{FACTS} · pull request reviews from api.github.com · OSV advisories from api.osv.dev · digest: " in last
    assert last.startswith("<sub>Audited with <a href=") and "locally" not in last


def test_a_shallow_checkout_that_fetches_the_base_says_so_and_a_full_one_does_not(tmp_path, no_network):
    root, base = shop(tmp_path)
    clone = tmp_path / "clone"
    subprocess.run(["git", "clone", "-q", "--depth", "1", f"file://{root}", str(clone)], check=True, capture_output=True)
    traffic = external.Traffic()
    action.fetch_base(root, base, traffic)
    assert traffic.hosts == []
    fake = FakeGitHub()
    assert action.main(environment(tmp_path, clone, base), fake) == 0
    (_, _, data), = fake.writes()
    assert f"{FACTS} · git history from the origin remote · pull request reviews from api.github.com · digest: " in last_line(data["body"])
    action.fetch_base(clone, base, traffic)
    assert traffic.hosts == []


def test_the_run_that_judged_nothing_has_no_signature_because_no_check_ran(tmp_path, no_network):
    root, base = repository(tmp_path, {"src/payments/charge.py": "A = 1\n"}, {"src/payments/charge.py": "A = 2\n", ADR: adr()})
    fake = FakeGitHub()
    assert action.main(env_for(tmp_path, root, base), fake) == 0
    (_, _, data), = fake.writes()
    body = data["body"]
    assert "No decisions exist on the base commit" in body and "0 LLM calls" not in body and body.count("<sub>") == 1
    assert last_line(body).startswith("<sub>decisis ")


@pytest.mark.parametrize("value", ["false", "FALSE", "no", "0"])
def test_the_input_set_to_false_leaves_the_footer_as_it_was_and_changes_nothing_else(value, tmp_path, no_network):
    for name in ("on", "off", "repo"):
        (tmp_path / name).mkdir()
    held = shop(tmp_path / "repo")
    flags = {"DECISIS_FAIL_ON_VIOLATION": "true", "DECISIS_SARIF": "true"}
    code_on, on, _ = comment(tmp_path / "on", held, GITHUB_WORKSPACE=str(tmp_path / "on"), **flags)
    code_off, off, _ = comment(tmp_path / "off", held, GITHUB_WORKSPACE=str(tmp_path / "off"), DECISIS_SIGNATURE=value, **flags)
    old = f"<sub>decisis 9.9.9, snapshot {snapshot_text()}. This comment is updated on each run.</sub>\n"
    assert code_on == code_off == 1
    assert off.endswith(old) and "0 LLM calls" not in off and "decisis 9.9.9</a>" not in off
    assert on[:on.rindex("<sub>")] == off[:-len(old)]
    plain = lambda name: {k: v for k, v in outputs(tmp_path / name).items() if k != "sarif-file"}
    assert plain("on") == plain("off")
    assert (tmp_path / "on" / "decisis.sarif").read_text(encoding="utf-8") == (tmp_path / "off" / "decisis.sarif").read_text(encoding="utf-8")


@pytest.mark.parametrize("value", ["", "true", "yes", "1"])
def test_the_footer_is_signed_when_the_input_is_true_or_empty(value, tmp_path, no_network):
    assert "0 LLM calls" in comment(tmp_path, DECISIS_SIGNATURE=value)[1]


def test_a_value_that_is_not_true_or_false_stops_the_step_before_any_request(tmp_path, capsys, no_network):
    root, base = shop(tmp_path)
    fake = FakeGitHub()
    assert action.main(environment(tmp_path, root, base, DECISIS_SIGNATURE="maybe"), fake) == 2
    assert fake.sent == [] and "DECISIS_SIGNATURE must be true or false" in capsys.readouterr().out


def test_the_input_is_true_by_default_reaches_python_through_the_environment_and_is_documented():
    doc = yaml.safe_load((ROOT / "action.yml").read_text(encoding="utf-8"))
    assert doc["inputs"]["signature"]["default"] == "true"
    step, = (s for s in doc["runs"]["steps"] if s.get("id") == "check")
    assert step["env"]["DECISIS_SIGNATURE"] == "${{ inputs.signature }}"
    assert "${{" not in step["run"] and "signature" not in step["run"]
    row, = re.findall(r"^\| `signature` \|.*$", DOCS["action"], re.M)
    assert "`true`" in row and "`false`" in row and "digest" in row
    assert "--no-signature" in DOCS["commands"]


def test_the_digest_is_defined_in_the_data_model_the_way_the_code_computes_it(capsys, no_network):
    doc = DOCS["data-model"]
    section = " ".join(doc[doc.index("## The signature"):].split("\n## ", 1)[0].split())
    assert "SHA-256" in section and f"first {signature.DIGEST_LENGTH} hexadecimal" in section
    assert all(f"`{key}`" in section for key in signature.VOLATILE)
    assert "sorted keys" in section and "no spaces" in section and "ASCII" in section
    for word in ("Checked", "Audited", "locally", "api.osv.dev", "api.github.com", "nothing was judged"):
        assert word in section
    shown = re.search(r"digest: ([0-9a-f]{12})\)", section).group(1)
    assert digest_of(page_of(capsys, audit_args())) == shown


def many_violations() -> dict:
    many = [{"file": f"src/{'x' * 200}{i}.py", "line": i, "decision": f"decision:d{i}", "rule": "imports_forbidden",
             "verdict": "violated", "why": "w" * 300, "import": "db", "target": "db.py"} for i in range(3000)]
    return {"changed": [r["file"] for r in many], "governing": [], "superseded": [], "violations": many, "unresolved": [], "impact": [], "rules": []}


def test_the_signature_is_the_last_line_when_the_lists_are_cut_to_fit(no_network):
    o = action.Outcome(many_violations(), pull(), [], "9.9.9", "s.json", contacted=())
    out = action.body(o)
    assert len(out) <= action.MAX_BODY and "Cut to fit GitHub's 65,536-character limit" in out
    assert out.endswith(action.footer(o) + "\n") and "<sub>Checked locally with" in out and out.count("<sub>") == 1


def test_the_signature_survives_the_last_resort_cut_and_without_it_the_cut_is_as_before(no_network):
    notes = ["n" * 1000] * 100
    signed = action.Outcome(many_violations(), pull(), [], "9.9.9", "s.json", notes=list(notes), contacted=())
    out = action.body(signed)
    assert len(out) <= action.MAX_BODY and "The comment was cut at GitHub's limit." in out
    assert out.endswith(action.footer(signed) + "\n") and out.count("<sub>") == 1
    plain = action.Outcome(many_violations(), pull(), [], "9.9.9", "s.json", notes=list(notes), sign=False)
    cut = action.body(plain)
    assert len(cut) <= action.MAX_BODY and cut.endswith("\n\nThe comment was cut at GitHub's limit.\n") and "<sub>" not in cut


def test_a_hostile_version_reaches_the_comment_only_as_escaped_text(no_network):
    o = hostile_outcome()
    o.version, o.contacted = HOSTILE, ()
    last = last_line(action.body(o))
    for raw in ("<script", "<img", "<!--", "@everyone", "](", "**bold**", "‮", "\x00", ":shipit:", "$x$"):
        assert raw not in last
    assert last.startswith("<sub>Checked locally with <a href=") and last.endswith("</sub>")
    assert re.findall(r'<a href="([^"]*)"', last) == [signature.HOME]


def test_an_outcome_whose_traffic_was_not_recorded_is_not_called_local(no_network):
    empty = {"changed": [], "governing": [], "superseded": [], "violations": [], "unresolved": [], "impact": [], "rules": []}
    last = last_line(action.body(action.Outcome(empty, pull(), [], "9.9.9", "s.json")))
    assert last.startswith("<sub>Checked with <a href=") and "locally" not in last and "api." not in last
