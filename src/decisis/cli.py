from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path

from . import audit
from . import check
from . import checker
from . import compare
from . import cypher
from . import demo
from . import external
from . import github as gh
from . import impact
from . import init
from . import inventory
from . import madr
from . import patch
from . import render
from . import rules
from . import sarif
from . import signature
from . import commit as wb
from . import checkout as co
from .queries import load as query
from . import sandbox as sb
from .sandbox import sandbox

MAX_LIMIT = 100
VIEWS = {"mermaid": render.mermaid, "html": render.html}
ROOT_HELP = ("files next to the inventory (go.sum, pyproject.toml, -r includes) are read only under this directory "
             "(default: the nearest directory above the inventory that holds .git, else the inventory's directory)")


def bounded(lo: int, hi: int):
    def parse(text: str) -> int:
        try:
            value = int(text)
        except ValueError:
            raise argparse.ArgumentTypeError(f"{text!r} is not a whole number") from None
        if not lo <= value <= hi:
            raise argparse.ArgumentTypeError(f"{value} is outside {lo} to {hi}")
        return value
    return parse


def day(text: str):
    try:
        return rules.today(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"{text!r} is not a date such as 2026-01-31") from None


TODAY_HELP = ("judge waivers as of this UTC date, YYYY-MM-DD, and treat a decision whose valid_until is on or before it as closed "
              "(default: today in UTC)")
IMPACT_TODAY_HELP = "treat a decision whose valid_until is on or before this UTC date, YYYY-MM-DD, as closed (default: today in UTC)"
WARN_HELP = ("list under expiring_soon the waivers that cover a result and expire within N days of the run's date, 0 turns it off "
             f"(default {rules.WARN_DAYS}, at most {rules.MAX_WARN_DAYS}); this never changes a verdict or the exit code")


SIGNATURE_HELP = ("leave the one-line signature (the decisis version, the facts of the run and a digest of the result) out of --format html; "
                  "no other output changes")


def signature_flag(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--no-signature", dest="signature", action="store_false", help=SIGNATURE_HELP)


def warn_flag(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--warn-days", type=bounded(0, rules.MAX_WARN_DAYS), default=rules.WARN_DAYS, metavar="N", help=WARN_HELP)


def limit_flags(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--max-nodes", type=bounded(1, sb.CEILING_NODES), metavar="N",
                        help=f"refuse a graph with more nodes (default {sb.MAX_NODES} or DECISIS_MAX_NODES, at most {sb.CEILING_NODES})")
    parser.add_argument("--max-edges", type=bounded(1, sb.CEILING_EDGES), metavar="N",
                        help=f"refuse a graph with more edges (default {sb.MAX_EDGES} or DECISIS_MAX_EDGES, at most {sb.CEILING_EDGES})")
    parser.add_argument("--query-timeout", type=bounded(1, sb.CEILING_SECONDS), metavar="SECONDS",
                        help=f"stop a query that runs longer (default {sb.QUERY_SECONDS} or DECISIS_QUERY_TIMEOUT, at most {sb.CEILING_SECONDS})")


def limits(a: argparse.Namespace) -> sb.Limits:
    return sb.Limits.resolve(a.max_nodes, a.max_edges, a.query_timeout)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="decisis")
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("checkout", help="export a bounded subgraph from Vinc to a JSON snapshot")
    c.add_argument("seeds", nargs="+")
    c.add_argument("--depth", type=int, default=1)
    c.add_argument("--out", required=True)
    ini = sub.add_parser("init", help="build a snapshot from a repository's ADRs, CODEOWNERS and postmortems, and merged pull requests")
    ini.add_argument("--repo-dir", help="the repository to read (default: the current directory, or none with --github)")
    ini.add_argument("--repo", help="the repository name to put before each code path, for example Shop")
    ini.add_argument("--adr-dir", help=f"read ADRs only from this directory, relative to --repo-dir (default: {', '.join(init.ADR_DIRS)})")
    ini.add_argument("--postmortem-dir", help=f"read postmortems only from this directory, relative to --repo-dir (default: {', '.join(init.POSTMORTEM_DIRS)})")
    ini.add_argument("--github", metavar="OWNER/REPO", help="also read merged pull requests from GitHub, with GITHUB_TOKEN when it is set")
    ini.add_argument("--label", help="with --github: select pull requests with this label (default: decision) or a ## Decision section")
    ini.add_argument("--since", help="with --github: read pull requests merged on or after this date, for example 2026-01-31")
    ini.add_argument("--limit", type=bounded(1, gh.MAX_LIMIT), metavar="N",
                     help=f"with --github: read at most N closed pull requests, most recently updated first (default {gh.DEFAULT_LIMIT}, at most {gh.MAX_LIMIT})")
    ini.add_argument("--suggest-refs", action="store_true",
                     help="give each ADR that states no code path the existing files and directories its text names, as suggested code_ref")
    ini.add_argument("--patch", metavar="FILE",
                     help="with --suggest-refs: write a unified diff that adds each suggested code_ref to its ADR's front matter; no ADR is changed, and FILE must not exist and must lie outside the ADR directories")
    ini.add_argument("--out", required=True)
    na = sub.add_parser("new-adr", help="write the next-numbered MADR file with status proposed and the code refs and rule given")
    na.add_argument("title")
    na.add_argument("--repo-dir", default=".", help="the repository to write into (default: the current directory)")
    na.add_argument("--adr-dir", help=f"the ADR directory, relative to --repo-dir (default: the first of {', '.join(init.ADR_DIRS)} that exists)")
    na.add_argument("--code-ref", action="append", default=[], metavar="PATH", help="a path from the repository root the decision governs; repeat for more")
    na.add_argument("--rule", metavar="JSON", help='one JSON object read as audit and check read it, for example \'{"review_required": {"paths": ["src/**"], "reviewers": ["@org/team"]}}\'')
    na.add_argument("--waiver", action="append", default=[], metavar="JSON",
                    help='one waiver as a JSON object, for example \'{"path": "src/legacy/**", "rule": "review_required", '
                         '"reason": "frozen code", "expires": "2027-01-31", "approved_by": "@org/team"}\'; repeat for more')
    na.add_argument("--date", help="the date in the front matter (default: today)")
    p = sub.add_parser("paths", help="load a snapshot into a throwaway Relate file and list paths between two ids")
    p.add_argument("snapshot")
    p.add_argument("source")
    p.add_argument("target")
    p.add_argument("--hops", type=bounded(1, impact.MAX_HOPS), default=4, help=f"longest path to look for (1 to {impact.MAX_HOPS})")
    p.add_argument("--limit", type=bounded(1, MAX_LIMIT), default=10, help=f"most paths to return (1 to {MAX_LIMIT})")
    p.add_argument("--format", choices=["json", *VIEWS], default="json")
    im = sub.add_parser("impact", help="list the decisions, records and concepts that govern one or more code paths")
    im.add_argument("snapshot")
    im.add_argument("code_paths", nargs="+", metavar="code_path", help="a file or directory, for example reports/export.py or storage/")
    im.add_argument("--hops", type=bounded(0, impact.MAX_HOPS), default=3, help=f"how far from a matching concept to look (0 to {impact.MAX_HOPS})")
    im.add_argument("--repo", help="skip code_refs that name another repository, for example Demo")
    im.add_argument("--format", choices=["json", "text", *VIEWS], default="json")
    im.add_argument("--today", type=day, metavar="DATE", help=IMPACT_TODAY_HELP)
    ck = sub.add_parser("check", help="judge a change set against the review and import rules of the decisions in a snapshot; exits 1 on a violation")
    ck.add_argument("snapshot")
    ck.add_argument("--repo-dir", default=".", help="the repository the changed files are read from (default: the current directory)")
    which = ck.add_mutually_exclusive_group(required=True)
    which.add_argument("--changed", nargs="+", metavar="FILE", help="the changed files, relative to --repo-dir")
    which.add_argument("--base", metavar="REF", help="list the changed files with git diff --name-only REF...HEAD in --repo-dir")
    ck.add_argument("--reviewers", nargs="+", default=[], metavar="HANDLE", help="the handles that reviewed the change, for example @alice @org/team")
    ck.add_argument("--fail-on-unresolved", action="store_true", help="also exit 1 when an import or a file cannot be judged, or a decision file was not read")
    ck.add_argument("--hops", type=bounded(0, impact.MAX_HOPS), default=3, help=f"how far impact looks from a matching concept (0 to {impact.MAX_HOPS})")
    ck.add_argument("--repo", help="skip code_refs that name another repository, for example Demo")
    ck.add_argument("--format", choices=["json", "text", *VIEWS, "sarif"], default="json")
    ck.add_argument("--today", type=day, metavar="DATE", help=TODAY_HELP)
    warn_flag(ck)
    signature_flag(ck)
    au = sub.add_parser("audit", help="join a Vinc snapshot, a lockfile or SBOM and OSV advisories in a throwaway Relate graph")
    au.add_argument("snapshot")
    au.add_argument("lockfile", help="package-lock.json, a CycloneDX or SPDX JSON SBOM, uv.lock, Cargo.lock, go.mod (read with the go.sum next to it), "
                    "a GitHub Actions workflow (read with the workflows next to it), action.yml, .terraform.lock.hcl, or another format in the README")
    au.add_argument("--repo", required=True, help="repository name as it appears in Vinc code_ref, for example Vinc")
    au.add_argument("--depth", type=bounded(1, audit.MAX_DEPTH), default=8, help=f"longest dependency chain to follow (1 to {audit.MAX_DEPTH})")
    au.add_argument("--out", help="write the JSON report here; with --format mermaid, html or sarif the view still goes to stdout")
    au.add_argument("--format", choices=["json", *VIEWS, "sarif"], default="json")
    au.add_argument("--osv-cache", metavar="FILE", help="read OSV advisories from this file and never from the network")
    au.add_argument("--root", type=Path, metavar="DIR", help=ROOT_HELP)
    au.add_argument("--today", type=day, metavar="DATE", help=TODAY_HELP)
    warn_flag(au)
    signature_flag(au)
    pr = sub.add_parser("propose", help="re-derive an audit report's records and print the exact write set the owner approves")
    pr.add_argument("report")
    pr.add_argument("snapshot", help="the snapshot the audit read")
    pr.add_argument("lockfile", help="the lockfile or SBOM the audit read (for go.mod, the go.sum next to it is read too)")
    pr.add_argument("--repo", required=True)
    pr.add_argument("--space", required=True)
    pr.add_argument("--out", required=True)
    pr.add_argument("--lockfile-path", help="the lockfile path inside the repository, for subject_path (default: package-lock.json for an npm lockfile, else the file's name)")
    pr.add_argument("--ref", help="the commit the lockfile was read at, for measured_ref")
    pr.add_argument("--depth", type=bounded(1, audit.MAX_DEPTH), default=8, help=f"the audit's --depth, for the dependency paths (1 to {audit.MAX_DEPTH})")
    pr.add_argument("--osv-cache", metavar="FILE", help="read OSV advisories from this file and never from the network")
    pr.add_argument("--root", type=Path, metavar="DIR", help=ROOT_HELP)
    cm = sub.add_parser("commit", help="write an approved write set to Vinc and read it back (needs a full key)")
    cm.add_argument("plan")
    cm.add_argument("--approve", required=True, help="the approval digest printed by propose")
    dm = sub.add_parser("demo", help="run the whole sandbox procedure on synthetic data, offline, against an in-process fake Vinc")
    dm.add_argument("--out", default="demo", help="where the transcript, the expected findings and the sample Relate database go")
    dm.add_argument("--fixtures", type=Path, help="the fixtures directory (default: the one in this repository)")
    ok = dm.add_mutually_exclusive_group()
    ok.add_argument("--approve", metavar="DIGEST", help="approve the write set with the digest the demo prints")
    ok.add_argument("--yes", action="store_true", help="approve the demo write set without typing the digest")
    cp = sub.add_parser("compare", help="run the benchmark: Vinc retrieval (A), a text join (B) and the Relate graph (C) on the same tasks")
    cp.add_argument("--tasks", type=Path, help="the task file with expected findings (default: bench/tasks.json in this repository)")
    cp.add_argument("--out", type=Path, help="write the full results as JSON here")
    cp.add_argument("--table", type=Path, help="write the results table as Markdown here")
    gc = sub.add_parser("gc", help="remove task directories that a killed run left behind")
    gc.add_argument("--root", type=Path, help="the directory that holds the task directories (default: /dev/shm, or the system temporary directory)")
    gc.add_argument("--grace", type=bounded(0, 86400), default=sb.GRACE_SECONDS, metavar="SECONDS",
                    help=f"leave directories younger than this (default {sb.GRACE_SECONDS})")
    qy = sub.add_parser("query", help="run one read-only Cypher statement on a throwaway Relate graph of a snapshot and print the rows as JSON")
    qy.add_argument("snapshot")
    qy.add_argument("cypher", help="one statement that starts with MATCH, OPTIONAL MATCH, WITH, UNWIND, RETURN or CALL; writes are refused")
    qy.add_argument("--param", action="append", default=[], type=param, metavar="KEY=VALUE",
                    help="a value for $KEY; VALUE is read as JSON when it parses (12, true, [1, 2]), else as text")
    for s in (p, im, ck, au, pr, qy):
        limit_flags(s)
    sv = sub.add_parser("serve", help="serve impact, paths, audit, check and query to an agent as a read-only MCP server over stdio (needs decisis[mcp])")
    sv.add_argument("--mcp", action="store_true", required=True, help="speak MCP over stdin and stdout")
    sv.add_argument("--snapshot", type=Path, required=True, help="the JSON snapshot every tool call reads")
    sv.add_argument("--osv-cache", type=Path, metavar="FILE", help="audit reads OSV advisories from this file and never from the network")
    sv.add_argument("--allow-network", action="store_true", help="let audit ask api.osv.dev when there is no --osv-cache")
    sv.add_argument("--root", type=Path, default=Path("."), help="audit reads lockfiles and check reads changed files and runs git diff only under this directory (default: the current one)")
    a = ap.parse_args(argv)
    try:
        return run(a)
    except (OSError, UnicodeDecodeError) as e:
        ap.exit(1, f"{ap.prog}: error: {e}\n")
    except ValueError as e:
        ap.error(str(e))
    except (external.NetworkRefused, external.NetworkFailed, gh.GitHubFailed, sb.LimitExceeded, sb.relate.Error) as e:
        ap.exit(1, f"{ap.prog}: error: {e}\n")


PARAM_KEY = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,63}")


def param(text: str) -> tuple[str, object]:
    key, sep, raw = text.partition("=")
    if not sep or not PARAM_KEY.fullmatch(key):
        raise argparse.ArgumentTypeError(f"{text!r} is not KEY=VALUE with a parameter name for KEY")
    try:
        return key, json.loads(raw)
    except ValueError:
        return key, raw


def params_of(pairs: list[tuple[str, object]]) -> dict:
    out: dict = {}
    for key, value in pairs:
        if key in out:
            raise ValueError(f"--param {key} is given twice")
        out[key] = value
    return out


def serve(a: argparse.Namespace) -> int:
    try:
        from . import serve as mcp_server
    except ModuleNotFoundError as e:
        if (e.name or "").split(".")[0] not in ("mcp", "jsonschema", "anyio"):
            raise
        raise ValueError("serve --mcp needs the mcp extra: pip install 'decisis[mcp]'") from None
    return mcp_server.main(mcp_server.load_tools(a.snapshot, a.root, a.osv_cache, a.allow_network))


def subject_file(text: str, path: Path) -> str:
    return "package-lock.json" if inventory.detect(text, path.name) == "npm" else path.name


def run(a: argparse.Namespace) -> int:
    if a.cmd == "serve":
        return serve(a)
    if a.cmd == "gc":
        return gc(a.root or sb.default_root(), a.grace)
    if a.cmd == "compare":
        root = demo.default_fixtures().parent
        result = compare.run(root, a.tasks or root / "bench" / "tasks.json")
        if a.out:
            a.out.write_text(json.dumps(result, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
        table = compare.render(result)
        if a.table:
            a.table.write_text(table, encoding="utf-8")
        sys.stdout.write(table)
        return 0
    if a.cmd == "demo":
        return demo.run(Path(a.out), a.fixtures, approve=a.approve, yes=a.yes)[0]
    if a.cmd == "propose":
        lock_text, siblings = inventory.load(Path(a.lockfile), root=a.root)
        report = json.loads(Path(a.report).read_text(encoding="utf-8"))
        plan = wb.propose(report, a.repo, a.space, lockfile_path=a.lockfile_path or subject_file(lock_text, Path(a.lockfile)), ref=a.ref)
        advisories = external.fetch_advisories
        if a.osv_cache:
            advisories = external.cached_advisories(external.read_osv_cache(Path(a.osv_cache).read_text(encoding="utf-8")))
        plan, checked = checker.rederive(plan, co.load(Path(a.snapshot).read_text(encoding="utf-8")), lock_text, a.repo, advisories,
                                         a.depth, limits=limits(a), filename=Path(a.lockfile).name, siblings=siblings,
                                         day=rules.today(report["today"]) if isinstance(report.get("today"), str) else None)
        Path(a.out).write_text(init.dump(plan), encoding="utf-8")
        failed = sum(1 for c in checked if c["problems"])
        print(f"Re-derived {len(checked)} records with {sum(c['checks'] for c in checked)} checks; {failed} failed.\n")
        print(init.SURROGATE.sub(lambda m: f"\\u{ord(m.group()):04x}", wb.render(plan)))
        return 1 if failed else 0
    if a.cmd == "commit":
        plan = json.loads(Path(a.plan).read_text(encoding="utf-8"))
        wb.check_approval(plan, a.approve)
        client = co.VincMCP.from_env("full")
        client.space = plan["space"]
        receipt = wb.commit(plan, a.approve, client)
        print(json.dumps(receipt, ensure_ascii=False, indent=1))
        return 0 if receipt["verified"] else 1
    if a.cmd == "query":
        report = cypher.run(co.load(Path(a.snapshot).read_text(encoding="utf-8")), a.cypher, params_of(a.param), limits=limits(a))
        sys.stdout.write(init.dump(report))
        return 0
    if a.cmd == "impact":
        report = impact.run(co.load(Path(a.snapshot).read_text(encoding="utf-8")), a.code_paths, a.hops, a.repo, limits=limits(a), day=a.today)
        if a.format == "text":
            print(impact.render(report))
        elif a.format in VIEWS:
            sys.stdout.write(VIEWS[a.format]("impact", report))
        else:
            sys.stdout.write(init.dump(report))
        return 0
    if a.cmd == "check":
        return run_check(a)
    if a.cmd == "audit":
        traffic = external.Traffic()
        advisories = external.live_advisories(traffic)
        if a.osv_cache:
            advisories = external.cached_advisories(external.read_osv_cache(Path(a.osv_cache).read_text(encoding="utf-8")))
        text, siblings = inventory.load(Path(a.lockfile), root=a.root)
        report = audit.run(co.load(Path(a.snapshot).read_text(encoding="utf-8")), text, a.repo, a.depth,
                           advisories=advisories, limits=limits(a), filename=Path(a.lockfile).name, siblings=siblings, day=a.today,
                           warn_days=a.warn_days)
        text = init.dump(report)[:-1]
        if a.format in VIEWS or a.format == "sarif":
            if a.out:
                Path(a.out).write_text(text + "\n", encoding="utf-8")
            sys.stdout.write(view(a, "audit", report, signature.AUDITED, traffic) if a.format in VIEWS
                             else sarif.dumps(sarif.log([sarif.audit_run(report, sarif.inventory_path(Path(a.lockfile), a.root))])))
        elif a.out:
            Path(a.out).write_text(text + "\n", encoding="utf-8")
            print(json.dumps({"summary": report["summary"], "violations": report["violations"], "waived": report["waived"], "loaded": report["loaded"],
                              "unresolved_packages": len(report["unresolved_packages"]), "inventory_notes": report["inventory_notes"],
                              **({"unread_decisions": len(report["unread_decisions"])} if report.get("unread_decisions") else {}),
                              **({"not_governing": len(report["not_governing"])} if report.get("not_governing") else {}),
                              **({rules.EXPIRING: len(report[rules.EXPIRING])} if report.get(rules.EXPIRING) else {}),
                              "out": a.out}))
        else:
            sys.stdout.write(text + "\n")
        return 0
    if a.cmd == "init":
        readers, diff_file = init_readers(a), init_patch(a)
        snapshot = init.build(a.repo_dir or ".", a.repo, *readers, adr_dir=a.adr_dir, postmortem_dir=a.postmortem_dir,
                              suggest_refs=a.suggest_refs)
        made = patch.build(Path(os.path.abspath(a.repo_dir or ".")), snapshot) if diff_file is not None else None
        if made is not None and made.text:
            patch.write(diff_file, made)
        Path(a.out).write_text(init.dump(snapshot), encoding="utf-8")
        meta = snapshot["meta"]
        printed = {"out": a.out, "nodes": meta["nodes"], "edges": meta["edges"], "problems": meta["problems"]}
        if made is not None:
            printed["patch"] = {"out": a.patch if made.text else None, "adrs": len(made.adrs), "code_refs": made.refs,
                                "not_applied": len(made.skipped), "left_out": [{"file": f, "reason": r} for f, r in made.left_out]}
        sys.stdout.write(init.dump(printed))
        return 0
    if a.cmd == "new-adr":
        path = madr.write(a.repo_dir, a.title, a.adr_dir, a.code_ref, a.rule, a.date, a.waiver)
        print(json.dumps({"out": str(path)}, ensure_ascii=False))
        return 0
    if a.cmd == "checkout":
        graph = co.checkout(co.VincMCP.from_env(), a.seeds, a.depth)
        Path(a.out).write_text(co.dump(graph), encoding="utf-8")
        print(json.dumps(graph.meta))
        return 0
    graph = co.load(Path(a.snapshot).read_text(encoding="utf-8"))
    with sandbox(limits=limits(a)) as box:
        counts = box.load(graph)
        rows = box.query(query("paths_between", hops=a.hops, limit=a.limit), {"source": a.source, "target": a.target})
    report = {"loaded": counts, "paths": rows}
    if a.format in VIEWS:
        sys.stdout.write(VIEWS[a.format]("paths", render.annotate_paths(report, graph, a.source, a.target)))
        return 0
    sys.stdout.write(init.dump(report))
    return 0


def view(a: argparse.Namespace, kind: str, report: dict, verb: str, traffic: external.Traffic) -> str:
    if a.format == "html" and a.signature:
        return render.html(kind, report, signature.of(verb, [report], traffic.hosts))
    return VIEWS[a.format](kind, report)


def run_check(a: argparse.Namespace) -> int:
    root = Path(a.repo_dir)
    if not root.is_dir():
        raise ValueError(f"--repo-dir {a.repo_dir} is not a directory")
    changed = check.changed_since(root, a.base) if a.base is not None else a.changed
    report = check.run(co.load(Path(a.snapshot).read_text(encoding="utf-8")), changed, root, a.reviewers, a.hops, a.repo,
                       base=a.base, limits=limits(a), day=a.today, warn_days=a.warn_days)
    if a.format == "text":
        print(check.render(report))
    elif a.format in VIEWS:
        sys.stdout.write(view(a, "check", report, signature.CHECKED, external.Traffic()))
    elif a.format == "sarif":
        sys.stdout.write(sarif.dumps(sarif.log([sarif.check_run(report)])))
    else:
        sys.stdout.write(init.dump(report))
    return 1 if check.failed(report, a.fail_on_unresolved) else 0


def init_patch(a: argparse.Namespace) -> Path | None:
    if a.patch is None:
        return None
    if not a.suggest_refs:
        raise ValueError("--patch writes the suggestions --suggest-refs makes, so it needs --suggest-refs")
    if a.github is not None and a.repo_dir is None:
        raise ValueError("--patch changes the ADRs of a repository directory, so with --github it needs --repo-dir")
    return patch.target(Path(os.path.abspath(a.repo_dir or ".")), a.patch, a.adr_dir, a.out)


def init_readers(a: argparse.Namespace) -> tuple:
    if a.github is None:
        if a.label is not None or a.since is not None or a.limit is not None:
            raise ValueError("--label, --since and --limit go with --github")
        return ()
    if a.repo_dir is None and (a.adr_dir is not None or a.postmortem_dir is not None):
        raise ValueError("with --github, --adr-dir and --postmortem-dir need --repo-dir")
    if a.label is not None and not a.label.strip():
        raise ValueError("--label must name a label")
    gh.repository(a.github)
    since = gh.since_date(a.since) if a.since is not None else None
    pulls = gh.PullReader(a.github, gh.clean_token(os.environ.get("GITHUB_TOKEN")), (a.label or "decision").strip(), since,
                          a.limit or gh.DEFAULT_LIMIT)
    return (*init.READERS, pulls) if a.repo_dir is not None else (pulls,)


def gc(root: Path, grace: int) -> int:
    if not sb.can_sweep():
        print("decisis gc: this platform cannot check the owner of a task directory safely; nothing was removed")
        return 0
    errors: list = []
    removed = sb.sweep(root, grace, errors)
    for path in removed:
        print(f"removed {path}")
    for path, why in errors:
        print(f"kept {path}: {why}")
    print(f"removed {len(removed)} task director{'y' if len(removed) == 1 else 'ies'} under {root}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
