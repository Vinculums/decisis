from __future__ import annotations

import json
import shutil
from datetime import datetime, timezone
from pathlib import Path

from . import audit, checker, external, rules
from . import checkout as co
from . import commit as wb
from .fake_vinc import FakeVinc
from .queries import load as query
from .sandbox import Sandbox

REPO = "Demo"
SEED = "concept:demo-app"
SPACE = "demo-space"
TAGLINE = "Persistent Knowledge. Ephemeral Reasoning."
SAMPLE = "sample.rl"


def default_fixtures() -> Path:
    for here in (Path(__file__).resolve().parents[2] / "fixtures", Path(__file__).resolve().parent / "fixtures"):
        if (here / "demo").is_dir():
            return here
    return Path("fixtures")


def _stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _arrows(ids: list[str], rels: list[str], graph) -> str:
    forward = {(e["source"], e["type"], e["target"]) for e in graph.edges}
    out = [ids[0]]
    for a, r, b in zip(ids, rels, ids[1:]):
        out.append(f"-{r}-> {b}" if (a, r, b) in forward else f"<-{r}- {b}")
    return " ".join(out)


def _violated(finding: dict) -> list[str]:
    return sorted(p["decision"] for p in finding["policies"] if p["verdict"] == "violated")


def _finding_line(f: dict) -> str:
    line = f"  {f['status']:<12} {f['severity']:<8} {f['advisory'].split(':', 1)[1]}  {f['package'].split('/', 1)[1]}"
    if f["dev_only"]:
        line += "  (development only)"
    if _violated(f):
        line += "  violates " + ", ".join(_violated(f))
    return line


def expected(report: dict, plan: dict, path: dict) -> dict:
    return {
        "repo": REPO,
        "summary": report["summary"],
        "violations": report["violations"],
        "findings": [{"package": f["package"], "advisory": f["advisory"], "severity": f["severity"], "status": f["status"],
                      "dev_only": f["dev_only"], "path": f["path"],
                      "violates": _violated(f)}
                     for f in report["findings"]],
        "multi_hop_path": path,
        "records": [n["id"] for n in plan["nodes"]],
        "edges": [[e["from"], e["type"], e["to"]] for e in plan["edges"]],
        "digest": plan["digest"],
    }


class Demo:
    def __init__(self, emit=print):
        self.emit, self.steps = emit, []

    def step(self, title: str, lines: list[str], **data) -> None:
        n = len(self.steps) + 1
        self.emit(f"\n{n}. {title}")
        for line in lines:
            self.emit(f"   {line}".rstrip())
        self.steps.append({"step": n, "title": title, "lines": lines, **({"data": data} if data else {})})


def run(out: Path, fixtures: Path | None = None, approve: str | None = None, yes: bool = False,
        sandbox_root: Path | None = None, emit=print) -> tuple[int, dict]:
    fixtures = fixtures or default_fixtures()
    stamps = {"started_at": _stamp()}
    demo = Demo(emit)
    emit(f"decisis demo: a dependency audit on synthetic data, offline. {TAGLINE}")

    space = co.load((fixtures / "demo" / "vinc_space.json").read_text(encoding="utf-8"))
    fake = FakeVinc(space, name=SPACE)
    before = fake.counts()
    demo.step("Vinc knowledge", [
        f"A synthetic Vinc space ({SPACE}) holds {before['nodes']} nodes and {before['edges']} edges: decisions, concepts and records",
        "for an app, a billing service and a design system. An in-process fake Vinc serves it; no account, no network.",
    ], space=SPACE, **before)

    demo.step("The task: a dependency audit", [
        f"Which security advisories does repository {REPO} reach through its npm lockfile,",
        "and which of the team's decisions do they break?",
    ], repo=REPO, lockfile="audit/demo-lockfile.json")

    vinc = co.checkout(fake, [SEED], 1)
    stamps["checked_out_at"] = vinc.meta.pop("extracted_at")
    demo.step("Checkout: only task-relevant knowledge", [
        f"Seed {SEED}, depth 1: {len(vinc.nodes)} of {before['nodes']} nodes and {len(vinc.edges)} of {before['edges']} edges come out.",
        *[f"  {n['id']}  ({n['title']})" for n in vinc.nodes],
        "Billing, design and CI knowledge stays in Vinc.",
    ], seeds=[SEED], depth=1, nodes=[n["id"] for n in vinc.nodes], edges=len(vinc.edges))

    cache = external.read_osv_cache((fixtures / "audit" / "osv-cache.json").read_text(encoding="utf-8"))
    lock = (fixtures / "audit" / "demo-lockfile.json").read_text(encoding="utf-8")
    graph = audit.compose(vinc, lock, REPO, external.cached_advisories(cache))
    box = Sandbox(sandbox_root)
    try:
        today = cache["fetched_at"][:10]
        report = audit.analyze(box, graph, REPO, day=rules.today(today))
        m = graph.meta
        demo.step("Relate graph: Vinc knowledge joined with external data", [
            "A private Relate file in a fresh 0700 directory under tmpfs; reasoning opens it read only.",
            f"Loaded {report['loaded']['nodes']} nodes and {report['loaded']['edges']} edges: {len(vinc.nodes)} Vinc nodes, "
            f"1 repository and {m['packages']} packages from the lockfile,",
            f"{m['advisories']} OSV advisories (cache fetched {cache['fetched_at']}) and {m['governance_links']} code_ref link from the repository to Vinc.",
        ], loaded=report["loaded"], packages=m["packages"], advisories=m["advisories"], governance_links=m["governance_links"])

        hit = next((f for f in report["findings"] for p in f["policies"] if p["verdict"] == "violated"), report["findings"][0])
        rule = next((p["decision"] for p in hit["policies"] if p["verdict"] == "violated"), report["governing"][0]["decision"])
        rows = box.query(query("decision_to_advisory", depth=8), {"decision": rule, "package": hit["package"], "advisory": hit["advisory"]})
        path = {"from": rule, "to": hit["advisory"], "ids": rows[0]["ids"], "rels": rows[0]["rels"], "hops": len(rows[0]["rels"])}
        s = report["summary"]
        demo.step("Multi-hop path: from a decision to an advisory", [
            f"{path['hops']} hops across Vinc knowledge, the lockfile and OSV:",
            "  " + _arrows(path["ids"], path["rels"], graph),
            f"Findings: {len(report['findings'])} package and advisory pairs; {s['affected']} affected, "
            f"{s['not_affected']} not affected, {s['unresolved']} unresolved; {report['violations']} decision violations.",
            *[_finding_line(f) for f in report["findings"]],
        ], path=path)

        plan = wb.propose(report, REPO, SPACE, today=today)
        checked = checker.check_plan(plan, box, checker.decisions(vinc), REPO)
        plan = checker.withhold(plan, checked)
        failed = [c for c in checked if c["problems"]]
        demo.step("Checker and approval", [
            f"The Checker re-derives each proposed record from the sandbox: {sum(c['checks'] for c in checked)} checks over "
            f"{len(checked)} records (advisory hash, version in range, path in the graph, decision in the checkout); "
            f"{len(failed)} records fail.",
            *[f"  {c['record']}: {p}" for c in failed for p in c["problems"]],
            *[line.rstrip() for line in wb.render(plan).splitlines() if not line.startswith("Approve with:")],
        ], checks=sum(c["checks"] for c in checked), records=len(checked), failed=[c["record"] for c in failed], digest=plan["digest"])

        findings = expected(report, plan, path)
        if failed:
            approval = {"status": "refused", "why": "the Checker failed a record"}
        elif approve is not None and approve != plan["digest"]:
            approval = {"status": "refused", "why": f"--approve {approve} does not match digest {plan['digest']}"}
        elif approve is not None or yes:
            approval = {"status": "approved", "digest": plan["digest"], "by": "--approve" if approve else "--yes"}
        else:
            approval = {"status": "pending", "digest": plan["digest"]}
        emit({"approved": f"   Approved by a person with {approval.get('by')} for digest {plan['digest']}.",
              "pending": f"   Waiting for a person: nothing is written. Run again with --approve {plan['digest']} (or --yes).",
              "refused": f"   Not approved: {approval.get('why')}. Nothing is written."}[approval["status"]])

        out.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(box.path, out / SAMPLE)
        sample_kb = round((out / SAMPLE).stat().st_size / 1024)
    finally:
        box.destroy()
    removed = not box.dir.exists()

    lines, receipt, survived = [], None, None
    if approval["status"] == "approved":
        receipt = wb.commit(plan, approval["digest"], fake)
        again = co.checkout(fake, receipt["written"], 1)
        stamps["read_back_at"] = again.meta.pop("extracted_at")
        want = {(e["from"], co.relation(e), e["to"]) for e in plan["edges"]}
        survived = len(want & {(e["source"], e["type"], e["target"]) for e in again.edges})
        lines += [f"Wrote {len(receipt['written'])} records and {receipt['edges']} edges to the fake Vinc with create_only.",
                  f"Read back: {'every node and edge matches' if receipt['verified'] else 'MISMATCH ' + '; '.join(receipt['problems'])}.",
                  f"A new checkout of the records finds {survived} of {len(want)} edges with their type and direction.",
                  f"The space now holds {fake.counts()['nodes']} nodes and {fake.counts()['edges']} edges."]
    else:
        lines.append("Nothing was written to Vinc.")
    lines += [f"Sample Relate database for judges: {out.name}/{SAMPLE} ({sample_kb} KB, synthetic data only).",
              f"Operational sandbox deleted: {'yes' if removed else 'NO'}."]
    demo.step("Commit, read-back and cleanup", lines, sandbox_removed=removed, sample=SAMPLE,
              receipt=receipt, edges_after_checkout=survived)

    stamps["finished_at"] = _stamp()
    transcript = {"demo": "decisis dependency audit on synthetic data", "tagline": TAGLINE, "steps": demo.steps,
                  "approval": approval, "findings": findings, "timestamps": stamps}
    (out / "transcript.json").write_text(json.dumps(transcript, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    (out / "expected_findings.json").write_text(json.dumps(findings, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    emit(f"\nTranscript: {(out / 'transcript.json').as_posix()}; expected findings: {(out / 'expected_findings.json').as_posix()}")
    ok = removed and (approval["status"] == "pending" or (receipt is not None and receipt["verified"]))
    return (0 if ok else 1), transcript
