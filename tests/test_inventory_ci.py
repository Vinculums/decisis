from __future__ import annotations

import copy
import io
import json
import re
from pathlib import Path

import pytest

from test_audit import no_network
from test_inventory import FIX
from decisis import audit, checker, cli, external, inventory, rules, semver
from decisis import checkout as co
from decisis import commit as wb
from decisis.inventory import actions, terraform

CI = FIX / "ci"
WORKFLOWS = CI / ".github" / "workflows"
WORKFLOW = WORKFLOWS / "ci.yml"
LOCK = CI / ".terraform.lock.hcl"
CACHE = CI / "osv-cache.json"
CHECKOUT_SHA = "11bd71901bbe5b1630ceea73d27597364c9af683"
CHANGED_SHA = "0e58ed8671d6b60d0890c21b07f8835ace038e67"
CHANGED = "pkg:githubactions/tj-actions/changed-files@v35"
ALLOW = {"package_allowed": [{"ecosystem": "GitHub Actions", "name": "actions/checkout"},
                             {"ecosystem": "GitHub Actions", "name": "Actions/Setup-Node"},
                             {"ecosystem": "GitHub Actions", "name": "actions/cache"},
                             {"ecosystem": "GitHub Actions", "name": "tj-actions/changed-files"},
                             {"ecosystem": "Terraform", "name": "hashicorp/aws"}]}
PINNED = {"pinned_to_commit": True}
HIGH = {"advisory_severity_at_least": "HIGH"}


def snapshot(*decisions: tuple[str, object]) -> co.Subgraph:
    nodes = [{"id": "concept:shop", "kind": "concept", "title": "Shop", "props": {"code_ref": "Shop"}}]
    nodes += [{"id": did, "kind": "decision", "title": did, "props": {"rule": rule}} for did, rule in decisions]
    edges = [{"source": did, "target": "concept:shop", "type": "ABOUT", "evidence": "test"} for did, _ in decisions]
    return co.load(json.dumps({"nodes": nodes, "edges": edges}))


def cached():
    return external.cached_advisories(external.read_osv_cache(CACHE.read_text(encoding="utf-8")))


def read_path(path: Path) -> tuple[list[dict], list[dict]]:
    text, siblings = inventory.load(path)
    return inventory.read(text, path.name, "Shop", siblings)


def packages(path: Path) -> dict[str, dict]:
    return {n["id"]: n["props"] for n in read_path(path)[0] if n["kind"] == "Package"}


def report(path: Path, *decisions: tuple[str, object]) -> dict:
    text, siblings = inventory.load(path)
    return audit.run(snapshot(*decisions), text, "Shop", advisories=cached(), filename=path.name, siblings=siblings)


def finding(rep: dict, package: str, kind: str, advisory: str | None = None) -> dict:
    return next(f for f in rep["findings"] if f["package"] == package and f.get("kind", "advisory") == kind
                and f.get("advisory") == advisory)


def test_every_uses_of_the_workflows_becomes_a_package_with_its_ref_as_given():
    pkgs = packages(WORKFLOW)
    assert {pid: (p["ecosystem"], p["name"], p["version"]) for pid, p in pkgs.items() if not p["unresolved"]} == {
        f"pkg:githubactions/actions/checkout@{CHECKOUT_SHA}": ("GitHub Actions", "actions/checkout", CHECKOUT_SHA),
        "pkg:githubactions/actions/setup-node@v4.1.0": ("GitHub Actions", "actions/setup-node", "v4.1.0"),
        "pkg:githubactions/actions/cache@v4": ("GitHub Actions", "actions/cache", "v4"),
        CHANGED: ("GitHub Actions", "tj-actions/changed-files", "v35"),
        f"pkg:githubactions/tj-actions/changed-files@{CHANGED_SHA}": ("GitHub Actions", "tj-actions/changed-files", CHANGED_SHA),
        "pkg:githubactions/some-org/unvetted-action@v1": ("GitHub Actions", "some-org/unvetted-action", "v1"),
        "pkg:githubactions/octo-org/shared-workflows@main": ("GitHub Actions", "octo-org/shared-workflows", "main")}
    assert pkgs[CHANGED]["purl"] == "pkg:githubactions/tj-actions/changed-files@v35"
    assert pkgs[CHANGED]["source_system"] == "github-actions-workflow" and pkgs[CHANGED]["source_ref"] == "Shop:ci.yml#jobs.test.steps[3]"
    assert not any(p["dev"] for p in pkgs.values())


def test_local_docker_and_expression_uses_are_listed_and_not_queried():
    pkgs = packages(WORKFLOW)
    assert {pid: p["unresolved"] for pid, p in pkgs.items() if p["unresolved"] and "valid YAML" not in p["unresolved"]} == {
        "pkg:unknown/./.github/actions/setup@": actions.LOCAL,
        "pkg:unknown/docker://alpine:3.20@": actions.DOCKER,
        "pkg:unknown/${{ matrix.action }}@": actions.EXPRESSION}
    assert not any(external.queryable({"kind": "Package", "props": p}) for p in pkgs.values() if p["unresolved"])
    assert {p["ecosystem"] for p in pkgs.values() if p["unresolved"] and "valid YAML" not in p["unresolved"]} == {"GitHub Actions"}


@pytest.mark.parametrize("value", ["../x@v1", "owner/../x@v1", "owner/repo/../../x@v1", "./../outside", "o_x/repo@v1", "owner/.@v1"])
def test_a_uses_that_leaves_its_place_or_is_not_a_name_is_refused(value):
    pkg = actions.action(value)
    assert pkg["id"] == f"pkg:unknown/{value}@" and pkg["version"] == "" and "is not owner/repo@ref" in pkg["unresolved"]


def test_edges_name_the_file_job_and_step_and_aliases_in_a_workflow_are_expanded():
    edges = {(e["target"], e["evidence"]) for e in read_path(WORKFLOW)[1]}
    assert ("pkg:githubactions/actions/cache@v4", "ci.yml jobs.test.steps[2] uses actions/cache/restore@v4") in edges
    assert ("pkg:githubactions/octo-org/shared-workflows@main",
            "ci.yml jobs.shared uses octo-org/shared-workflows/.github/workflows/build.yml@main") in edges
    assert (f"pkg:githubactions/tj-actions/changed-files@{CHANGED_SHA}",
            f"release.yml jobs.publish.steps[1] uses tj-actions/changed-files@{CHANGED_SHA}") in edges
    assert all(e["source"] == "repo:Shop" for e in read_path(WORKFLOW)[1])


def test_a_workflow_that_is_not_valid_yaml_is_unresolved_with_the_reason():
    broken = packages(WORKFLOW)["pkg:unknown/broken.yml@"]["unresolved"]
    assert broken.startswith("broken.yml is not valid YAML: ") and broken.endswith("; its uses were not read")
    alone = inventory.read((WORKFLOWS / "broken.yml").read_text(encoding="utf-8"), "broken.yml", "Shop")[0]
    assert [n["id"] for n in alone if n["kind"] == "Package"] == ["pkg:unknown/broken.yml@"]
    assert sorted(inventory.load(WORKFLOWS / "broken.yml")[1]) == ["ci.yml", "release.yml"]


def test_the_sibling_workflows_are_read_through_the_bounded_reader_and_only_workflows_count(tmp_path):
    flows = tmp_path / ".github" / "workflows"
    flows.mkdir(parents=True)
    (tmp_path / ".git").mkdir()
    (flows / "a.yml").write_text("on: push\njobs:\n  x:\n    steps:\n      - uses: actions/checkout@v4\n", encoding="utf-8")
    (flows / "b.yaml").write_text("on: push\njobs:\n  y:\n    uses: octo/flows/.github/workflows/z.yml@v2\n", encoding="utf-8")
    (flows / "notes.yml").write_text("title: not a workflow\n", encoding="utf-8")
    (flows / "c.txt").write_text("on: push\njobs: {}\n", encoding="utf-8")
    (tmp_path / "outside.yml").write_text("on: push\njobs:\n  q:\n    steps:\n      - uses: evil/action@v1\n", encoding="utf-8")
    (flows / "link.yml").symlink_to(tmp_path / "outside.yml")
    (flows / "deploy.yml").write_bytes("on: push\njobs:\n  d:\n    steps:\n      - uses: tj-actions/changed-files@v35\n# caf\xe9\n"
                                       .encode("latin-1"))
    text, siblings = inventory.load(flows / "a.yml", root=flows)
    assert sorted(siblings) == ["b.yaml", "notes.yml"] and sorted(siblings.unread) == ["deploy.yml", "link.yml"]
    pkgs = {n["id"]: n["props"] for n in inventory.read(text, "a.yml", "Shop", siblings)[0] if n["kind"] == "Package"}
    assert sorted(pkgs) == ["pkg:githubactions/actions/checkout@v4", "pkg:githubactions/octo/flows@v2", "pkg:unknown/deploy.yml@",
                            "pkg:unknown/link.yml@"]
    assert pkgs["pkg:unknown/deploy.yml@"]["unresolved"].startswith("'utf-8' codec can't decode byte 0xe9")
    assert pkgs["pkg:unknown/link.yml@"]["unresolved"] == f"'link.yml' leads outside {flows.resolve()}; its uses were not read"
    nodes = inventory.read(text, "a.yml", "Shop", siblings)[0]
    assert "inventory_notes" not in next(n for n in nodes if n["kind"] == "Repository")["props"]
    _, plain = inventory.load(flows / "a.yml", reader=lambda name: None)
    assert dict(plain) == {}


def test_a_composite_action_file_reads_its_steps_and_no_siblings(tmp_path):
    (tmp_path / "action.yml").write_text("name: setup\nruns:\n  using: composite\n  steps:\n    - uses: actions/setup-go@v5\n"
                                         "    - run: go build\n", encoding="utf-8")
    (tmp_path / "ci.yml").write_text("on: push\njobs:\n  x:\n    steps:\n      - uses: actions/checkout@v4\n", encoding="utf-8")
    assert inventory.detect((tmp_path / "action.yml").read_text(encoding="utf-8"), "action.yml") == "github-actions"
    text, siblings = inventory.load(tmp_path / "action.yml", root=tmp_path)
    assert dict(siblings) == {}
    assert list(packages(tmp_path / "action.yml")) == ["pkg:githubactions/actions/setup-go@v5"]
    assert packages(tmp_path / "action.yml")["pkg:githubactions/actions/setup-go@v5"]["source_ref"] == "Shop:action.yml#runs.steps[0]"


def test_a_yaml_file_without_on_and_jobs_is_not_taken_for_a_workflow():
    with pytest.raises(ValueError, match="cannot tell what config.yml is"):
        inventory.detect("version: 2.1\njobs:\n  build: {}\n", "config.yml")


def test_osv_is_asked_by_action_name_and_decisis_compares_the_ref():
    sent = []

    def opener(req, timeout=None):
        sent.append(json.loads(req.data)["queries"])
        return io.BytesIO(json.dumps({"results": [{} for _ in sent[-1]]}).encode())

    nodes, _ = read_path(WORKFLOW)
    external.fetch_advisories([n for n in nodes if n["kind"] == "Package"], opener=opener)
    assert {"package": {"ecosystem": "GitHub Actions", "name": "tj-actions/changed-files"}} in sent[0]
    assert all("version" not in q for q in sent[0]) and len(sent[0]) == 7


@pytest.mark.parametrize("ref, affected", [
    ("v35", True), ("v35.7.6", True), ("v45", True), ("v45.0.7", True), ("v46.0.1", False), ("v47", False), ("46.0.2", False),
    ("v46", None), ("v46.0", None), (CHANGED_SHA, None), ("main", None)])
def test_a_ref_is_ordered_as_a_tag_and_a_major_or_minor_tag_covers_every_release_under_it(ref, affected):
    record = json.loads(CACHE.read_text(encoding="utf-8"))["vulns"]["GHSA-mrrh-fwg8-r2c3"]
    assert semver.affects(ref, "GitHub Actions", "tj-actions/changed-files", record["affected"]) is affected


def test_a_commit_sha_that_osv_lists_is_affected():
    listed = [{"package": {"ecosystem": "GitHub Actions", "name": "o/a"}, "versions": [CHANGED_SHA],
               "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2"}]}]}]
    assert semver.affects(CHANGED_SHA, "GitHub Actions", "O/A", listed) is True


def test_the_report_holds_the_real_tj_actions_advisories_pins_and_the_allowlist():
    rep = report(WORKFLOW, ("decision:ci", [HIGH, PINNED, ALLOW]))
    for ghsa in ("GHSA-mrrh-fwg8-r2c3", "GHSA-mcph-m25j-8j63"):
        hit = finding(rep, CHANGED, "advisory", f"adv:{ghsa}")
        assert hit["status"] == "affected" and hit["severity"] == "HIGH" and hit["policies"][0]["verdict"] == "violated"
        assert finding(rep, f"pkg:githubactions/tj-actions/changed-files@{CHANGED_SHA}", "advisory", f"adv:{ghsa}")["status"] == "unresolved"
    pins = {f["package"] for f in rep["findings"] if f.get("kind") == "pin" and f["status"] == "affected"}
    assert {(f["package"], f["kind"]) for f in rep["findings"] if f.get("kind") in ("pin", "allowlist") and f["status"] == "unresolved"} == {
        ("pkg:unknown/${{ matrix.action }}@", "pin"), ("pkg:unknown/${{ matrix.action }}@", "allowlist"),
        ("pkg:unknown/docker://alpine:3.20@", "pin"), ("pkg:unknown/docker://alpine:3.20@", "allowlist")}
    assert not any(f["package"] == "pkg:unknown/./.github/actions/setup@" for f in rep["findings"])
    assert pins == {CHANGED, "pkg:githubactions/actions/setup-node@v4.1.0", "pkg:githubactions/actions/cache@v4",
                    "pkg:githubactions/some-org/unvetted-action@v1", "pkg:githubactions/octo-org/shared-workflows@main"}
    tag = finding(rep, "pkg:githubactions/actions/setup-node@v4.1.0", "pin")
    assert tag["policies"] == [{"decision": "decision:ci", "verdict": "violated", "rule": "pinned_to_commit",
                                "why": "actions/setup-node is pinned to 'v4.1.0', not to a full 40-character commit SHA"}]
    unlisted = {f["package"] for f in rep["findings"] if f.get("kind") == "allowlist" and f["status"] == "affected"}
    assert unlisted == {"pkg:githubactions/some-org/unvetted-action@v1", "pkg:githubactions/octo-org/shared-workflows@main"}
    assert not any(f["package"].endswith(CHECKOUT_SHA) for f in rep["findings"])
    assert {u["package"] for u in rep["unresolved_packages"]} == {
        "pkg:unknown/./.github/actions/setup@", "pkg:unknown/docker://alpine:3.20@", "pkg:unknown/${{ matrix.action }}@",
        "pkg:unknown/broken.yml@"}
    assert rep["inventory_notes"] == list(actions.NOTES)


def test_an_owner_or_repo_written_in_another_case_is_one_action_and_osv_is_asked_for_each_spelling(tmp_path):
    (tmp_path / "ci.yml").write_text("on: push\njobs:\n  a:\n    steps:\n      - uses: TJ-Actions/Changed-Files@v35\n"
                                     "      - uses: Azure/setup-kubectl@v1\n  b:\n    steps:\n      - uses: tj-actions/changed-files@v35\n",
                                     encoding="utf-8")
    pkgs = packages(tmp_path / "ci.yml")
    assert pkgs[CHANGED]["name"] == "tj-actions/changed-files" and pkgs[CHANGED]["purl"] == "pkg:githubactions/tj-actions/changed-files@v35"
    assert pkgs[CHANGED]["spellings"] == ["TJ-Actions/Changed-Files", "tj-actions/changed-files"]
    assert ("pkg:githubactions/tj-actions/changed-files@v35", "ci.yml jobs.a.steps[0] uses TJ-Actions/Changed-Files@v35") in {
        (e["target"], e["evidence"]) for e in read_path(tmp_path / "ci.yml")[1]}
    assert [q["package"]["name"] for q in external.osv_queries(pkgs["pkg:githubactions/azure/setup-kubectl@v1"])] == [
        "azure/setup-kubectl", "Azure/setup-kubectl"]
    rep = report(tmp_path / "ci.yml", ("decision:ci", [{"advisory_severity_at_least": "LOW"}]))
    assert {(f["package"], f["advisory"], f["status"]) for f in rep["findings"]} == {
        (CHANGED, "adv:GHSA-mrrh-fwg8-r2c3", "affected"), (CHANGED, "adv:GHSA-mcph-m25j-8j63", "affected"),
        ("pkg:githubactions/azure/setup-kubectl@v1", "adv:GHSA-p756-rfxh-x63h", "affected")}


def test_a_sibling_file_a_reader_names_but_cannot_read_is_a_note_not_dropped(tmp_path):
    (tmp_path / "poetry.lock").write_text((FIX / "poetry" / "poetry.lock").read_text(encoding="utf-8"), encoding="utf-8")
    (tmp_path / "pyproject.toml").write_bytes('[tool.poetry]\nname = "caf\xe9"\n'.encode("latin-1"))
    nodes, _ = read_path(tmp_path / "poetry.lock")
    notes = next(n for n in nodes if n["kind"] == "Repository")["props"]["inventory_notes"]
    assert any(n.startswith("pyproject.toml, beside poetry.lock, was not read: 'utf-8' codec can't decode") for n in notes)


def test_unnamed_uses_are_unresolved_under_pin_and_allowlist_rules_and_local_actions_pass():
    pin, allow = rules.parse(PINNED).rules[0], rules.parse(ALLOW).rules[0]
    for value in ("${{ matrix.action }}", "../x@v1"):
        facts = actions.action(value)
        assert rules.outcome(pin, facts)[0] == rules.UNKNOWN and rules.outcome(allow, facts)[0] == rules.UNKNOWN
    docker = actions.action("docker://alpine:3.20")
    assert rules.outcome(pin, docker)[0] == rules.UNKNOWN and rules.outcome(allow, docker)[0] == rules.UNKNOWN
    local = actions.action("./.github/actions/setup")
    assert rules.outcome(pin, local)[0] == rules.CLEAR and rules.outcome(allow, local) == (
        rules.CLEAR, "./.github/actions/setup is a local action in this repository, which the allowlist allows")


def test_terraform_providers_are_read_with_their_versions_and_checked_against_rules_only():
    pkgs = packages(LOCK)
    assert {pid: (p["ecosystem"], p["name"], p["version"], p["unresolved"]) for pid, p in pkgs.items()} == {
        "pkg:terraform/registry.terraform.io/hashicorp/aws@5.0.0": ("Terraform", "registry.terraform.io/hashicorp/aws", "5.0.0", terraform.UNRESOLVED),
        "pkg:terraform/registry.terraform.io/integrations/github@6.2.3":
            ("Terraform", "registry.terraform.io/integrations/github", "6.2.3", terraform.UNRESOLVED)}
    assert {e["evidence"] for e in read_path(LOCK)[1]} == {
        ".terraform.lock.hcl locks registry.terraform.io/hashicorp/aws 5.0.0 (constraints ~> 5.0)",
        ".terraform.lock.hcl locks registry.terraform.io/integrations/github 6.2.3"}
    rep = report(LOCK, ("decision:ci", [HIGH, PINNED, ALLOW]))
    assert rep["meta"]["advisories"] == 0 and rep["inventory_notes"] == list(terraform.NOTES)
    assert "OSV has no Terraform ecosystem" in rep["inventory_notes"][0]
    assert [(f["package"], f["kind"], f["status"]) for f in rep["findings"]] == [
        ("pkg:terraform/registry.terraform.io/integrations/github@6.2.3", "allowlist", "affected")]
    assert [u["reason"] for u in rep["unresolved_packages"]] == [terraform.UNRESOLVED] * 2


@pytest.mark.parametrize("text, problem", [
    ('module "x" {\n}\n', 'line 1: expected provider "<address>" {'),
    ('provider "registry.terraform.io/hashicorp/aws" {\n  version = 5.0\n}\n', "line 2: expected a quoted string"),
    ('provider "registry.terraform.io/hashicorp/aws" {\n  constraints = "~> 5"\n}\n', "has no version"),
    ('provider "registry.terraform.io/hashicorp/aws" {\n  version = "5.0.0"\n', "ends inside the block"),
    ('provider "aws" {\n  version = "5.0.0"\n}\n', "expected a provider address"),
    ('provider "hashicorp/aws" {\n  version = "1"\n  version = "2"\n}\n', "version is set twice"),
    ('provider "hashicorp/aws" {\n  version = "1"\n}\nprovider "hashicorp/aws" {\n  version = "1"\n}\n', "listed twice"),
    ('provider "hashicorp/aws" {\n  version = "1"\n  hashes = [\n    h1:abc,\n  ]\n}\n', "line 4: expected a quoted string or ]"),
])
def test_the_terraform_lock_parser_refuses_what_it_cannot_read(text, problem):
    with pytest.raises(ValueError, match=re.escape(problem)):
        terraform.parse(text, terraform.LOCKFILE)


def test_a_terraform_file_that_is_not_a_lock_file_is_not_taken_for_one():
    assert not terraform.detect('provider "aws" {\n  region = var.region\n}\n', "main.tf")
    assert terraform.detect('# c\n\nprovider "registry.terraform.io/hashicorp/aws" {\n', "providers.lock")
    assert terraform.parse('provider "hashicorp/aws" {\n  version = "1.0.0"\n  hashes = ["h1:a", "zh:b"]\n}\n', "x")[0]["hashes"] == ["h1:a", "zh:b"]


@pytest.mark.parametrize("raw, problem", [
    ({"package_allowed": []}, "package_allowed must be a non-empty list of {ecosystem, name} mappings"),
    ({"package_allowed": [{"ecosystem": "npm"}]}, "package_allowed must be a non-empty list of {ecosystem, name} mappings"),
    ({"package_allowed": [{"ecosystem": "npm", "name": "x", "versions": ["1"]}]}, "package_allowed must be a non-empty list of {ecosystem, name} mappings"),
    ({"pinned_to_commit": False}, "pinned_to_commit must be true, not False"),
    ({"pinned_to_commit": "true"}, "pinned_to_commit must be true, not 'true'"),
])
def test_a_malformed_allowlist_or_pin_rule_is_a_rule_problem(raw, problem):
    parsed = rules.parse(raw)
    assert parsed.rules == () and parsed.problems[0].reason == problem


def test_the_allowlist_judges_only_the_ecosystems_it_names_and_pinning_only_actions():
    allow = rules.parse(ALLOW).rules[0]
    assert rules.outcome(allow, {"ecosystem": "npm", "name": "left-pad", "version": "1.0.0"}) == (
        rules.CLEAR, "the allowlist names no npm packages")
    assert rules.outcome(allow, {"ecosystem": "GitHub Actions", "name": "actions/SETUP-node", "version": "v4"})[0] == rules.CLEAR
    assert rules.outcome(allow, {"ecosystem": "Terraform", "name": "registry.terraform.io/HashiCorp/aws", "version": "5"})[0] == rules.CLEAR
    pin = rules.parse(PINNED).rules[0]
    assert rules.outcome(pin, {"ecosystem": "npm", "name": "x", "version": "1.0.0"})[0] == rules.CLEAR
    assert rules.outcome(pin, {"ecosystem": "GitHub Actions", "name": "a/b", "version": CHECKOUT_SHA[:39]})[0] == rules.MATCH
    assert rules.outcome(pin, {"ecosystem": "GitHub Actions", "name": "a/b", "version": CHECKOUT_SHA.upper()})[0] == rules.MATCH
    assert rules.outcome(pin, {"ecosystem": "GitHub Actions", "name": "a/b", "version": CHECKOUT_SHA}) == (
        rules.CLEAR, f"a/b is pinned to commit {CHECKOUT_SHA}")


def plan(path: Path, vinc: co.Subgraph, rep: dict | None = None) -> tuple[dict, list[dict]]:
    text, siblings = inventory.load(path)
    rep = rep or audit.run(vinc, text, "Shop", advisories=cached(), filename=path.name, siblings=siblings)
    proposed = wb.propose(rep, "Shop", "s", today="2026-11-25", lockfile_path=f".github/workflows/{path.name}")
    return checker.rederive(proposed, vinc, text, "Shop", cached(), filename=path.name, siblings=siblings)


def test_allowlist_pin_and_advisory_violations_become_records_the_checker_derives_again():
    vinc = snapshot(("decision:ci", [HIGH, PINNED, ALLOW]))
    kept, checked = plan(WORKFLOW, vinc)
    assert [c["problems"] for c in checked] == [[]] * len(checked) and kept["digest"] == wb.digest(kept)
    by_id = {n["id"]: n["props"] for n in kept["nodes"]}
    unlisted = by_id["record:shop-githubactions-some-org-9a8ae91-shipped-unlisted-package"]
    assert unlisted["predicate"] == "uses_unlisted_package" and unlisted["value"] == "GitHub Actions:some-org/unvetted-action"
    assert unlisted["rules"] == ["package_allowed"] and unlisted["violates"] == ["decision:ci"]
    pin = by_id["record:shop-githubactions-actions-setup-node-shipped-unpinned"]
    assert pin["predicate"] == "not_pinned_to_commit" and pin["versions"] == ["v4.1.0"] and pin["rules"] == ["pinned_to_commit"]
    assert pin["statement"] == ("Shop ships actions/setup-node v4.1.0, a ref that is not the full commit SHA a decision requires. "
                                "Path: actions/setup-node.")
    assert by_id["record:shop-tj-actions-changed-files-shipped-ghsa-mrrh-fwg8-r2c3"]["versions"] == ["v35"]
    assert sum(1 for n in kept["nodes"] if n["props"]["predicate"] == "not_pinned_to_commit") == 5
    lock_kept, lock_checked = plan(LOCK, vinc)
    assert [c["problems"] for c in lock_checked] == [[]] and [(n["props"]["predicate"], n["props"]["value"]) for n in lock_kept["nodes"]] == [
        ("uses_unlisted_package", "Terraform:registry.terraform.io/integrations/github")]


def test_a_pin_record_for_an_action_pinned_to_a_commit_is_held():
    vinc = snapshot(("decision:ci", [PINNED]))
    text, siblings = inventory.load(WORKFLOW)
    rep = copy.deepcopy(audit.run(vinc, text, "Shop", advisories=cached(), filename=WORKFLOW.name, siblings=siblings))
    fake = copy.deepcopy(finding(rep, "pkg:githubactions/actions/setup-node@v4.1.0", "pin"))
    fake.update(package=f"pkg:githubactions/actions/checkout@{CHECKOUT_SHA}", name="actions/checkout", version=CHECKOUT_SHA,
                path=["repo:Shop", f"pkg:githubactions/actions/checkout@{CHECKOUT_SHA}"])
    rep["findings"].append(fake)
    kept, checked = plan(WORKFLOW, vinc, rep)
    failed = [p for c in checked for p in c["problems"]]
    assert failed == [f"decision:ci has no pin rule that actions/checkout {CHECKOUT_SHA} violates"]
    assert [h["record"] for h in kept["held"] if "record" in h] == ["record:shop-githubactions-actions-checkout-shipped-unpinned"]


def test_the_cli_audits_workflows_and_terraform_offline_and_propose_re_derives(tmp_path, capsys, no_network):
    snap = tmp_path / "snapshot.json"
    snap.write_text(json.dumps({"nodes": [{"id": "concept:shop", "kind": "concept", "title": "Shop", "props": {"code_ref": "Shop"}},
                                          {"id": "decision:ci", "kind": "decision", "title": "ci", "props": {"rule": [HIGH, PINNED, ALLOW]}}],
                                "edges": [{"source": "decision:ci", "target": "concept:shop", "type": "ABOUT", "evidence": "t"}]}),
                    encoding="utf-8")
    for path in (WORKFLOW, LOCK):
        assert cli.main(["audit", str(snap), str(path), "--repo", "Shop", "--osv-cache", str(CACHE), "--out", str(tmp_path / "r.json")]) == 0
        capsys.readouterr()
        assert cli.main(["propose", str(tmp_path / "r.json"), str(snap), str(path), "--repo", "Shop", "--space", "s",
                         "--osv-cache", str(CACHE), "--out", str(tmp_path / "plan.json")]) == 0
        assert "; 0 failed." in capsys.readouterr().out
        assert json.loads((tmp_path / "plan.json").read_text(encoding="utf-8"))["nodes"]
