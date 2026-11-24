from __future__ import annotations

import json
from pathlib import Path

import pytest

from test_audit import no_network
from decisis import audit, cli, external, inventory
from decisis import checkout as co
from decisis.inventory import bun, js, npm, pnpm

ROOT = Path(__file__).resolve().parents[1]
FIX = ROOT / "fixtures" / "inventory"
JS = FIX / "js"
CACHE = FIX / "osv-cache.json"
VINC = ROOT / "fixtures" / "audit" / "vinc.json"
FILES = {"pnpm-v6": JS / "pnpm-v6" / "pnpm-lock.yaml", "pnpm-v9": JS / "pnpm-v9" / "pnpm-lock.yaml",
         "yarn-v1": JS / "yarn-v1" / "yarn.lock", "yarn-berry": JS / "yarn-berry" / "yarn.lock", "bun": JS / "bun" / "bun.lock"}
READER = {"pnpm-v6": "pnpm", "pnpm-v9": "pnpm", "yarn-v1": "yarn", "yarn-berry": "yarn", "bun": "bun"}
PACKAGE_PROPS = {"ecosystem", "name", "version", "dev", "licenses", "license_expression", "purl", "unresolved",
                 "source_system", "source_ref", "fetched_at"}
WORKSPACE_PROPS = {"name", "path", "source_system", "source_ref", "fetched_at"}
APP, LIB = "workspace:Demo:packages/app", "workspace:Demo:packages/lib"
PEER = ("pkg:npm/react-dom@18.2.0", "pkg:npm/react@18.2.0")
EDGES = {
    ("repo:Demo", APP), ("repo:Demo", LIB), ("repo:Demo", "pkg:npm/semver@7.5.1"),
    (APP, LIB), (APP, "pkg:npm/mkdirp@0.5.5"), (APP, "pkg:npm/react@18.2.0"), (APP, "pkg:npm/semver@7.5.1"),
    (LIB, "pkg:npm/debug@2.6.8"), (LIB, "pkg:npm/react-dom@18.2.0"), (LIB, "pkg:npm/@colors/colors@1.5.0"), (LIB, "pkg:npm/react@18.2.0"),
    ("pkg:npm/mkdirp@0.5.5", "pkg:npm/minimist@1.2.5"), ("pkg:npm/debug@2.6.8", "pkg:npm/ms@2.0.0"),
    ("pkg:npm/semver@7.5.1", "pkg:npm/lru-cache@6.0.0"), ("pkg:npm/lru-cache@6.0.0", "pkg:npm/yallist@4.0.0"),
    ("pkg:npm/react@18.2.0", "pkg:npm/loose-envify@1.4.0"), ("pkg:npm/react-dom@18.2.0", "pkg:npm/loose-envify@1.4.0"),
    ("pkg:npm/react-dom@18.2.0", "pkg:npm/scheduler@0.23.0"), ("pkg:npm/scheduler@0.23.0", "pkg:npm/loose-envify@1.4.0"),
    ("pkg:npm/loose-envify@1.4.0", "pkg:npm/js-tokens@4.0.0"), PEER,
}
DEV = {"pkg:npm/semver@7.5.1", "pkg:npm/lru-cache@6.0.0", "pkg:npm/yallist@4.0.0"}
MINIMIST = ["repo:Demo", APP, "pkg:npm/mkdirp@0.5.5", "pkg:npm/minimist@1.2.5", "adv:GHSA-xvch-5gv4-984h"]


def read(fmt: str) -> tuple[list[dict], list[dict]]:
    text, siblings = inventory.load(FILES[fmt])
    return inventory.read(text, FILES[fmt].name, "Demo", siblings)


def evidence(fmt: str) -> dict[tuple[str, str], str]:
    return {(e["source"], e["target"]): e["evidence"] for e in read(fmt)[1]}


def report(fmt: str) -> dict:
    text, siblings = inventory.load(FILES[fmt])
    cache = external.read_osv_cache(CACHE.read_text(encoding="utf-8"))
    return audit.run(co.load(VINC.read_text(encoding="utf-8")), text, "Demo", advisories=external.cached_advisories(cache),
                     filename=FILES[fmt].name, siblings=siblings)


@pytest.mark.parametrize("fmt", sorted(FILES))
def test_each_lockfile_is_told_from_its_content_and_its_name(fmt):
    text, _ = inventory.load(FILES[fmt])
    assert inventory.detect(text, FILES[fmt].name) == READER[fmt]
    assert inventory.detect(text, "inventory.txt") == READER[fmt]


@pytest.mark.parametrize("fmt", sorted(FILES))
def test_workspaces_are_nodes_between_the_repository_and_their_packages(fmt):
    nodes, edges = read(fmt)
    kinds = {n["id"]: n["kind"] for n in nodes}
    assert sorted(i for i, k in kinds.items() if k == "Workspace") == [APP, LIB]
    assert all(set(n["props"]) == WORKSPACE_PROPS for n in nodes if n["kind"] == "Workspace")
    assert all(set(n["props"]) == PACKAGE_PROPS for n in nodes if n["kind"] == "Package")
    assert all(e["source"] in kinds and e["target"] in kinds and e["type"] == "DEPENDS_ON" and e["evidence"] for e in edges)
    want = EDGES - {PEER} if fmt == "yarn-v1" else EDGES
    assert {(e["source"], e["target"]) for e in edges} == want


@pytest.mark.parametrize("fmt", sorted(FILES))
def test_dev_only_packages_are_marked_dev_and_the_rest_are_shipped(fmt):
    nodes, _ = read(fmt)
    assert {n["id"] for n in nodes if n["kind"] == "Package" and n["props"]["dev"]} == DEV
    marks = evidence(fmt)
    assert marks[("repo:Demo", "pkg:npm/semver@7.5.1")].endswith("(dev)")
    assert marks[(APP, "pkg:npm/semver@7.5.1")].endswith("(dev)")


@pytest.mark.parametrize("fmt", sorted(FILES))
def test_peer_and_optional_dependencies_are_edges_with_their_kind_in_the_evidence(fmt):
    marks = evidence(fmt)
    assert marks[(LIB, "pkg:npm/@colors/colors@1.5.0")].endswith("(optional)")
    if fmt != "yarn-v1":
        assert marks[PEER].endswith("(peer)")


@pytest.mark.parametrize("fmt", sorted(FILES))
def test_every_package_has_the_npm_ecosystem_and_the_npm_readers_id(fmt):
    pkgs = [n for n in read(fmt)[0] if n["kind"] == "Package"]
    lock = {"lockfileVersion": 3, "packages": {"": {}, **{f"node_modules/{n['props']['name']}": {"version": n["props"]["version"]} for n in pkgs}}}
    ids = {n["props"]["name"]: n["id"] for n in npm.parse_npm_lock(json.dumps(lock), "Demo")[0] if n["kind"] == "Package"}
    assert all(n["props"]["ecosystem"] == "npm" and not n["props"]["unresolved"] for n in pkgs)
    assert {n["props"]["name"]: n["id"] for n in pkgs} == ids
    assert all(n["props"]["purl"] == next(m for m in npm.parse_npm_lock(json.dumps(lock), "Demo")[0] if m["id"] == n["id"])["props"]["purl"]
               for n in pkgs)


@pytest.mark.parametrize("fmt", sorted(FILES))
def test_an_affected_finding_is_reached_through_a_workspace(fmt):
    rep = report(fmt)
    hit = [f for f in rep["findings"] if f["package"] == "pkg:npm/minimist@1.2.5"]
    assert len(hit) == 1 and hit[0]["status"] == "affected" and hit[0]["dev_only"] is False and hit[0]["path"] == MINIMIST
    semver = [f for f in rep["findings"] if f["package"] == "pkg:npm/semver@7.5.1"]
    assert semver and all(f["dev_only"] for f in semver)
    assert rep["unresolved_packages"] == []


@pytest.mark.parametrize("fmt", ["pnpm-v9", "yarn-berry", "bun"])
def test_the_cli_audits_a_monorepo_lockfile_offline(fmt, no_network, capsys):
    assert cli.main(["audit", str(VINC), str(FILES[fmt]), "--repo", "Demo", "--osv-cache", str(CACHE)]) == 0
    rep = json.loads(capsys.readouterr().out)
    assert rep["summary"]["affected"] > 0 and rep["meta"]["packages"] == 13


def propose(tmp_path: Path, capsys, fmt: str, rep: dict) -> tuple[int, dict, str]:
    (tmp_path / "report.json").write_text(json.dumps(rep), encoding="utf-8")
    capsys.readouterr()
    code = cli.main(["propose", str(tmp_path / "report.json"), str(VINC), str(FILES[fmt]), "--repo", "Demo", "--space", "demo-space",
                     "--osv-cache", str(CACHE), "--out", str(tmp_path / "plan.json")])
    return code, json.loads((tmp_path / "plan.json").read_text(encoding="utf-8")), capsys.readouterr().out


@pytest.mark.parametrize("fmt", ["pnpm-v6", "yarn-v1", "bun"])
def test_propose_re_derives_a_record_whose_path_runs_through_a_workspace(tmp_path, capsys, no_network, fmt):
    code, plan, out = propose(tmp_path, capsys, fmt, report(fmt))
    assert code == 0 and plan["held"] == [] and "; 0 failed." in out
    record = next(n for n in plan["nodes"] if n["props"]["entity"] == "Demo:minimist")
    assert record["props"]["dependency_paths"] == [MINIMIST]


def test_propose_holds_a_path_that_skips_the_workspace(tmp_path, capsys, no_network):
    rep = report("pnpm-v9")
    f = next(f for f in rep["findings"] if f["package"] == "pkg:npm/minimist@1.2.5")
    f["path"] = ["repo:Demo", "pkg:npm/mkdirp@0.5.5", "pkg:npm/minimist@1.2.5", "adv:GHSA-xvch-5gv4-984h"]
    code, plan, _ = propose(tmp_path, capsys, "pnpm-v9", rep)
    held = next(h for h in plan["held"] if h.get("failed"))
    assert code == 1 and held["failed"] == [f"a dependency path is not in the sandbox graph: {' -> '.join(f['path'])}"]


@pytest.mark.parametrize("name,data", [("bun.lockb", b"#!/usr/bin/env bun\nbun-lockfile-format-v0\n\x02\x00\xff\xfe\x9c"),
                                       ("bun.lockb", b"\x00\xff"), ("lock.bin", b"#!/usr/bin/env bun\nbun-lockfile-format-v0\n\xff")])
def test_a_binary_bun_lockb_is_refused_with_the_command_that_writes_the_text_lockfile(tmp_path, capsys, name, data):
    lockb = tmp_path / name
    lockb.write_bytes(data)
    with pytest.raises(ValueError, match=r"run `bun install --save-text-lockfile`"):
        inventory.load(lockb)
    with pytest.raises(ValueError, match=r"run `bun install --save-text-lockfile`"):
        inventory.read("#!/usr/bin/env bun\nbun-lockfile-format-v0\n", "bun.lockb", "Demo")
    with pytest.raises(SystemExit):
        cli.main(["audit", str(VINC), str(lockb), "--repo", "Demo", "--osv-cache", str(CACHE)])
    assert "bun install --save-text-lockfile" in capsys.readouterr().err


def test_a_pnpm_lockfile_version_other_than_6_or_9_is_refused():
    with pytest.raises(ValueError, match="lockfileVersion 5.4; audit reads pnpm lockfile versions 6 and 9"):
        inventory.read("lockfileVersion: 5.4\n\npackages:\n  /ms/2.0.0:\n    dev: false\n", "pnpm-lock.yaml", "Demo")


def test_a_yarn_lock_without_its_package_json_links_every_package_from_the_repository():
    nodes, edges = inventory.read(FILES["yarn-v1"].read_text(encoding="utf-8"), "yarn.lock", "Demo")
    assert not [n for n in nodes if n["kind"] == "Workspace"]
    roots = {e["target"]: e["evidence"] for e in edges if e["source"] == "repo:Demo"}
    assert roots["pkg:npm/mkdirp@0.5.5"] == js.ORPHAN and "pkg:npm/minimist@1.2.5" not in roots


def test_pnpm_aliases_links_and_sources_outside_the_registry():
    text = """lockfileVersion: '9.0'

importers:

  .:
    dependencies:
      local-cjs:
        specifier: npm:ms@2.0.0
        version: ms@2.0.0
      tool:
        specifier: github:demo/tool
        version: https://codeload.github.com/demo/tool/tar.gz/abc123

packages:

  ms@2.0.0:
    resolution: {integrity: sha512-x}

  tool@https://codeload.github.com/demo/tool/tar.gz/abc123:
    resolution: {tarball: https://codeload.github.com/demo/tool/tar.gz/abc123}
    version: 1.0.0

snapshots:

  ms@2.0.0: {}

  tool@https://codeload.github.com/demo/tool/tar.gz/abc123: {}
"""
    nodes, edges = pnpm.read(text, "pnpm-lock.yaml", "Demo")
    pkgs = {n["props"]["name"]: n["props"] for n in nodes if n["kind"] == "Package"}
    assert {e["target"] for e in edges} == {"pkg:npm/ms@2.0.0", "pkg:npm/tool@https://codeload.github.com/demo/tool/tar.gz/abc123"}
    assert pkgs["ms"]["unresolved"] == "" and "not an npm registry version" in pkgs["tool"]["unresolved"]


def test_bun_resolves_a_nested_package_before_the_hoisted_one():
    text = """{
  "lockfileVersion": 1,
  "workspaces": {
    "": {
      "name": "demo",
      "dependencies": {
        "debug": "2.6.8",
        "ms": "2.1.3",
      },
    },
  },
  "packages": {
    "debug": ["debug@2.6.8", "", { "dependencies": { "ms": "2.0.0" } }, "sha512-a"],

    "debug/ms": ["ms@2.0.0", "", {}, "sha512-b"],

    "ms": ["ms@2.1.3", "", {}, "sha512-c"],
  }
}
"""
    _, edges = bun.read(text, "bun.lock", "Demo")
    assert {(e["source"], e["target"]) for e in edges} == {("repo:Demo", "pkg:npm/debug@2.6.8"), ("repo:Demo", "pkg:npm/ms@2.1.3"),
                                                          ("pkg:npm/debug@2.6.8", "pkg:npm/ms@2.0.0")}


def test_yaml_scalars_stay_strings():
    assert js.yaml_tree("on: yes\nversion: 1.10\nn: ~\n", "x.yaml") == {"on": "yes", "version": "1.10", "n": "~"}


ALIAS_LOCKS = {
    "npm": ("package-lock.json", json.dumps({"lockfileVersion": 3, "packages": {
        "": {"dependencies": {"foo": "npm:minimist@1.2.5"}}, "node_modules/foo": {"name": "minimist", "version": "1.2.5"}}})),
    "yarn-v1": ("yarn.lock", '# yarn lockfile v1\n\n\n"foo@npm:minimist@1.2.5":\n  version "1.2.5"\n'
                '  resolved "https://registry.yarnpkg.com/minimist/-/minimist-1.2.5.tgz#67d66014b66a6a8aaa0c083c5fd58df4e4e97602"\n'),
    "yarn-berry": ("yarn.lock", '__metadata:\n  version: 8\n\n"demo@workspace:.":\n  version: 0.0.0-use.local\n  resolution: "demo@workspace:."\n'
                   '  dependencies:\n    foo: "npm:minimist@1.2.5"\n\n"foo@npm:minimist@1.2.5":\n  version: 1.2.5\n'
                   '  resolution: "minimist@npm:1.2.5"\n  languageName: node\n  linkType: hard\n'),
    "pnpm-v6": ("pnpm-lock.yaml", "lockfileVersion: '6.0'\n\ndependencies:\n  foo:\n    specifier: npm:minimist@1.2.5\n"
                "    version: /minimist@1.2.5\n\npackages:\n\n  /minimist@1.2.5:\n    resolution: {integrity: sha512-x}\n    dev: false\n"),
    "pnpm-v9": ("pnpm-lock.yaml", "lockfileVersion: '9.0'\n\nimporters:\n\n  .:\n    dependencies:\n      foo:\n"
                "        specifier: npm:minimist@1.2.5\n        version: minimist@1.2.5\n\npackages:\n\n  minimist@1.2.5:\n"
                "    resolution: {integrity: sha512-x}\n\nsnapshots:\n\n  minimist@1.2.5: {}\n"),
    "bun": ("bun.lock", '{\n  "lockfileVersion": 1,\n  "workspaces": {\n    "": {\n      "name": "demo",\n      "dependencies": {\n'
            '        "foo": "npm:minimist@1.2.5",\n      },\n    },\n  },\n  "packages": {\n'
            '    "foo": ["minimist@1.2.5", "", {}, "sha512-x"],\n  }\n}\n'),
}


@pytest.mark.parametrize("fmt", sorted(ALIAS_LOCKS))
def test_an_npm_alias_has_the_id_of_the_package_it_names(fmt):
    name, text = ALIAS_LOCKS[fmt]
    nodes, edges = inventory.read(text, name, "Demo")
    assert [n["id"] for n in nodes if n["kind"] == "Package"] == ["pkg:npm/minimist@1.2.5"]
    assert ("repo:Demo", "pkg:npm/minimist@1.2.5") in {(e["source"], e["target"]) for e in edges}


def laughs(head: str, tail: str) -> str:
    rows = ['a0: &a0 ["lol","lol","lol","lol","lol","lol","lol","lol","lol","lol"]']
    rows += [f"a{i}: &a{i} [" + ",".join([f"*a{i - 1}"] * 10) + "]" for i in range(1, 10)]
    return head + "\n".join(rows) + "\n" + tail


@pytest.mark.parametrize("name,text", [
    ("pnpm-lock.yaml", laughs("", "lockfileVersion: *a9\n")),
    ("yarn.lock", laughs("__metadata:\n  version: 8\n", '"x@npm:1.0.0":\n  version: 1.0.0\n  resolution: *a9\n')),
])
def test_a_lockfile_with_a_yaml_anchor_is_refused_before_anything_expands(name, text):
    with pytest.raises(ValueError, match="uses a YAML anchor or alias"):
        inventory.read(text, name, "Demo")


def test_aliases_are_allowed_only_when_asked_and_only_within_the_budget():
    from decisis import yamltext
    small = "base: &b {runs-on: ubuntu-latest}\njob: *b\n"
    with pytest.raises(ValueError, match="anchor or alias"):
        yamltext.load(small, "ci.yml")
    assert yamltext.load(small, "ci.yml", aliases=True) == {"base": {"runs-on": "ubuntu-latest"}, "job": {"runs-on": "ubuntu-latest"}}
    with pytest.raises(ValueError, match="more than 100000 YAML nodes"):
        yamltext.load(laughs("", ""), "ci.yml", aliases=True)
    with pytest.raises(ValueError, match="deeper than 64 levels"):
        yamltext.load("[" * 80 + "]" * 80, "ci.yml", aliases=True)


def test_a_lockfile_that_is_not_utf8_is_refused_not_audited_clean(tmp_path, capsys, no_network):
    lock = tmp_path / "package-lock.json"
    lock.write_bytes((ROOT / "fixtures" / "audit" / "demo-lockfile.json").read_bytes().replace(b'"lodash"', b'"lod\xffsh"', 1))
    with pytest.raises(UnicodeDecodeError):
        inventory.load(lock)
    with pytest.raises(SystemExit):
        cli.main(["audit", str(VINC), str(lock), "--repo", "Demo", "--osv-cache", str(ROOT / "fixtures" / "audit" / "osv-cache.json")])
    assert "can't decode" in capsys.readouterr().err


@pytest.mark.parametrize("fmt", ["yarn-v1", "yarn-berry"])
def test_the_mcp_audit_reads_the_same_package_json_files_as_the_cli(fmt):
    pytest.importorskip("mcp")
    pytest.importorskip("jsonschema")
    from decisis import serve
    tools = serve.load_tools(VINC, FILES[fmt].parent, CACHE)
    rep = tools.call("audit", {"lockfile": "yarn.lock", "repo": "Demo", "detail": "full"})
    hit = next(f for f in rep["findings"] if f["package"] == "pkg:npm/minimist@1.2.5")
    assert hit["path"] == MINIMIST
    assert all(f["dev_only"] for f in rep["findings"] if f["package"] == "pkg:npm/semver@7.5.1")
    assert rep["summary"] == report(fmt)["summary"]


def test_the_mcp_audit_refuses_a_binary_bun_lockb_before_reading_it(tmp_path):
    pytest.importorskip("mcp")
    pytest.importorskip("jsonschema")
    from decisis import serve
    (tmp_path / "bun.lockb").write_bytes(b"#!/usr/bin/env bun\nbun-lockfile-format-v0\n\x02\x00\xff\xfe")
    tools = serve.load_tools(VINC, tmp_path, CACHE)
    with pytest.raises(serve.Refused, match=r"run `bun install --save-text-lockfile`"):
        tools.call("audit", {"lockfile": "bun.lockb", "repo": "Demo"})


def test_a_yarn_workspace_that_leads_outside_the_root_is_not_read(tmp_path):
    repo, outside = tmp_path / "repo", tmp_path / "outside"
    (repo / ".git").mkdir(parents=True)
    (outside / "evil").mkdir(parents=True)
    (outside / "evil" / "package.json").write_text('{"name": "evil", "dependencies": {"minimist": "1.2.5"}}', encoding="utf-8")
    (repo / "packages").mkdir()
    (repo / "packages" / "evil").symlink_to(outside / "evil", target_is_directory=True)
    (repo / "package.json").write_text('{"name": "demo", "workspaces": ["packages/*"]}', encoding="utf-8")
    (repo / "yarn.lock").write_text(ALIAS_LOCKS["yarn-v1"][1], encoding="utf-8")
    _, siblings = inventory.load(repo / "yarn.lock")
    assert sorted(siblings) == ["package.json"]
