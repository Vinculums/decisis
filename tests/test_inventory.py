from __future__ import annotations

import io
import json
from pathlib import Path

import pytest

from test_audit import no_network
from decisis import audit, cli, external, inventory, pep440, semver
from decisis import checkout as co
from decisis.inventory import shape

ROOT = Path(__file__).resolve().parents[1]
FIX = ROOT / "fixtures" / "inventory"
CACHE = FIX / "osv-cache.json"
VINC = ROOT / "fixtures" / "audit" / "vinc.json"
NPM = ROOT / "fixtures" / "audit" / "demo-lockfile.json"
FILES = {"npm": NPM, "cyclonedx": FIX / "cyclonedx.json", "spdx": FIX / "spdx.json", "uv": FIX / "uv.lock",
         "cargo": FIX / "Cargo.lock", "go": FIX / "go" / "go.mod"}
PACKAGE_PROPS = {"ecosystem", "name", "version", "dev", "licenses", "license_expression", "purl", "unresolved",
                 "source_system", "source_ref", "fetched_at"}


def osv_cache() -> dict:
    return external.read_osv_cache(CACHE.read_text(encoding="utf-8"))


def read(fmt: str, repo: str = "Demo") -> tuple[list[dict], list[dict]]:
    text, siblings = inventory.load(FILES[fmt])
    return inventory.read(text, FILES[fmt].name, repo, siblings)


def packages(fmt: str) -> dict[str, dict]:
    return {n["id"]: n["props"] for n in read(fmt)[0] if n["kind"] == "Package"}


def pairs(fmt: str) -> set[tuple[str, str]]:
    return {(e["source"], e["target"]) for e in read(fmt)[1]}


def report(fmt: str) -> dict:
    text, siblings = inventory.load(FILES[fmt])
    cache = osv_cache() if fmt != "npm" else external.read_osv_cache((NPM.parent / "osv-cache.json").read_text(encoding="utf-8"))
    return audit.run(co.load(VINC.read_text(encoding="utf-8")), text, "Demo", advisories=external.cached_advisories(cache),
                     filename=FILES[fmt].name, siblings=siblings)


@pytest.mark.parametrize("fmt", sorted(FILES))
def test_the_format_is_told_from_the_content_and_the_file_name(fmt):
    text, _ = inventory.load(FILES[fmt])
    assert inventory.detect(text, FILES[fmt].name) == fmt
    assert inventory.detect(text, "inventory.txt") == fmt


def test_a_file_of_no_known_format_is_refused_with_the_list_of_formats():
    with pytest.raises(ValueError, match="CycloneDX JSON 1.4 to 1.6, SPDX JSON 2.3, uv.lock, Cargo.lock"):
        inventory.detect('{"name": "not an inventory"}', "notes.json")


@pytest.mark.parametrize("fmt", sorted(FILES))
def test_every_reader_returns_the_same_node_and_edge_shape(fmt):
    nodes, edges = read(fmt)
    repo = [n for n in nodes if n["kind"] == "Repository"]
    assert [n["id"] for n in repo] == ["repo:Demo"]
    assert set(repo[0]["props"]) == {"source_system", "source_ref", "fetched_at", "content_hash"}
    pkgs = [n for n in nodes if n["kind"] == "Package"]
    assert pkgs and all(set(n["props"]) == PACKAGE_PROPS for n in pkgs)
    assert all(isinstance(n["props"]["licenses"], list) and isinstance(n["props"]["dev"], bool) for n in pkgs)
    assert all(n["title"] == f"{n['props']['name']}@{n['props']['version']}" for n in pkgs)
    assert all(set(e) == {"source", "target", "type", "evidence"} and e["type"] == "DEPENDS_ON" and e["evidence"] for e in edges)
    ids = {n["id"] for n in nodes}
    assert all(e["source"] in ids and e["target"] in ids for e in edges)


def test_npm_ids_and_the_old_import_stay_as_they_were():
    nodes, edges = external.parse_npm_lock(NPM.read_text(encoding="utf-8"), "Demo")
    again = read("npm")
    assert [n["id"] for n in nodes] == [n["id"] for n in again[0]] and edges == again[1]
    lodash = packages("npm")["pkg:npm/lodash@4.17.15"]
    assert lodash["purl"] == "pkg:npm/lodash@4.17.15" and lodash["licenses"] == [] and lodash["source_system"] == "npm-lockfile"


def test_cyclonedx_components_dependencies_licenses_and_the_dev_scope():
    pkgs = packages("cyclonedx")
    assert pkgs["pkg:npm/@colors/colors@1.5.0"]["purl"] == "pkg:npm/%40colors/colors@1.5.0"
    assert pkgs["pkg:npm/@colors/colors@1.5.0"]["name"] == "@colors/colors"
    assert pkgs["pkg:npm/minimist@1.2.5"]["licenses"] == ["MIT"]
    assert pkgs["pkg:npm/semver@7.5.1"]["dev"] is True and pkgs["pkg:npm/debug@2.6.8"]["dev"] is False
    assert {("repo:Demo", "pkg:npm/debug@2.6.8"), ("pkg:npm/debug@2.6.8", "pkg:npm/ms@2.0.0")} <= pairs("cyclonedx")
    generic = pkgs["pkg:generic/openssl@3.0.11"]
    assert generic["ecosystem"] == "" and generic["unresolved"] and generic["licenses"] == []


@pytest.mark.parametrize("spec,ok", [("1.3", False), ("1.4", True), ("1.5", True), ("1.6", True), ("2.0", False)])
def test_cyclonedx_reads_spec_versions_1_4_to_1_6(spec, ok):
    bom = json.loads(FILES["cyclonedx"].read_text(encoding="utf-8"))
    bom["specVersion"] = spec
    if ok:
        assert inventory.read(json.dumps(bom), "bom.json", "Demo")[0]
    else:
        with pytest.raises(ValueError, match="1.4, 1.5, 1.6"):
            inventory.read(json.dumps(bom), "bom.json", "Demo")


def test_spdx_relationships_become_edges_and_dev_dependencies_mark_their_subtree():
    pkgs = packages("spdx")
    assert {k for k, p in pkgs.items() if p["dev"]} == {"pkg:pypi/pytest@8.2.0", "pkg:pypi/pluggy@1.5.0", "pkg:pypi/iniconfig@2.0.0",
                                                        "pkg:pypi/packaging@24.0"}
    assert ("repo:Demo", "pkg:pypi/itsdangerous@2.2.0") in pairs("spdx")
    assert ("pkg:pypi/pytest@8.2.0", "pkg:pypi/pluggy@1.5.0") in pairs("spdx")
    assert pkgs["pkg:pypi/idna@3.6"]["licenses"] == ["BSD-3-Clause"]
    assert pkgs["pkg:pypi/packaging@24.0"]["licenses"] == ["Apache-2.0", "BSD-2-Clause"]
    assert pkgs["pkg:pypi/packaging@24.0"]["license_expression"] == "Apache-2.0 OR BSD-2-Clause"
    doc = json.loads(FILES["spdx"].read_text(encoding="utf-8"))
    doc["spdxVersion"] = "SPDX-2.2"
    with pytest.raises(ValueError, match="SPDX JSON 2.3"):
        inventory.read(json.dumps(doc), "sbom.spdx.json", "Demo")


def test_uv_lock_maps_the_project_to_the_repository_and_its_dev_group_to_dev():
    pkgs = packages("uv")
    assert all(p["ecosystem"] == "PyPI" for p in pkgs.values()) and "pkg:pypi/inventory-worker@0.1.0" not in pkgs
    assert {k for k, p in pkgs.items() if not p["dev"]} == {"pkg:pypi/certifi@2023.7.22", "pkg:pypi/idna@3.6"}
    got = {(e["source"], e["target"]): e["evidence"] for e in read("uv")[1]}
    assert got[("repo:Demo", "pkg:pypi/pytest@8.2.0")] == "inventory-worker requires pytest (group dev)"
    assert got[("pkg:pypi/pytest@8.2.0", "pkg:pypi/colorama@0.4.6")] == "pytest requires colorama; sys_platform == 'win32'"


def test_cargo_lock_resolves_name_and_version_references():
    assert {("repo:Demo", "pkg:cargo/time@0.1.43"), ("pkg:cargo/time@0.1.43", "pkg:cargo/winapi@0.3.9")} <= pairs("cargo")
    assert packages("cargo")["pkg:cargo/time@0.1.43"]["purl"] == "pkg:cargo/time@0.1.43"
    lock = "\n".join(['version = 3', '[[package]]', 'name = "app"', 'version = "0.1.0"', 'dependencies = ["rand 0.8.5", "rand 0.7.3 (registry+https://github.com/rust-lang/crates.io-index)"]',
                      *[f'[[package]]\nname = "rand"\nversion = "{v}"\nsource = "registry+https://github.com/rust-lang/crates.io-index"' for v in ("0.7.3", "0.8.5")]])
    nodes, edges = inventory.read(lock, "Cargo.lock", "Demo")
    assert {(e["source"], e["target"]) for e in edges} == {("repo:Demo", "pkg:cargo/rand@0.7.3"), ("repo:Demo", "pkg:cargo/rand@0.8.5")}
    assert all(not n["props"]["dev"] for n in nodes if n["kind"] == "Package")


def test_go_mod_is_read_with_the_go_sum_next_to_it():
    pkgs = packages("go")
    yaml = pkgs["pkg:golang/gopkg.in/yaml.v3@3.0.0-20210107192922-496545a6307b"]
    assert yaml["ecosystem"] == "Go" and yaml["purl"] == "pkg:golang/gopkg.in/yaml.v3@v3.0.0-20210107192922-496545a6307b"
    assert {e["evidence"] for e in read("go")[1]} >= {"go.mod requires golang.org/x/text v0.3.7 // indirect"}
    mod = FILES["go"].read_text(encoding="utf-8")
    with pytest.raises(ValueError, match="go.sum next to it"):
        inventory.read(mod, "go.mod", "Demo")
    with pytest.raises(ValueError, match="go.sum has no line for github.com/google/uuid v1.3.0"):
        inventory.read(mod, "go.mod", "Demo", {"go.sum": ""})


def test_go_replace_directives_swap_or_drop_a_module():
    mod = "module example.com/a\n\ngo 1.22\n\nrequire (\n\tgithub.com/x/y v1.0.0\n\tgithub.com/x/z v1.0.0\n)\n\nreplace github.com/x/y => github.com/fork/y v1.0.1\nreplace github.com/x/z v1.0.0 => ../z\n"
    nodes, edges = inventory.read(mod, "go.mod", "Demo", {"go.sum": "github.com/fork/y v1.0.1 h1:abc=\n"})
    assert [n["id"] for n in nodes if n["kind"] == "Package"] == ["pkg:golang/github.com/fork/y@1.0.1"]
    assert edges[0]["evidence"] == "go.mod requires github.com/x/y v1.0.0 (replaced by github.com/fork/y v1.0.1)"


@pytest.mark.parametrize("purl,ecosystem,name,version", [
    ("pkg:npm/%40babel/core@7.24.0", "npm", "@babel/core", "7.24.0"),
    ("pkg:pypi/Django_Rest@3.0", "PyPI", "django-rest", "3.0"),
    ("pkg:cargo/serde@1.0.0", "crates.io", "serde", "1.0.0"),
    ("pkg:golang/golang.org/x/net@v0.17.0", "Go", "golang.org/x/net", "0.17.0"),
    ("pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1", "Maven", "org.apache.logging.log4j:log4j-core", "2.14.1"),
    ("pkg:nuget/Newtonsoft.Json@12.0.1", "NuGet", "Newtonsoft.Json", "12.0.1"),
    ("pkg:gem/rails@7.0.0", "RubyGems", "rails", "7.0.0"),
    ("pkg:composer/laravel/framework@9.0.0", "Packagist", "laravel/framework", "9.0.0"),
    ("pkg:githubactions/actions/checkout@v4", "GitHub Actions", "actions/checkout", "v4"),
    ("pkg:deb/debian/openssl@3.0.11-1~deb12u1?arch=amd64&distro=debian-12", "Debian:12", "openssl", "3.0.11-1~deb12u1"),
    ("pkg:apk/alpine/busybox@1.36.1-r2?distro=alpine-3.18.4", "Alpine:v3.18", "busybox", "1.36.1-r2"),
    ("pkg:deb/ubuntu/openssl@3.0.2?distro=ubuntu-22.04", "", "openssl", "3.0.2"),
    ("pkg:rpm/redhat/openssl@3.0.7", "", "openssl", "3.0.7"),
    ("pkg:generic/zlib@1.3", "", "zlib", "1.3"),
])
def test_purl_types_map_to_osv_ecosystems_with_one_table(purl, ecosystem, name, version):
    got = shape.from_purl(purl)
    assert (got["ecosystem"], got["name"], got["version"]) == (ecosystem, name, version)
    assert bool(got["unresolved"]) == (ecosystem == "")
    assert "?" not in got["purl"]


def test_license_expressions_become_spdx_ids():
    assert shape.license_ids("(MIT OR Apache-2.0) AND BSD-3-Clause") == ["MIT", "Apache-2.0", "BSD-3-Clause"]
    assert shape.license_ids("GPL-2.0-only WITH Classpath-exception-2.0") == ["GPL-2.0-only"]
    assert shape.license_ids("NOASSERTION") == [] and shape.license_ids("") == []


@pytest.mark.parametrize("lower,higher", [
    ("1.0.dev0", "1.0a1"), ("1.0a1", "1.0a2.dev1"), ("1.0a2", "1.0b1"), ("1.0b1", "1.0rc1"), ("1.0rc1", "1.0"),
    ("1.0", "1.0.post1"), ("1.0.post1.dev1", "1.0.post1"), ("1.0", "1.0+local"), ("1.0+abc", "1.0+1"),
    ("1.9", "1.10"), ("2023.7.22", "2024.7.4"), ("9.0", "1!1.0"), ("1.0c1", "1.0"), ("3.6", "3.7"),
])
def test_pep440_orders_versions_like_pip(lower, higher):
    assert pep440.key(lower) < pep440.key(higher)


def test_pep440_treats_equal_spellings_as_equal_and_refuses_what_is_not_a_version():
    assert pep440.key("1.0") == pep440.key("1.0.0") == pep440.key("v1.0")
    assert pep440.key("1.0-1") == pep440.key("1.0.post1") == pep440.key("1.0_r1")
    assert pep440.key("1.0RC1") == pep440.key("1.0rc1") == pep440.key("1.0-c1")
    with pytest.raises(ValueError):
        pep440.key("not a version")


def ranges_only(record: dict) -> list[dict]:
    return [{**a, "versions": []} for a in record["affected"]]


@pytest.mark.parametrize("vid,ecosystem,name,inside,outside", [
    ("GHSA-jjg7-2v4v-x38h", "PyPI", "idna", "3.6", "3.7"),
    ("GHSA-6q48-6c7w-9gw2", "PyPI", "certifi", "2023.7.22", "2026.10.18"),
    ("RUSTSEC-2020-0071", "crates.io", "time", "0.1.43", "0.2.23"),
    ("GO-2022-0603", "Go", "gopkg.in/yaml.v3", "3.0.0-20210107192922-496545a6307b", "3.0.1"),
    ("GHSA-xvch-5gv4-984h", "npm", "minimist", "1.2.5", "1.2.6"),
])
def test_ranges_are_ordered_by_the_package_ecosystem(vid, ecosystem, name, inside, outside):
    affected = ranges_only(osv_cache()["vulns"][vid])
    assert semver.affects(inside, ecosystem, name, affected) is True
    assert semver.affects(outside, ecosystem, name, affected) is False


def test_a_version_that_cannot_be_ordered_is_unresolved_never_affected():
    pypi = ranges_only(osv_cache()["vulns"]["GHSA-jjg7-2v4v-x38h"])
    assert semver.affects("not.a version", "PyPI", "idna", pypi) is None
    maven = [{"package": {"ecosystem": "Maven", "name": "g:a"}, "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.0"}]}]}]
    assert semver.affects("1.0", "Maven", "g:a", maven) is None
    assert semver.affects("1.0", "Maven", "g:a", [{**maven[0], "versions": ["1.0"]}]) is True
    assert semver.affects("3.6", "PyPI", "IDNA", pypi) is True


def test_events_are_sorted_before_they_are_read():
    events = [{"introduced": "2.0"}, {"fixed": "2.5"}, {"introduced": "0"}, {"fixed": "1.0"}]
    assert [semver.in_range(v, events) for v in ("0.5", "1.5", "2.1", "3.0")] == [True, False, True, False]


def test_osv_is_queried_with_each_package_ecosystem_and_unresolved_packages_are_not_queried():
    sent = []

    def opener(req, timeout=None):
        if req.full_url == external.OSV_BATCH:
            queries = json.loads(req.data)["queries"]
            sent.extend(queries)
            return io.BytesIO(json.dumps({"results": [{"vulns": []} for _ in queries]}).encode())
        raise AssertionError(req.full_url)

    nodes = [n for fmt in ("cyclonedx", "uv", "cargo", "go") for n in read(fmt)[0]]
    external.fetch_advisories(nodes, opener=opener)
    assert {q["package"]["ecosystem"] for q in sent} == {"npm", "PyPI", "crates.io", "Go"}
    assert {"package": {"ecosystem": "Go", "name": "golang.org/x/text"}, "version": "0.3.7"} in sent
    assert all(q["package"]["name"] != "openssl" for q in sent)


@pytest.mark.parametrize("fmt,package,advisory,dev", [
    ("cyclonedx", "pkg:npm/minimist@1.2.5", "adv:GHSA-xvch-5gv4-984h", False),
    ("cyclonedx", "pkg:npm/semver@7.5.1", "adv:GHSA-c2qf-rxjj-qqgw", True),
    ("spdx", "pkg:pypi/certifi@2023.7.22", "adv:GHSA-6q48-6c7w-9gw2", False),
    ("uv", "pkg:pypi/pytest@8.2.0", "adv:GHSA-6w46-j5rx-g56g", True),
    ("cargo", "pkg:cargo/smallvec@1.6.0", "adv:GHSA-43w2-9j62-hq99", False),
    ("go", "pkg:golang/golang.org/x/text@0.3.7", "adv:GHSA-69ch-w2m2-3vjp", False),
])
def test_each_ecosystem_has_an_affected_finding_from_the_cache(fmt, package, advisory, dev):
    rep = report(fmt)
    hit = [f for f in rep["findings"] if f["package"] == package and f["advisory"] == advisory]
    assert len(hit) == 1 and hit[0]["status"] == "affected" and hit[0]["dev_only"] is dev
    assert hit[0]["path"][0] == "repo:Demo" and hit[0]["path"][-2:] == [package, advisory]
    assert any(p["verdict"] == "violated" for p in hit[0]["policies"]) is (not dev and hit[0]["severity"] in ("HIGH", "CRITICAL"))


def test_the_report_lists_packages_it_could_not_query():
    assert report("cyclonedx")["unresolved_packages"] == [
        {"package": "pkg:generic/openssl@3.0.11", "reason": "purl type generic has no OSV ecosystem this reader can name"}]
    assert report("cargo")["unresolved_packages"] == []


@pytest.mark.parametrize("fmt", ["cyclonedx", "spdx", "uv", "cargo", "go"])
def test_the_cli_audits_every_format_offline_from_the_cache(fmt, no_network, capsys):
    assert cli.main(["audit", str(VINC), str(FILES[fmt]), "--repo", "Demo", "--osv-cache", str(CACHE)]) == 0
    rep = json.loads(capsys.readouterr().out)
    assert rep["summary"]["affected"] > 0 and rep["meta"]["packages"] == len(packages(fmt))


def test_a_package_missing_from_the_cache_stops_the_run(no_network):
    cache = osv_cache()
    del cache["queries"]["pkg:cargo/serde@1.0.130"]
    text, _ = inventory.load(FILES["cargo"])
    with pytest.raises(external.NetworkRefused, match="pkg:cargo/serde@1.0.130"):
        audit.run(co.load(VINC.read_text(encoding="utf-8")), text, "Demo", advisories=external.cached_advisories(cache), filename="Cargo.lock")


def test_pep440_agrees_with_packaging_on_the_cached_pypi_versions():
    version = pytest.importorskip("packaging.version")
    seen = sorted({v for r in osv_cache()["vulns"].values() for a in r["affected"] if a["package"]["ecosystem"] == "PyPI"
                   for v in a.get("versions") or []} | {"1.0.dev0", "1.0a1.post1.dev2", "1.0b2-346", "1.0c1", "1!0.1", "1.0+abc.5", "1.0+5"})
    assert sorted(seen, key=pep440.key) == sorted(seen, key=version.Version)


def propose(tmp_path: Path, capsys, fmt: str, rep: dict) -> tuple[int, dict, str]:
    (tmp_path / "report.json").write_text(json.dumps(rep), encoding="utf-8")
    capsys.readouterr()
    code = cli.main(["propose", str(tmp_path / "report.json"), str(VINC), str(FILES[fmt]), "--repo", "Demo", "--space", "demo-space",
                     "--osv-cache", str(CACHE), "--out", str(tmp_path / "plan.json")])
    return code, json.loads((tmp_path / "plan.json").read_text(encoding="utf-8")), capsys.readouterr().out


@pytest.mark.parametrize("fmt", ["cyclonedx", "spdx", "uv", "cargo", "go"])
def test_propose_re_derives_the_records_of_every_ecosystem(tmp_path, capsys, no_network, fmt):
    code, plan, out = propose(tmp_path, capsys, fmt, report(fmt))
    assert code == 0 and plan["nodes"] and plan["held"] == [] and "; 0 failed." in out
    assert all(n["props"]["subject_path"] == f"demo:{FILES[fmt].name}" for n in plan["nodes"])


def test_propose_holds_a_go_record_whose_version_is_not_in_the_inventory(tmp_path, capsys, no_network):
    rep = report("go")
    f = next(f for f in rep["findings"] if f["package"] == "pkg:golang/golang.org/x/text@0.3.7" and f["advisory"] == "adv:GHSA-69ch-w2m2-3vjp")
    f["package"] = "pkg:golang/golang.org/x/text@0.3.8"
    code, plan, out = propose(tmp_path, capsys, "go", rep)
    assert code == 1
    held = next(h for h in plan["held"] if h.get("failed"))
    assert "golang.org/x/text 0.3.8 is not a package in the lockfile" in held["failed"]
    assert "golang.org/x/text 0.3.8 is not inside the advisory's affected ranges" in held["failed"]


def test_propose_checks_pypi_records_by_their_pep440_ranges(tmp_path, capsys, no_network):
    cache = osv_cache()
    for record in cache["vulns"].values():
        record["affected"] = ranges_only(record)
    stripped = tmp_path / "osv-cache.json"
    stripped.write_text(json.dumps(cache), encoding="utf-8")
    text, siblings = inventory.load(FILES["uv"])
    rep = audit.run(co.load(VINC.read_text(encoding="utf-8")), text, "Demo", advisories=external.cached_advisories(cache),
                    filename="uv.lock", siblings=siblings)
    assert rep["summary"]["affected"] == 10 and rep["summary"]["unresolved"] == 0
    (tmp_path / "report.json").write_text(json.dumps(rep), encoding="utf-8")
    capsys.readouterr()
    code = cli.main(["propose", str(tmp_path / "report.json"), str(VINC), str(FILES["uv"]), "--repo", "Demo", "--space", "demo-space",
                     "--osv-cache", str(stripped), "--out", str(tmp_path / "plan.json")])
    plan = json.loads((tmp_path / "plan.json").read_text(encoding="utf-8"))
    assert code == 0 and plan["nodes"] and plan["held"] == []


def lodash_twice() -> dict:
    prod, dev = "lodash@4.17.20|node_modules/lodash", "lodash@4.17.20|node_modules/jest/node_modules/lodash"
    flag = {"name": "cdx:npm:package:development", "value": "true"}
    return {"bomFormat": "CycloneDX", "specVersion": "1.5", "metadata": {"component": {"bom-ref": "root", "name": "app", "version": "1.0.0"}},
            "components": [{"bom-ref": prod, "name": "lodash", "version": "4.17.20", "purl": "pkg:npm/lodash@4.17.20"},
                           {"bom-ref": dev, "name": "lodash", "version": "4.17.20", "purl": "pkg:npm/lodash@4.17.20", "properties": [flag]},
                           {"bom-ref": "jest@1.0.0", "name": "jest", "version": "1.0.0", "purl": "pkg:npm/jest@1.0.0", "properties": [flag]}],
            "dependencies": [{"ref": "root", "dependsOn": [prod, "jest@1.0.0"]}, {"ref": "jest@1.0.0", "dependsOn": [dev]}]}


def test_a_production_instance_of_a_package_wins_over_a_development_one():
    nodes, edges = inventory.read(json.dumps(lodash_twice()), "bom.json", "Demo")
    dev = {n["id"]: n["props"]["dev"] for n in nodes if n["kind"] == "Package"}
    assert dev == {"pkg:npm/lodash@4.17.20": False, "pkg:npm/jest@1.0.0": True}
    adv = {"id": "GHSA-test-0000-0001", "summary": "test", "database_specific": {"severity": "HIGH"},
           "affected": [{"package": {"ecosystem": "npm", "name": "lodash"}, "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "4.17.21"}]}]}]}
    cache = {"fetched_at": "2026-11-25T00:00:00Z", "queries": {"pkg:npm/lodash@4.17.20": ["GHSA-test-0000-0001"], "pkg:npm/jest@1.0.0": []},
             "vulns": {"GHSA-test-0000-0001": adv}}
    rep = audit.run(co.load(VINC.read_text(encoding="utf-8")), json.dumps(lodash_twice()), "Demo",
                    advisories=external.cached_advisories(cache), filename="bom.json")
    assert rep["violations"] >= 1
    assert all(not f["dev_only"] for f in rep["findings"])


def test_a_package_marked_development_everywhere_and_reached_only_that_way_stays_development():
    bom = lodash_twice()
    bom["components"][0]["properties"] = [{"name": "cdx:npm:package:development", "value": "true"}]
    nodes, _ = inventory.read(json.dumps(bom), "bom.json", "Demo")
    assert {n["id"]: n["props"]["dev"] for n in nodes if n["kind"] == "Package"} == {"pkg:npm/lodash@4.17.20": True, "pkg:npm/jest@1.0.0": True}


@pytest.mark.parametrize("kind,ecosystem,version", [("SEMVER", "npm", "2.0.0"), ("ECOSYSTEM", "PyPI", "2.0.0"),
                                                    ("SEMVER", "crates.io", "2.0.0"), ("ECOSYSTEM", "Go", "1.5.0")])
def test_a_version_at_or_above_the_range_limit_is_not_affected(kind, ecosystem, version):
    affected = [{"package": {"ecosystem": ecosystem, "name": "p"}, "ranges": [{"type": kind, "events": [{"introduced": "0"}, {"limit": "1.5.0"}]}]}]
    assert semver.affects(version, ecosystem, "p", affected) is False
    assert semver.affects("1.4.0", ecosystem, "p", affected) is True


def cpe_only_sboms() -> dict[str, str]:
    cpe = "cpe:2.3:a:openssl:openssl:1.1.1k:*:*:*:*:*:*:*"
    bom = {"bomFormat": "CycloneDX", "specVersion": "1.5", "components": [
        {"bom-ref": "a", "type": "library", "name": "openssl", "version": "1.1.1k", "cpe": cpe},
        {"bom-ref": "b", "type": "library", "name": "log4j-core", "group": "org.apache.logging.log4j", "version": "2.14.1"}]}
    doc = {"spdxVersion": "SPDX-2.3", "SPDXID": "SPDXRef-DOCUMENT", "packages": [
        {"SPDXID": "SPDXRef-a", "name": "openssl", "versionInfo": "1.1.1k", "licenseConcluded": "NOASSERTION",
         "externalRefs": [{"referenceCategory": "SECURITY", "referenceType": "cpe23Type", "referenceLocator": cpe}]}], "relationships": []}
    return {"bom.cdx.json": json.dumps(bom), "sbom.spdx.json": json.dumps(doc)}


@pytest.mark.parametrize("name", ["bom.cdx.json", "sbom.spdx.json"])
def test_a_component_without_a_purl_is_unresolved_with_its_cpe(name):
    nodes, _ = inventory.read(cpe_only_sboms()[name], name, "Demo")
    pkgs = {n["id"]: n["props"] for n in nodes if n["kind"] == "Package"}
    assert pkgs["pkg:unknown/openssl@1.1.1k"]["unresolved"] == "the inventory gives no purl; CPE cpe:2.3:a:openssl:openssl:1.1.1k:*:*:*:*:*:*:*"
    assert all(set(p) == PACKAGE_PROPS and p["ecosystem"] == "" for p in pkgs.values())


@pytest.mark.parametrize("name", ["bom.cdx.json", "sbom.spdx.json"])
def test_an_sbom_with_nothing_to_query_is_refused_not_reported_clean(tmp_path, capsys, no_network, name):
    path = tmp_path / name
    path.write_text(cpe_only_sboms()[name], encoding="utf-8")
    with pytest.raises(SystemExit) as stop:
        cli.main(["audit", str(VINC), str(path), "--repo", "Demo", "--osv-cache", str(CACHE)])
    assert stop.value.code != 0 and "can be queried at OSV, so there is nothing to audit" in capsys.readouterr().err


def test_an_sbom_with_some_unresolved_packages_lists_them_beside_the_findings(tmp_path, capsys, no_network):
    out = tmp_path / "report.json"
    assert cli.main(["audit", str(VINC), str(FILES["cyclonedx"]), "--repo", "Demo", "--osv-cache", str(CACHE), "--out", str(out)]) == 0
    assert json.loads(capsys.readouterr().out)["unresolved_packages"] == 1


@pytest.mark.parametrize("name,text", [("uv.lock", "version = 1\nrequires-python = \">=3.11\"\n"), ("Cargo.lock", "version = 3\n"),
                                       ("package-lock.json", '{"lockfileVersion": 3, "packages": {"": {"name": "app"}}}')])
def test_an_inventory_with_no_packages_is_refused(name, text):
    with pytest.raises(ValueError, match="lists no packages, so there is nothing to audit"):
        inventory.read(text, name, "Demo")
