from __future__ import annotations

import json
from pathlib import Path

import pytest

from test_audit import no_network
from test_inventory import PACKAGE_PROPS, VINC, ranges_only
from decisis import audit, cli, external, inventory, maven, semver
from decisis import checkout as co
from decisis.inventory import gradle, shape
from decisis.inventory import pom as reader

JVM = Path(__file__).resolve().parents[1] / "fixtures" / "inventory" / "jvm"
CACHE = JVM / "osv-cache.json"
FILES = {"gradle": JVM / "gradle.lockfile", "pom": JVM / "pom.xml"}
LOG4J = "pkg:maven/org.apache.logging.log4j:log4j-core@2.14.1"
QUALIFIER_ORDER = ["1-alpha2snapshot", "1-alpha2", "1-alpha-123", "1-beta-2", "1-beta123", "1-m2", "1-m11", "1-rc", "1-cr2", "1-rc123",
                   "1-SNAPSHOT", "1", "1-sp", "1-sp2", "1-sp123", "1-abc", "1-def", "1-pom-1", "1-1-snapshot", "1-1", "1-2", "1-123"]
NUMBER_ORDER = ["2.0", "2.0.a", "2-1", "2.0.2", "2.0.123", "2.1.0", "2.1-a", "2.1b", "2.1-c", "2.1-1", "2.1.0.1", "2.2", "2.123",
                "11.a2", "11.a11", "11.b2", "11.b11", "11.m2", "11.m11", "11", "11.a", "11b", "11c", "11m"]
LOG4J_ORDER = ["2.0-alpha1", "2.0-beta9", "2.0-rc1", "2.0", "2.0.1", "2.3.1", "2.4", "2.12.2", "2.13.0", "2.14.1", "2.15.0",
               "3.0.0-alpha1", "3.0.0-beta3", "3.0.0"]
SPEC_ORDER = [["1-snapshot", "1", "1-sp"], ["1-foo2", "1-foo10"], ["1.foo", "1-1", "1.1"], ["1-ga.1", "1-sp.1"]]


def osv_cache() -> dict:
    return external.read_osv_cache(CACHE.read_text(encoding="utf-8"))


def read(fmt: str, repo: str = "Demo") -> tuple[list[dict], list[dict]]:
    text, siblings = inventory.load(FILES[fmt])
    return inventory.read(text, FILES[fmt].name, repo, siblings)


def packages(fmt: str) -> dict[str, dict]:
    return {n["id"]: n["props"] for n in read(fmt)[0] if n["kind"] == "Package"}


def report(fmt: str) -> dict:
    text, siblings = inventory.load(FILES[fmt])
    return audit.run(co.load(VINC.read_text(encoding="utf-8")), text, "Demo", advisories=external.cached_advisories(osv_cache()),
                     filename=FILES[fmt].name, siblings=siblings)


def pom(dependencies: str, head: str = "") -> str:
    return (f'<project xmlns="http://maven.apache.org/POM/4.0.0"><modelVersion>4.0.0</modelVersion>{head}'
            f"<dependencies>{dependencies}</dependencies></project>")


def dep(group: str, artifact: str, version: str = "", scope: str = "") -> str:
    v = f"<version>{version}</version>" if version else ""
    s = f"<scope>{scope}</scope>" if scope else ""
    return f"<dependency><groupId>{group}</groupId><artifactId>{artifact}</artifactId>{v}{s}</dependency>"


def read_pom(text: str) -> dict[str, dict]:
    return {n["props"]["name"]: n["props"] for n in inventory.read(text, "pom.xml", "Demo")[0] if n["kind"] == "Package"}


@pytest.mark.parametrize("order", [QUALIFIER_ORDER, NUMBER_ORDER, LOG4J_ORDER, *SPEC_ORDER], ids=lambda o: o[0])
def test_maven_versions_order_like_comparable_version(order):
    for i, lower in enumerate(order):
        for higher in order[i + 1:]:
            assert maven.key(lower) < maven.key(higher), (lower, higher)


@pytest.mark.parametrize("a,b", [("1", "1.0"), ("1", "1.0.0"), ("1", "1-0"), ("1.0", "1.0-0"), ("1a", "1-a"), ("1a", "1.0.0-a"),
                                 ("1ga", "1"), ("1.ga", "1-ga"), ("1release", "1"), ("1Final", "1"), ("1cr", "1rc"),
                                 ("1a1", "1-alpha-1"), ("1b2", "1-beta-2"), ("1m3", "1-milestone-3"), ("1X", "1x"),
                                 ("1.0-SNAPSHOT", "1-snapshot"), ("1.foo", "1-foo")])
def test_maven_treats_equal_spellings_as_equal(a, b):
    assert maven.key(a) == maven.key(b)


def test_maven_refuses_an_empty_version():
    with pytest.raises(ValueError):
        maven.key(" ")


def test_every_version_osv_lists_for_a_maven_package_falls_in_its_ranges():
    checked = 0
    for record in osv_cache()["vulns"].values():
        for a in record["affected"]:
            if a["package"]["ecosystem"] == "Maven" and a.get("ranges"):
                for v in a.get("versions") or []:
                    assert semver.affects(v, "Maven", a["package"]["name"], ranges_only({"affected": [a]})) is True, v
                    checked += 1
    assert checked > 500


@pytest.mark.parametrize("version,inside", [("2.14.1", True), ("2.0-beta9", True), ("2.12.1", True), ("2.0-beta8", False),
                                            ("2.3.1", False), ("2.12.2", False), ("2.15.0", False), ("2.17.1", False)])
def test_log4j_core_is_placed_in_the_log4shell_ranges_by_maven_order(version, inside):
    affected = ranges_only(osv_cache()["vulns"]["GHSA-jfh8-c2jp-5v3q"])
    assert semver.affects(version, "Maven", "org.apache.logging.log4j:log4j-core", affected) is inside


@pytest.mark.parametrize("fmt", sorted(FILES))
def test_the_format_is_told_from_the_content_and_the_file_name(fmt):
    text, _ = inventory.load(FILES[fmt])
    assert inventory.detect(text, FILES[fmt].name) == fmt
    assert inventory.detect(text, "inventory.txt") == fmt


@pytest.mark.parametrize("fmt", sorted(FILES))
def test_both_readers_return_the_shared_node_and_edge_shape(fmt):
    nodes, edges = read(fmt)
    pkgs = [n for n in nodes if n["kind"] == "Package"]
    assert pkgs and all(set(n["props"]) == PACKAGE_PROPS and n["props"]["ecosystem"] == "Maven" for n in pkgs)
    assert all(e["source"] == "repo:Demo" and e["type"] == "DEPENDS_ON" and e["evidence"] for e in edges)
    assert {e["target"] for e in edges} == {n["id"] for n in pkgs}


def test_gradle_packages_are_named_group_colon_artifact_and_test_or_compile_only_configurations_are_dev():
    pkgs = packages("gradle")
    assert {p["name"]: p["dev"] for p in pkgs.values()} == {
        "com.google.code.gson:gson": False, "junit:junit": True, "org.apache.logging.log4j:log4j-api": False,
        "org.apache.logging.log4j:log4j-core": False, "org.hamcrest:hamcrest-core": True, "org.projectlombok:lombok": True}
    assert all(p["source_system"] == "gradle-lockfile" and p["unresolved"] == "" for p in pkgs.values())
    assert pkgs[LOG4J]["purl"] == "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"


@pytest.mark.parametrize("configuration,dev", [("runtimeClasspath", False), ("compileClasspath", True), ("testRuntimeClasspath", True),
                                               ("integrationTestRuntimeClasspath", True), ("compileOnly", True),
                                               ("annotationProcessor", True), ("kapt", True), ("releaseRuntimeClasspath", False),
                                               ("classpath", False)])
def test_gradle_configuration_names_mark_development_use(configuration, dev):
    assert gradle.development(configuration) is dev


def test_a_settings_gradle_lockfile_is_read_the_same_way():
    text = "com.gradle:develocity-gradle-plugin:3.17=classpath\nempty=\n"
    assert inventory.detect(text, "settings-gradle.lockfile") == "gradle"
    nodes, _ = inventory.read(text, "settings-gradle.lockfile", "Demo")
    assert [n["id"] for n in nodes if n["kind"] == "Package"] == ["pkg:maven/com.gradle:develocity-gradle-plugin@3.17"]


def test_a_gradle_line_that_is_not_a_coordinate_is_refused():
    with pytest.raises(ValueError, match="line 2 of the Gradle lockfile"):
        inventory.read("a:b:1=runtimeClasspath\nnot-a-coordinate=runtimeClasspath\n", "gradle.lockfile", "Demo")


def test_gradle_and_pom_packages_get_the_same_id_and_purl_as_a_cyclonedx_maven_component():
    from_sbom = shape.from_purl("pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1?type=jar")
    for fmt in FILES:
        props = packages(fmt)[from_sbom["id"]]
        assert (props["ecosystem"], props["name"], props["version"], props["purl"]) == \
            (from_sbom["ecosystem"], from_sbom["name"], from_sbom["version"], from_sbom["purl"])


def test_pom_versions_come_from_literals_properties_and_the_files_own_dependency_management():
    pkgs = {p["name"]: p for p in packages("pom").values()}
    assert pkgs["org.apache.logging.log4j:log4j-core"]["version"] == "2.14.1"
    assert pkgs["org.apache.logging.log4j:log4j-api"]["version"] == "2.14.1"
    assert pkgs["com.google.code.gson:gson"]["version"] == "2.10.1"
    assert pkgs["org.hamcrest:hamcrest-core"]["version"] == "1.3"
    assert {n: p["dev"] for n, p in pkgs.items() if p["dev"]} == {
        "jakarta.servlet:jakarta.servlet-api": True, "junit:junit": True, "org.hamcrest:hamcrest-core": True}
    assert all(p["source_system"] == "maven-pom" for p in pkgs.values())


def test_pom_versions_it_cannot_resolve_are_listed_with_the_reason():
    assert report("pom")["unresolved_packages"] == [
        {"package": "pkg:maven/com.google.guava:guava@",
         "reason": "version ${guava.version}: property guava.version is not defined in this POM (it may come from a parent or the build)"},
        {"package": "pkg:maven/org.apache.commons:commons-text@", "reason": "version range [1.9,2.0) is chosen by Maven at build time"},
        {"package": "pkg:maven/org.springframework.boot:spring-boot-starter-web@",
         "reason": "pom.xml gives no version; Maven takes it from the parent org.springframework.boot:spring-boot-starter-parent:2.7.18 "
                   "or the imported BOM com.fasterxml.jackson:jackson-bom:2.15.3"}]
    assert packages("pom")["pkg:maven/org.apache.commons:commons-text@"]["purl"] == "pkg:maven/org.apache.commons/commons-text"


def test_pom_project_properties_resolve_and_loops_and_build_time_versions_do_not():
    head = "<parent><groupId>p</groupId><artifactId>parent</artifactId><version>3.1</version></parent>" \
           "<properties><a>${b}</a><b>${a}</b></properties>"
    pkgs = read_pom(pom(dep("p", "own", "${project.parent.version}") + dep("p", "same", "${project.version}") + dep("x", "loop", "${a}")
                        + dep("x", "latest", "LATEST"), head))
    assert pkgs["p:own"]["version"] == pkgs["p:same"]["version"] == "3.1"
    assert pkgs["x:loop"]["unresolved"] == "version ${a}: properties refer to each other in a loop"
    assert pkgs["x:latest"]["unresolved"] == "version LATEST is chosen by Maven at build time"


def test_pom_properties_that_grow_without_bound_are_unresolved():
    props = "".join(f"<p{i}>{'${p%d}' % (i + 1) * 10}</p{i}>" for i in range(12)) + "<p12>x</p12>"
    pkgs = read_pom(pom(dep("x", "huge", "${p0}"), f"<properties>{props}</properties>"))
    assert pkgs["x:huge"]["unresolved"] == "version ${p0}: properties expand to more than 256 characters"


def test_a_pom_without_a_parent_or_bom_says_nothing_manages_the_version():
    pkgs = read_pom(pom(dep("g", "a") + dep("g", "b", "1.0")))
    assert pkgs["g:a"]["unresolved"] == "pom.xml gives no version and does not manage one"


@pytest.mark.parametrize("text", [
    '<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;">]><project>&lol2;</project>',
    '<?xml version="1.0"?><!DOCTYPE project SYSTEM "http://example.invalid/x.dtd"><project/>',
    '<?xml version="1.0"?><!doctype project [<!entity x SYSTEM "file:///etc/passwd">]><project>&x;</project>'])
def test_a_pom_with_a_doctype_or_entity_is_refused_before_parsing(text, monkeypatch):
    monkeypatch.setattr(reader.ET, "fromstring", lambda *a: pytest.fail("parsed"))
    with pytest.raises(ValueError, match="DOCTYPE or entity declaration"):
        inventory.read(text, "pom.xml", "Demo")


@pytest.mark.parametrize("text,match", [("<project><dependencies>", "not well-formed XML"), ("<settings/>", "root element is settings")])
def test_a_pom_that_is_not_a_project_is_refused(text, match):
    with pytest.raises(ValueError, match=match):
        inventory.read(text, "pom.xml", "Demo")


@pytest.mark.parametrize("name,text", [("gradle.lockfile", "# This is a Gradle generated file for dependency locking.\nempty=\n"),
                                       ("pom.xml", "<project><dependencies/></project>")])
def test_a_jvm_inventory_with_no_packages_is_refused(name, text):
    with pytest.raises(ValueError, match="lists no packages, so there is nothing to audit"):
        inventory.read(text, name, "Demo")


@pytest.mark.parametrize("fmt", sorted(FILES))
def test_log4j_core_2_14_1_is_an_affected_finding_in_both_formats(fmt):
    rep = report(fmt)
    hit = [f for f in rep["findings"] if f["package"] == LOG4J and f["advisory"] == "adv:GHSA-jfh8-c2jp-5v3q"]
    assert len(hit) == 1 and hit[0]["status"] == "affected" and hit[0]["severity"] == "CRITICAL" and hit[0]["dev_only"] is False
    assert hit[0]["path"] == ["repo:Demo", LOG4J, "adv:GHSA-jfh8-c2jp-5v3q"]
    assert any(p["verdict"] == "violated" for p in hit[0]["policies"])


@pytest.mark.parametrize("fmt,plugin", [("gradle", "cyclonedx-gradle-plugin"), ("pom", "cyclonedx-maven-plugin")])
def test_the_report_notes_that_transitive_dependencies_are_not_resolved(fmt, plugin):
    notes = report(fmt)["notes"]
    assert len(notes) == 1 and "transitive dependencies are not resolved" in notes[0] and plugin in notes[0] and "CycloneDX" in notes[0]


def test_other_formats_carry_no_notes_key():
    text = (VINC.parent.parent / "inventory" / "Cargo.lock").read_text(encoding="utf-8")
    cache = external.read_osv_cache((VINC.parent.parent / "inventory" / "osv-cache.json").read_text(encoding="utf-8"))
    rep = audit.run(co.load(VINC.read_text(encoding="utf-8")), text, "Demo", advisories=external.cached_advisories(cache), filename="Cargo.lock")
    assert "notes" not in rep


@pytest.mark.parametrize("fmt", sorted(FILES))
def test_the_cli_audits_both_formats_offline_and_the_html_shows_the_note(fmt, no_network, capsys):
    assert cli.main(["audit", str(VINC), str(FILES[fmt]), "--repo", "Demo", "--osv-cache", str(CACHE)]) == 0
    rep = json.loads(capsys.readouterr().out)
    assert rep["summary"]["affected"] > 0 and rep["meta"]["packages"] == len(packages(fmt)) and rep["notes"]
    assert cli.main(["audit", str(VINC), str(FILES[fmt]), "--repo", "Demo", "--osv-cache", str(CACHE), "--format", "html"]) == 0
    page = capsys.readouterr().out
    assert "<h2>Notes</h2>" in page and "transitive dependencies are not resolved" in page


@pytest.mark.parametrize("fmt", sorted(FILES))
def test_propose_re_derives_the_jvm_records(tmp_path, capsys, no_network, fmt):
    (tmp_path / "report.json").write_text(json.dumps(report(fmt)), encoding="utf-8")
    code = cli.main(["propose", str(tmp_path / "report.json"), str(VINC), str(FILES[fmt]), "--repo", "Demo", "--space", "demo-space",
                     "--osv-cache", str(CACHE), "--out", str(tmp_path / "plan.json")])
    plan = json.loads((tmp_path / "plan.json").read_text(encoding="utf-8"))
    assert code == 0 and plan["nodes"] and plan["held"] == [] and "; 0 failed." in capsys.readouterr().out
