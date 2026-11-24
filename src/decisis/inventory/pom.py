from __future__ import annotations

import re
import xml.etree.ElementTree as ET

from .shape import Inventory, make_purl, package_id, text_digest

FORMAT = "pom"
SIBLINGS: tuple[str, ...] = ()
POM_NS = "http://maven.apache.org/POM/4.0.0"
DEV_SCOPES = {"test", "provided"}
BUILD_TIME = {"LATEST", "RELEASE"}
UNSAFE = re.compile(r"<!\s*(DOCTYPE|ENTITY)", re.I)
PROPERTY = re.compile(r"\$\{([^}]*)\}")
MAX_HOPS = 16
MAX_LENGTH = 256
NOTES = ("A pom.xml declares direct dependencies only, so transitive dependencies are not resolved and a vulnerable "
         "package that arrives through another one is not audited. For the full dependency graph, generate a CycloneDX "
         "SBOM with cyclonedx-maven-plugin (mvn org.cyclonedx:cyclonedx-maven-plugin:makeAggregateBom) and audit "
         "target/bom.json; audit reads CycloneDX JSON.",)


def detect(text: str, filename: str) -> bool:
    head = text[:2000]
    return filename == "pom.xml" or filename.endswith(".pom") or (POM_NS in head and "<project" in head)


def _local(tag) -> str:
    return tag.rsplit("}", 1)[-1] if isinstance(tag, str) else ""


def _children(el, name: str) -> list:
    return [c for c in el if _local(c.tag) == name] if el is not None else []


def _child(el, name: str):
    return next(iter(_children(el, name)), None)


def _text(el, name: str) -> str:
    c = _child(el, name)
    return (c.text or "").strip() if c is not None else ""


def parse(text: str, filename: str):
    if UNSAFE.search(text):
        raise ValueError(f"{filename} has a DOCTYPE or entity declaration; audit refuses it instead of expanding entities")
    try:
        root = ET.fromstring(text)
    except ET.ParseError as e:
        raise ValueError(f"{filename} is not well-formed XML: {e}") from None
    if _local(root.tag) != "project":
        raise ValueError(f"{filename} is not a Maven POM: its root element is {_local(root.tag)}, not project")
    return root


def properties(root) -> dict[str, str]:
    parent = _child(root, "parent")
    builtin = {"project.groupId": _text(root, "groupId") or _text(parent, "groupId"), "project.artifactId": _text(root, "artifactId"),
               "project.version": _text(root, "version") or _text(parent, "version"), "project.parent.groupId": _text(parent, "groupId"),
               "project.parent.artifactId": _text(parent, "artifactId"), "project.parent.version": _text(parent, "version")}
    block = _child(root, "properties")
    declared = {_local(c.tag): (c.text or "").strip() for c in (list(block) if block is not None else [])}
    return {k: v for k, v in {**declared, **builtin}.items() if v}


def expand(value: str, props: dict[str, str]) -> tuple[str, str]:
    for _ in range(MAX_HOPS):
        missing = [m for m in PROPERTY.findall(value) if m not in props]
        if missing:
            return value, f"property {missing[0]} is not defined in this POM (it may come from a parent or the build)"
        if len(PROPERTY.sub("", value)) + sum(len(props[m]) for m in PROPERTY.findall(value)) > MAX_LENGTH:
            return value, f"properties expand to more than {MAX_LENGTH} characters"
        done = PROPERTY.sub(lambda m: props[m[1]], value)
        if done == value:
            return value, ""
        value = done
    return value, "properties refer to each other in a loop"


def coordinates(el) -> str:
    return ":".join(_text(el, k) or "?" for k in ("groupId", "artifactId", "version"))


def managed(root, props: dict[str, str]) -> tuple[dict[str, object], list[str]]:
    entries = _children(_child(_child(root, "dependencyManagement"), "dependencies"), "dependency")
    local = {f"{expand(_text(d, 'groupId'), props)[0]}:{expand(_text(d, 'artifactId'), props)[0]}": d
             for d in entries if _text(d, "scope") != "import"}
    boms = [coordinates(d) for d in entries if _text(d, "scope") == "import"]
    return local, boms


def no_version(root, boms: list[str], filename: str) -> str:
    parent = _child(root, "parent")
    sources = ([f"the parent {coordinates(parent)}"] if parent is not None else []) + [f"the imported BOM {b}" for b in boms]
    if not sources:
        return f"{filename} gives no version and does not manage one"
    return f"{filename} gives no version; Maven takes it from {' or '.join(sources)}"


def chosen_at_build(version: str) -> str:
    if version.startswith(("[", "(")) or "," in version:
        return f"version range {version} is chosen by Maven at build time"
    if version in BUILD_TIME:
        return f"version {version} is chosen by Maven at build time"
    return ""


def _purl(group: str, artifact: str, version: str) -> str:
    purl = make_purl("maven", f"{group}/{artifact}", version)
    return purl if version else purl[:-1]


def _problem(field: str, raw: str, problem: str) -> str:
    return f"{field} {raw}: {problem}" if problem else ""


def dependency(d, props: dict[str, str], local: dict, missing: str) -> dict:
    raw_group, raw_artifact = _text(d, "groupId"), _text(d, "artifactId")
    group, group_problem = expand(raw_group, props)
    artifact, artifact_problem = expand(raw_artifact, props)
    name = f"{group}:{artifact}"
    entry = local.get(name)
    raw = _text(d, "version") or _text(entry, "version")
    version, version_problem = expand(raw, props) if raw else ("", "")
    problems = ["" if raw_group and raw_artifact else "the dependency has no groupId or no artifactId",
                _problem("groupId", raw_group, group_problem), _problem("artifactId", raw_artifact, artifact_problem),
                _problem("version", raw, version_problem), "" if raw else missing, chosen_at_build(version)]
    reason = next((p for p in problems if p), "")
    version = "" if reason else version
    return {"pkg": {"id": package_id("Maven", name, version), "ecosystem": "Maven", "name": name, "version": version,
                    "purl": _purl(group, artifact, version), "unresolved": reason},
            "scope": _text(d, "scope") or _text(entry, "scope") or "compile", "declared": raw or "no version"}


def read(text: str, filename: str, repo: str, siblings: dict[str, str] | None = None) -> tuple[list[dict], list[dict]]:
    root = parse(text, filename)
    props = properties(root)
    local, boms = managed(root, props)
    missing = no_version(root, boms, filename)
    inv = Inventory(repo, "maven-pom", text_digest(text))
    for i, d in enumerate(_children(_child(root, "dependencies"), "dependency")):
        dep = dependency(d, props, local, missing)
        pkg = dep["pkg"]
        inv.add(i, pkg, f"{repo}:{filename}#{pkg['name']}:{dep['declared']}", dev=dep["scope"] in DEV_SCOPES)
        inv.depends(None, i, f"{filename} declares {pkg['name']}:{dep['declared']} (scope {dep['scope']})")
    return inv.result()
