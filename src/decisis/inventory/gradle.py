from __future__ import annotations

import re

from .shape import Inventory, make_purl, package_id, text_digest

FORMAT = "gradle"
SIBLINGS: tuple[str, ...] = ()
NAMES = ("gradle.lockfile", "settings-gradle.lockfile")
HEADER = "# This is a Gradle generated file for dependency locking."
TEST = re.compile(r"^test|Test")
COMPILE_ONLY = re.compile(r"compileonly|compileclasspath|annotationprocessor|^kapt|^ksp", re.I)
NOTES = ("A Gradle lockfile pins every resolved version but not which dependency brings in which, so transitive "
         "dependencies are not resolved into paths: each package is linked to the repository directly. For the full "
         "dependency graph, generate a CycloneDX SBOM with cyclonedx-gradle-plugin (gradle cyclonedxBom) and audit "
         "that file; audit reads CycloneDX JSON.",)


def detect(text: str, filename: str) -> bool:
    return filename in NAMES or text.lstrip().startswith(HEADER)


def development(configuration: str) -> bool:
    return bool(TEST.search(configuration) or COMPILE_ONLY.search(configuration))


def entries(text: str) -> list[tuple[str, str, str, list[str]]]:
    out = []
    for number, line in enumerate(text.splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        coordinate, _, configurations = line.partition("=")
        if coordinate == "empty":
            continue
        parts = coordinate.split(":")
        if len(parts) != 3 or not all(parts):
            raise ValueError(f"line {number} of the Gradle lockfile is not group:artifact:version=configurations: {line[:80]}")
        out.append((*parts, [c for c in configurations.split(",") if c]))
    return out


def read(text: str, filename: str, repo: str, siblings: dict[str, str] | None = None) -> tuple[list[dict], list[dict]]:
    inv = Inventory(repo, "gradle-lockfile", text_digest(text))
    for group, artifact, version, configurations in entries(text):
        name = f"{group}:{artifact}"
        pkg = {"id": package_id("Maven", name, version), "ecosystem": "Maven", "name": name, "version": version,
               "purl": make_purl("maven", f"{group}/{artifact}", version), "unresolved": ""}
        dev = bool(configurations) and all(development(c) for c in configurations)
        inv.add((name, version), pkg, f"{repo}:{filename}#{name}:{version}", dev=dev)
        inv.depends(None, (name, version), f"{filename} locks {name}:{version} for {', '.join(configurations) or 'no configuration'}")
    return inv.result()
