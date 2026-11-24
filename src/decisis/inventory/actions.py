from __future__ import annotations

import re

from .. import yamltext
from .shape import Inventory, make_purl, package_id, text_digest
from .siblings import clean

FORMAT = "github-actions"
SIBLINGS: tuple[str, ...] = ()
ECOSYSTEM = "GitHub Actions"
SOURCE = "github-actions-workflow"
ACTION_FILES = ("action.yml", "action.yaml")
SUFFIXES = (".yml", ".yaml")
MAX_FILES = 256
USES = re.compile(r"([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)((?:/[^@\s]+)?)@(\S+)")
JOBS = re.compile(r"^jobs\s*:", re.M)
ON = re.compile(r"""^(on|"on"|'on')\s*:""", re.M)
RUNS = re.compile(r"^runs\s*:", re.M)
LOCAL = "a local action or workflow in this repository; it is listed, not queried"
DOCKER = "a Docker image, not a GitHub action; it is listed, not queried"
EXPRESSION = "the uses value is built from an expression, so the action is not known until the workflow runs"
NOTES = ("OSV does not order GitHub Actions versions, so audit asks OSV for every advisory of each action and compares the ref with "
         "the advisory's ranges itself: a tag is read as a version, a major or minor tag such as v4 or v4.1 stands for every release "
         "under it, and a branch or a commit SHA cannot be ordered, so its advisories are unresolved unless OSV lists the ref",)


def workflow(text: str) -> bool:
    return JOBS.search(text) is not None and ON.search(text) is not None


def detect(text: str, filename: str) -> bool:
    if filename in ACTION_FILES:
        return RUNS.search(text) is not None
    return filename.endswith(SUFFIXES) and workflow(text)


def sibling_names(read, resolve=None, listing=None, filename: str = "") -> tuple[str, ...]:
    if listing is None or filename in ACTION_FILES:
        return ()
    names = tuple(n for n in listing(".") if n.endswith(SUFFIXES) and n != filename)
    if len(names) > MAX_FILES:
        raise ValueError(f"the directory of {filename} holds more than {MAX_FILES} YAML files; audit reads at most {MAX_FILES} workflows")
    return names


def _unknown(value: str, reason: str) -> dict:
    return {"id": f"pkg:unknown/{value}@", "ecosystem": "", "name": value, "version": "", "purl": "", "unresolved": reason}


def action(value: str) -> dict:
    value = value.strip()
    if "${{" in value:
        return _unknown(value, EXPRESSION)
    if value.startswith("docker://"):
        return _unknown(value, DOCKER)
    if value.startswith("./"):
        return _unknown(value, LOCAL)
    m = USES.fullmatch(value)
    if m is None:
        return _unknown(value, f"{value!r} is not owner/repo@ref, owner/repo/path@ref, ./path or docker://image")
    name, ref = f"{m[1]}/{m[2]}", m[4]
    return {"id": package_id(ECOSYSTEM, name, ref), "ecosystem": ECOSYSTEM, "name": name, "version": ref,
            "purl": make_purl("githubactions", name, ref), "unresolved": ""}


def _steps(steps, where: str) -> list[tuple[str, object]]:
    if not isinstance(steps, list):
        return []
    return [(f"{where}[{i}]", step["uses"]) for i, step in enumerate(steps) if isinstance(step, dict) and "uses" in step]


def uses(doc) -> list[tuple[str, object]] | None:
    if not isinstance(doc, dict):
        return None
    jobs, runs = doc.get("jobs"), doc.get("runs")
    if isinstance(jobs, dict):
        out = []
        for job, body in jobs.items():
            if isinstance(body, dict) and "uses" in body:
                out.append((f"jobs.{job}", body["uses"]))
            if isinstance(body, dict):
                out += _steps(body.get("steps"), f"jobs.{job}.steps")
        return out
    if isinstance(runs, dict):
        return _steps(runs.get("steps"), "runs.steps")
    return None


def _unread(inv: Inventory, name: str, reason: str) -> None:
    pkg = _unknown(name, reason)
    inv.add(pkg["id"], pkg, f"{inv.repo}:{name}")
    inv.depends(None, pkg["id"], f"{name} could not be read")


def _file(inv: Inventory, name: str, text: str) -> None:
    try:
        found = uses(yamltext.load(text, name, aliases=True))
    except ValueError as e:
        _unread(inv, name, f"{' '.join(str(e).split())}; its uses were not read")
        return
    if found is None:
        _unread(inv, name, f"{name} has neither a jobs mapping (a workflow) nor runs.steps (a composite action)")
        return
    for where, value in found:
        pkg = action(value) if isinstance(value, str) else _unknown(f"{name}#{where}", f"{name} {where} uses is not a string")
        inv.add(pkg["id"], pkg, f"{inv.repo}:{name}#{where}")
        inv.depends(None, pkg["id"], f"{name} {where} uses {value}")


def files(text: str, filename: str, siblings: dict[str, str] | None) -> dict[str, str]:
    out = {filename: text}
    if filename in ACTION_FILES:
        return out
    for name, body in (siblings or {}).items():
        if name != filename and name.endswith(SUFFIXES) and "/" not in name and workflow(clean(body)):
            out[name] = clean(body)
    return out


def read(text: str, filename: str, repo: str, siblings: dict[str, str] | None = None) -> tuple[list[dict], list[dict]]:
    found = files(text, filename, siblings)
    inv = Inventory(repo, SOURCE, text_digest(*(f"{name}\n{body}" for name, body in sorted(found.items()))))
    for name, body in sorted(found.items()):
        _file(inv, name, body)
    return inv.result()
