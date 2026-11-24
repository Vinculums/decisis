from __future__ import annotations

import json

from .shape import development, digest, json_object, license_ids, make_purl, now, package_id

FORMAT = "npm"
SIBLINGS: tuple[str, ...] = ()


def detect(text: str, filename: str) -> bool:
    obj = json_object(text)
    return obj is not None and "lockfileVersion" in obj


def _resolve(packages: dict, from_path: str, dep: str) -> str | None:
    base = from_path
    while True:
        cand = f"{base}/node_modules/{dep}" if base else f"node_modules/{dep}"
        if cand in packages:
            return cand
        if not base:
            return None
        cut = base.rfind("/node_modules/")
        base = base[:cut] if cut >= 0 else ""


def _license(meta: dict) -> str:
    value = meta.get("license")
    return value if isinstance(value, str) else ""


def _props(name: str, meta: dict, repo: str, path: str, fetched: str) -> dict:
    lic = _license(meta)
    return {"ecosystem": "npm", "name": name, "version": meta["version"], "dev": bool(meta.get("dev")),
            "licenses": license_ids(lic), "license_expression": lic, "purl": make_purl("npm", name, meta["version"]),
            "unresolved": "", "source_system": "npm-lockfile", "source_ref": f"{repo}:{path}", "fetched_at": fetched}


def parse_npm_lock(text: str, repo: str, include_dev: bool = True) -> tuple[list[dict], list[dict]]:
    lock = json.loads(text)
    pkgs = lock.get("packages")
    if not isinstance(pkgs, dict) or lock.get("lockfileVersion", 0) < 2:
        raise ValueError("needs an npm lockfile v2 or v3 with a packages map")
    fetched = now()
    repo_id = f"repo:{repo}"
    nodes = {repo_id: {"id": repo_id, "kind": "Repository", "title": repo,
                       "props": {"source_system": "npm-lockfile", "source_ref": repo, "fetched_at": fetched, "content_hash": digest(lock)}}}
    ids: dict[str, str] = {}
    marks: dict[str, list[bool]] = {}
    for path, meta in pkgs.items():
        if not path or meta.get("link") or not meta.get("version"):
            continue
        if meta.get("dev") and not include_dev:
            continue
        name = meta.get("name") or path.rsplit("node_modules/", 1)[-1]
        pid = package_id("npm", name, meta["version"])
        ids[path] = pid
        marks.setdefault(pid, []).append(bool(meta.get("dev")))
        nodes.setdefault(pid, {"id": pid, "kind": "Package", "title": f"{name}@{meta['version']}",
                               "props": _props(name, meta, repo, path, fetched)})
    root = pkgs.get("", {})
    direct = {dep: f"{dep}: {spec}" for dep, spec in (root.get("dependencies") or {}).items()}
    if include_dev:
        direct.update({dep: f"{dep}: {spec}" for dep, spec in (root.get("devDependencies") or {}).items()})
    shipped_direct = set(root.get("dependencies") or {})
    for field, kind in (("peerDependencies", "peer"), ("optionalDependencies", "optional")):
        for dep, spec in (root.get(field) or {}).items():
            if dep not in shipped_direct:
                direct[dep] = f"{dep}: {spec} ({kind})"
        shipped_direct |= set(root.get(field) or {})
    edges, links = [], {}

    def link(src: str, dst: str, why: str, dev: bool) -> None:
        if (src, dst) not in links:
            edges.append({"source": src, "target": dst, "type": "DEPENDS_ON", "evidence": why})
        links[(src, dst)] = links.get((src, dst), True) and dev

    for dep in sorted(direct):
        target = _resolve(pkgs, "", dep)
        if target in ids:
            link(repo_id, ids[target], direct[dep], dep not in shipped_direct or bool(pkgs[target].get("dev")))
    for path, pid in sorted(ids.items()):
        meta = pkgs[path]
        required = {**(meta.get("dependencies") or {}), **(meta.get("optionalDependencies") or {})}
        for dep in sorted({*required, *(meta.get("peerDependencies") or {})}):
            target = _resolve(pkgs, path, dep)
            if target in ids:
                link(pid, ids[target], f"{path} requires {dep}" + ("" if dep in required else " (peer)"), bool(pkgs[target].get("dev")))
    workspaces = sorted(path for path in ids if "node_modules/" not in path)
    dev = development([repo_id, *(ids[w] for w in workspaces)], [repo_id, *(ids[w] for w in workspaces if not pkgs[w].get("dev"))],
                      links, sorted(marks), lambda pid: all(marks[pid]))
    for pid, is_dev in dev.items():
        nodes[pid]["props"]["dev"] = is_dev
    return list(nodes.values()), edges


def read(text: str, filename: str, repo: str, siblings: dict[str, str] | None = None) -> tuple[list[dict], list[dict]]:
    return parse_npm_lock(text, repo)
