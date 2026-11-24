from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from test_audit import no_network
from test_inventory import CACHE, FIX, PACKAGE_PROPS, VINC, osv_cache
from decisis import audit, cli, external, inventory
from decisis import checkout as co
from decisis.inventory import Siblings, directory_reader

POETRY = FIX / "poetry" / "poetry.lock"
POETRY_1 = FIX / "poetry-1.1" / "poetry.lock"
REQS = FIX / "requirements" / "requirements.txt"
FILES = {"poetry": POETRY, "requirements": REQS}
DIRECT_ONLY = ("requirements.txt lists direct dependencies only, so the packages they depend on were not seen and a vulnerable "
               "transitive dependency is not reported; audit a lockfile (poetry.lock, uv.lock) or an SBOM to cover them")


def read_path(path: Path, repo: str = "Demo") -> tuple[list[dict], list[dict]]:
    text, siblings = inventory.load(path)
    return inventory.read(text, path.name, repo, siblings)


def packages(path: Path) -> dict[str, dict]:
    return {n["id"]: n["props"] for n in read_path(path)[0] if n["kind"] == "Package"}


def evidence(path: Path) -> dict[tuple[str, str], str]:
    return {(e["source"], e["target"]): e["evidence"] for e in read_path(path)[1]}


def notes(path: Path) -> list[str]:
    return next(n for n in read_path(path)[0] if n["kind"] == "Repository")["props"].get("inventory_notes", [])


def report(path: Path) -> dict:
    text, siblings = inventory.load(path)
    return audit.run(co.load(VINC.read_text(encoding="utf-8")), text, "Demo", advisories=external.cached_advisories(osv_cache()),
                     filename=path.name, siblings=siblings)


def write(directory: Path, files: dict[str, str]) -> None:
    for name, text in files.items():
        (directory / name).parent.mkdir(parents=True, exist_ok=True)
        (directory / name).write_text(text, encoding="utf-8")


@pytest.mark.parametrize("path", [POETRY, POETRY_1, REQS], ids=["poetry", "poetry-1.1", "requirements"])
def test_python_inventories_are_told_from_content_and_name_and_return_the_common_shape(path):
    text, _ = inventory.load(path)
    fmt = "requirements" if path == REQS else "poetry"
    assert inventory.detect(text, path.name) == fmt and inventory.detect(text, "inventory.txt") == fmt
    nodes, edges = read_path(path)
    repo = [n for n in nodes if n["kind"] == "Repository"]
    assert set(repo[0]["props"]) - {"inventory_notes"} == {"source_system", "source_ref", "fetched_at", "content_hash"}
    pkgs = [n for n in nodes if n["kind"] == "Package"]
    assert pkgs and all(set(n["props"]) == PACKAGE_PROPS and n["props"]["ecosystem"] == "PyPI" for n in pkgs)
    ids = {n["id"] for n in nodes}
    assert all(e["type"] == "DEPENDS_ON" and e["evidence"] and e["source"] in ids and e["target"] in ids for e in edges)


def test_poetry_lock_2_takes_its_dev_and_docs_groups_from_pyproject():
    pkgs = packages(POETRY)
    assert {k for k, p in pkgs.items() if p["dev"]} == {"pkg:pypi/pytest@8.2.0", "pkg:pypi/pluggy@1.5.0",
                                                        "pkg:pypi/iniconfig@2.0.0", "pkg:pypi/packaging@24.0"}
    got = evidence(POETRY)
    assert got[("repo:Demo", "pkg:pypi/itsdangerous@2.2.0")] == "pyproject.toml requires ItsDangerous"
    assert got[("repo:Demo", "pkg:pypi/pytest@8.2.0")] == "pyproject.toml requires pytest (group dev)"
    assert got[("repo:Demo", "pkg:pypi/packaging@24.0")] == "pyproject.toml requires packaging (group docs)"
    assert got[("pkg:pypi/pytest@8.2.0", "pkg:pypi/pluggy@1.5.0")] == "pytest 8.2.0 requires Pluggy >=1.5,<2.0"
    assert got[("pkg:pypi/click@8.1.7", "pkg:pypi/colorama@0.4.6")] == 'click 8.1.7 requires colorama *; platform_system == "Windows"'
    assert pkgs["pkg:pypi/colorama@0.4.6"]["dev"] is False and notes(POETRY) == []


def test_poetry_lock_1_marks_dev_by_category_and_links_what_nothing_requires_to_the_repository():
    pkgs = packages(POETRY_1)
    assert {k for k, p in pkgs.items() if p["dev"]} == {"pkg:pypi/pytest@8.2.0", "pkg:pypi/pluggy@1.5.0",
                                                        "pkg:pypi/iniconfig@2.0.0", "pkg:pypi/packaging@24.0"}
    got = evidence(POETRY_1)
    assert got[("repo:Demo", "pkg:pypi/certifi@2023.7.22")] == "listed in poetry.lock with no dependency on it"
    assert ("pkg:pypi/pytest@8.2.0", "pkg:pypi/pluggy@1.5.0") in got and ("repo:Demo", "pkg:pypi/pluggy@1.5.0") not in got
    assert notes(POETRY_1) == []


def with_groups(text: str, groups: dict[str, list[str]]) -> str:
    def add(m: re.Match) -> str:
        return f'{m[0]}groups = {json.dumps(groups[m[1]])}\n'
    text = re.sub(r'name = "([a-z]+)"\nversion = "[^"]+"\n', add, text)
    return text.replace('lock-version = "2.0"', 'lock-version = "2.1"')


def test_poetry_lock_2_1_marks_every_group_but_main_as_dev(tmp_path):
    dev = {"pytest", "pluggy", "iniconfig"}
    groups = {n: ["docs"] if n == "packaging" else ["dev"] if n in dev else ["main", "dev"] if n == "colorama" else ["main"]
              for n in ("certifi", "click", "colorama", "idna", "iniconfig", "itsdangerous", "packaging", "pluggy", "pytest")}
    (tmp_path / "poetry.lock").write_text(with_groups(POETRY.read_text(encoding="utf-8"), groups), encoding="utf-8")
    pkgs = packages(tmp_path / "poetry.lock")
    assert {p["name"] for p in pkgs.values() if p["dev"]} == dev | {"packaging"}
    assert notes(tmp_path / "poetry.lock") == []


def test_poetry_lock_2_without_pyproject_says_the_dev_split_is_unknown(tmp_path, capsys, no_network):
    (tmp_path / "poetry.lock").write_text(POETRY.read_text(encoding="utf-8"), encoding="utf-8")
    assert not any(p["dev"] for p in packages(tmp_path / "poetry.lock").values())
    out = tmp_path / "report.json"
    assert cli.main(["audit", str(VINC), str(tmp_path / "poetry.lock"), "--repo", "Demo", "--osv-cache", str(CACHE),
                     "--out", str(out)]) == 0
    note = ("poetry.lock (lock-version 2.0) does not say which packages are development dependencies and there is no "
            "pyproject.toml next to it, so the dev split is unknown and every package counts as shipped")
    assert json.loads(out.read_text(encoding="utf-8"))["inventory_notes"] == [note]
    assert json.loads(capsys.readouterr().out)["inventory_notes"] == [note]


def test_a_poetry_lock_version_audit_does_not_know_is_refused():
    text = POETRY.read_text(encoding="utf-8").replace('lock-version = "2.0"', 'lock-version = "3.0"')
    with pytest.raises(ValueError, match="lock-version 3.0 is not one audit reads"):
        inventory.read(text, "poetry.lock", "Demo")


def test_a_poetry_package_from_a_path_or_git_source_is_unresolved():
    text = POETRY.read_text(encoding="utf-8").replace(
        'name = "idna"\nversion = "3.6"\n', 'name = "idna"\nversion = "3.6"\n[package.source]\ntype = "git"\n'
        'url = "https://example.com/idna.git"\nreference = "main"\nresolved_reference = "abc123"\n\n[[package]]\nname = "idna-extra"\n'
        'version = "0.1"\n', 1)
    pkgs = {n["id"]: n["props"] for n in inventory.read(text, "poetry.lock", "Demo")[0] if n["kind"] == "Package"}
    assert pkgs["pkg:pypi/idna@3.6"]["unresolved"] == "poetry.lock installs it from a git source (https://example.com/idna.git), not from PyPI"


def test_requirements_pins_become_packages_and_every_other_line_is_unresolved_with_its_reason():
    pkgs = packages(REQS)
    pinned = {k for k, p in pkgs.items() if not p["unresolved"]}
    assert pinned == {"pkg:pypi/certifi@2023.7.22", "pkg:pypi/idna@3.6", "pkg:pypi/pluggy@1.5.0", "pkg:pypi/itsdangerous@2.2.0",
                      "pkg:pypi/packaging@24.0"}
    assert pkgs["pkg:pypi/click@"]["unresolved"] == "requirements.txt line 10 gives >=8.0,<9, not a pinned version; audit does not guess one"
    assert pkgs["pkg:pypi/pytest@"]["unresolved"] == "requirements.txt line 11 gives no version, not a pinned version; audit does not guess one"
    assert pkgs["pkg:pypi/click@"]["version"] == "" and not any(p["dev"] for p in pkgs.values())
    got = evidence(REQS)
    assert got[("repo:Demo", "pkg:pypi/certifi@2023.7.22")] == "requirements.txt line 4: certifi==2023.7.22"
    assert got[("repo:Demo", "pkg:pypi/idna@3.6")] == 'requirements.txt line 7: idna==3.6 ; python_version >= "3.8"'
    assert got[("repo:Demo", "pkg:pypi/pluggy@1.5.0")] == "requirements.txt line 8: pluggy[dev]==1.5.0"
    assert got[("repo:Demo", "pkg:pypi/packaging@24.0")] == "base.txt line 3: packaging==24.0"
    assert all(src == "repo:Demo" for src, _ in got)


def test_an_include_loop_reads_each_file_once():
    nodes, _ = read_path(REQS)
    assert sum(1 for n in nodes if n["id"] == "pkg:pypi/packaging@24.0") == 1
    assert notes(REQS) == [DIRECT_ONLY]


def test_the_report_says_a_requirements_file_shows_direct_dependencies_only():
    rep = report(REQS)
    assert rep["inventory_notes"] == [DIRECT_ONLY]
    assert rep["unresolved_packages"] == [
        {"package": "pkg:pypi/click@", "reason": "requirements.txt line 10 gives >=8.0,<9, not a pinned version; audit does not guess one"},
        {"package": "pkg:pypi/pytest@", "reason": "requirements.txt line 11 gives no version, not a pinned version; audit does not guess one"}]
    assert report(POETRY)["inventory_notes"] == []


@pytest.mark.parametrize("path,package,advisory,dev", [
    (POETRY, "pkg:pypi/certifi@2023.7.22", "adv:GHSA-6q48-6c7w-9gw2", False),
    (POETRY, "pkg:pypi/pytest@8.2.0", "adv:GHSA-6w46-j5rx-g56g", True),
    (POETRY_1, "pkg:pypi/pytest@8.2.0", "adv:GHSA-6w46-j5rx-g56g", True),
    (REQS, "pkg:pypi/certifi@2023.7.22", "adv:GHSA-6q48-6c7w-9gw2", False),
    (REQS, "pkg:pypi/idna@3.6", "adv:GHSA-jjg7-2v4v-x38h", False),
], ids=["poetry-certifi", "poetry-pytest", "poetry-1.1-pytest", "requirements-certifi", "requirements-idna"])
def test_each_python_inventory_has_an_affected_finding_from_the_cache(path, package, advisory, dev):
    hit = [f for f in report(path)["findings"] if f["package"] == package and f["advisory"] == advisory]
    assert len(hit) == 1 and hit[0]["status"] == "affected" and hit[0]["dev_only"] is dev
    assert hit[0]["path"][0] == "repo:Demo" and hit[0]["path"][-2:] == [package, advisory]


@pytest.mark.parametrize("fmt", sorted(FILES))
def test_the_cli_audits_and_propose_re_derives_python_inventories_offline(fmt, tmp_path, capsys, no_network):
    assert cli.main(["audit", str(VINC), str(FILES[fmt]), "--repo", "Demo", "--osv-cache", str(CACHE)]) == 0
    rep = json.loads(capsys.readouterr().out)
    assert rep["summary"]["affected"] > 0 and rep["meta"]["packages"] == len(packages(FILES[fmt]))
    (tmp_path / "report.json").write_text(json.dumps(report(FILES[fmt])), encoding="utf-8")
    assert cli.main(["propose", str(tmp_path / "report.json"), str(VINC), str(FILES[fmt]), "--repo", "Demo", "--space", "demo-space",
                     "--osv-cache", str(CACHE), "--out", str(tmp_path / "plan.json")]) == 0
    plan = json.loads((tmp_path / "plan.json").read_text(encoding="utf-8"))
    assert plan["nodes"] and plan["held"] == [] and "; 0 failed." in capsys.readouterr().out


def test_requirements_names_are_normalized_like_pep_503():
    text = "Foo.Bar_baz==1.0\nfoo-bar-BAZ>=1\nZope.Interface==6.0\n"
    pkgs = {n["id"] for n in inventory.read(text, "requirements.txt", "Demo")[0] if n["kind"] == "Package"}
    assert pkgs == {"pkg:pypi/foo-bar-baz@1.0", "pkg:pypi/zope-interface@6.0"}


def test_requirements_includes_are_followed_only_inside_the_repository(tmp_path):
    repo = tmp_path / "repo"
    write(repo, {"requirements.txt": "-r sub/dev.txt\n-r ../outside.txt\n-r /etc/hosts\n-r link.txt\n-r missing.txt\n"
                                     "-r https://example.com/r.txt\ncertifi==2023.7.22\n",
                 "sub/dev.txt": "-r ../base.txt\npytest==8.2.0\n", "base.txt": "idna==3.6\n"})
    write(tmp_path, {"outside.txt": "click==8.1.7\n"})
    (repo / "link.txt").symlink_to(tmp_path / "outside.txt")
    pkgs = packages(repo / "requirements.txt")
    assert set(pkgs) == {"pkg:pypi/certifi@2023.7.22", "pkg:pypi/pytest@8.2.0", "pkg:pypi/idna@3.6"}
    got = notes(repo / "requirements.txt")
    assert got[0] == f"requirements.txt line 2 includes ../outside.txt, which was not followed: '../outside.txt' leads outside {repo}"
    assert got[1] == ("requirements.txt line 3 includes /etc/hosts, which was not followed: audit reads includes only by a relative "
                      "path inside the repository")
    assert got[2] == f"requirements.txt line 4 includes link.txt, which was not followed: 'link.txt' leads outside {repo}"
    assert got[3] == "requirements.txt line 5 includes missing.txt, which does not exist"
    assert got[4].startswith("requirements.txt line 6 includes https://example.com/r.txt, which was not followed")
    assert got[5:] == [DIRECT_ONLY]
    assert evidence(repo / "requirements.txt")[("repo:Demo", "pkg:pypi/idna@3.6")] == "base.txt line 1: idna==3.6"


def nested_repo(tmp_path: Path, git: str = "dir") -> Path:
    repo = tmp_path / "repo"
    write(repo, {"requirements/dev.txt": "-r ../requirements.txt\npytest==8.2.0\n", "requirements.txt": "certifi==2023.7.22\n"})
    if git == "dir":
        (repo / ".git").mkdir()
    elif git == "file":
        (repo / ".git").write_text("gitdir: /nowhere\n", encoding="utf-8")
    write(tmp_path, {"outside.txt": "click==8.1.7\n"})
    return repo


@pytest.mark.parametrize("git", ["dir", "file"])
def test_an_include_above_the_inventory_is_followed_up_to_the_repository_holding_git(tmp_path, git):
    repo = nested_repo(tmp_path, git)
    assert inventory.siblings.repository_root(repo / "requirements") == repo.resolve()
    pkgs = packages(repo / "requirements" / "dev.txt")
    assert set(pkgs) == {"pkg:pypi/pytest@8.2.0", "pkg:pypi/certifi@2023.7.22"}
    assert evidence(repo / "requirements" / "dev.txt")[("repo:Demo", "pkg:pypi/certifi@2023.7.22")] == \
        "../requirements.txt line 1: certifi==2023.7.22"


def test_without_git_the_boundary_is_the_inventory_directory_and_root_sets_it(tmp_path, capsys, no_network):
    repo = nested_repo(tmp_path, git="none")
    dev = repo / "requirements" / "dev.txt"
    assert set(packages(dev)) == {"pkg:pypi/pytest@8.2.0"}
    assert notes(dev)[0].startswith("dev.txt line 1 includes ../requirements.txt, which was not followed")
    text, siblings = inventory.load(dev, root=repo)
    assert "pkg:pypi/certifi@2023.7.22" in {n["id"] for n in inventory.read(text, "dev.txt", "Demo", siblings)[0]}
    out = tmp_path / "report.json"
    assert cli.main(["audit", str(VINC), str(dev), "--repo", "Demo", "--osv-cache", str(CACHE), "--root", str(repo),
                     "--out", str(out)]) == 0
    assert json.loads(out.read_text(encoding="utf-8"))["meta"]["packages"] == 2
    with pytest.raises(ValueError, match="is not under the root"):
        inventory.load(dev, root=tmp_path / "elsewhere")


def test_a_directory_symlink_back_to_itself_ends_the_include_loop(tmp_path):
    repo = tmp_path / "repo"
    write(repo, {"requirements.txt": "-r d/requirements.txt\n-r d/d/d/base.txt\ncertifi==2023.7.22\n", "base.txt": "idna==3.6\n"})
    (repo / "d").symlink_to(".")
    assert set(packages(repo / "requirements.txt")) == {"pkg:pypi/certifi@2023.7.22", "pkg:pypi/idna@3.6"}
    assert notes(repo / "requirements.txt") == [DIRECT_ONLY]


def test_a_long_include_chain_stops_with_a_note_instead_of_crashing(tmp_path, capsys, no_network):
    chain = {f"r{i}.txt": f"-r r{i + 1}.txt\npkg{i}==1.0\n" for i in range(400)}
    write(tmp_path, {**chain, "requirements.txt": "-r r0.txt\ncertifi==2023.7.22\n"})
    pkgs = packages(tmp_path / "requirements.txt")
    assert len(pkgs) == 1 + 64 and "pkg:pypi/pkg63@1.0" in pkgs and "pkg:pypi/pkg64@1.0" not in pkgs
    assert notes(tmp_path / "requirements.txt")[0] == ("r63.txt line 1 includes r64.txt, which was not followed: "
                                                       "includes are followed 64 levels deep")


def test_a_byte_order_mark_is_dropped_from_the_inventory_and_its_includes(tmp_path, capsys, no_network):
    bom = "\ufeff"
    write(tmp_path, {"requirements.txt": bom + "certifi==2023.7.22\n-r base.txt\n", "base.txt": bom + "idna==3.6\n"})
    assert set(packages(tmp_path / "requirements.txt")) == {"pkg:pypi/certifi@2023.7.22", "pkg:pypi/idna@3.6"}
    text = (tmp_path / "requirements.txt").read_text(encoding="utf-8")
    assert {n["id"] for n in inventory.read(text, "requirements.txt", "Demo", {"base.txt": bom + "idna==3.6\n"})[0]} >= \
        {"pkg:pypi/certifi@2023.7.22", "pkg:pypi/idna@3.6"}
    plain = report(REQS)["summary"]
    for name in ("requirements.txt", "base.txt"):
        write(tmp_path / "marked", {name: bom + (REQS.parent / name).read_text(encoding="utf-8")})
    marked = report(tmp_path / "marked" / "requirements.txt")["summary"]
    assert marked == plain and plain["affected"] > 0
    write(tmp_path / "poetry", {"poetry.lock": bom + POETRY.read_text(encoding="utf-8"),
                                "pyproject.toml": bom + (POETRY.parent / "pyproject.toml").read_text(encoding="utf-8")})
    assert set(packages(tmp_path / "poetry" / "poetry.lock")) == set(packages(POETRY))
    assert {k for k, p in packages(tmp_path / "poetry" / "poetry.lock").items() if p["dev"]} == \
        {k for k, p in packages(POETRY).items() if p["dev"]}


def test_the_sibling_reader_refuses_parent_absolute_and_escaping_paths(tmp_path):
    write(tmp_path, {"in/a.txt": "x", "out.txt": "y"})
    (tmp_path / "in" / "b.txt").symlink_to(tmp_path / "out.txt")
    read = directory_reader(tmp_path / "in")
    assert read("a.txt") == "x" and read("nothing.txt") is None
    for bad in ("../out.txt", "/etc/hosts", "C:\\x.txt", "b.txt", "sub\\..\\..\\out.txt"):
        with pytest.raises(ValueError):
            read(bad)


def test_a_caller_supplied_reader_serves_includes_and_a_plain_dict_does_not(tmp_path):
    files = {"base.txt": "idna==3.6\n"}
    asked = []

    def reader(name: str) -> str | None:
        asked.append(name)
        return files.get(name)

    text = "-r base.txt\ncertifi==2023.7.22\n"
    with_reader = inventory.read(text, "requirements.txt", "Demo", Siblings(reader=reader))[0]
    assert "pkg:pypi/idna@3.6" in {n["id"] for n in with_reader} and asked == ["base.txt"]
    nodes = inventory.read(text, "requirements.txt", "Demo", {})[0]
    repo = next(n for n in nodes if n["kind"] == "Repository")
    assert repo["props"]["inventory_notes"][0] == ("requirements.txt line 1 includes base.txt, which was not followed: "
                                                   "the caller gave no way to read other files")


def test_requirements_direct_references_local_projects_and_constraints():
    text = ("-e .\n-e git+https://github.com/example/foo.git@v1#egg=Foo_Bar\nbaz @ https://example.com/baz-1.0.tar.gz\n"
            "./wheels/qux-1.0-py3-none-any.whl\n-c constraints.txt\nwild==1.*\nexact===1.0\nboth==1.0,!=1.1\n"
            "certifi==2023.7.22 --hash=sha256:00 ; python_version >= '3.8'\n")
    nodes, _ = inventory.read(text, "requirements.txt", "Demo")
    pkgs = {n["id"]: n["props"] for n in nodes if n["kind"] == "Package"}
    assert pkgs["pkg:pypi/foo-bar@"]["unresolved"] == ("requirements.txt line 2 installs git+https://github.com/example/foo.git@v1#egg=Foo_Bar "
                                                      "directly, not a PyPI release")
    assert pkgs["pkg:pypi/baz@"]["unresolved"] == "requirements.txt line 3 installs baz from a URL, not a PyPI release"
    assert pkgs["pkg:pypi/wild@"]["unresolved"] and pkgs["pkg:pypi/exact@"]["unresolved"]
    assert not pkgs["pkg:pypi/both@1.0"]["unresolved"] and not pkgs["pkg:pypi/certifi@2023.7.22"]["unresolved"]
    repo = next(n for n in nodes if n["kind"] == "Repository")["props"]["inventory_notes"]
    assert repo[0] == "requirements.txt line 1 installs the local project .; its own dependencies are not listed here and were not seen"
    assert "requirements.txt line 4 installs the local project ./wheels/qux-1.0-py3-none-any.whl" in repo[1]
    assert repo[2] == "requirements.txt line 5 names the constraints file constraints.txt; constraints files are not read"


def test_a_requirements_file_with_nothing_pinned_is_refused(tmp_path, no_network):
    (tmp_path / "requirements.txt").write_text("click>=8\npytest\n", encoding="utf-8")
    with pytest.raises(SystemExit):
        cli.main(["audit", str(VINC), str(tmp_path / "requirements.txt"), "--repo", "Demo", "--osv-cache", str(CACHE)])


@pytest.mark.parametrize("text", ["hello world\n", "just some notes\n- item\n", "name = \"x\"\n"])
def test_a_text_file_that_is_not_a_requirements_file_is_not_read_as_one(text):
    with pytest.raises(ValueError, match="cannot tell what notes.txt is"):
        inventory.detect(text, "notes.txt")
