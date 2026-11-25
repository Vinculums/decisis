from __future__ import annotations

import hashlib
import json
import os
import re
import unicodedata
from pathlib import Path

import pytest

from test_adr_subfolders import adr, both, write
from decisis import cli, init, rules

ADR = "decision:korapp-docs-adr-"
PM = "record:korapp-docs-postmortems-"


def digest(rel: str) -> str:
    return hashlib.sha256(rel.encode("utf-8")).hexdigest()[:8]


def build(root: Path) -> dict:
    return init.build(root, "KorApp")


def ids_by_file(snap: dict) -> dict[str, str]:
    return {n["props"]["source_file"]: n["id"] for n in snap["nodes"] if n["kind"] in ("decision", "record")}


def skipped(snap: dict) -> list[dict]:
    return [p for p in snap["meta"]["problems"] if p["action"] == init.SKIPPED]


def test_a_korean_name_keeps_its_ascii_part_and_gains_a_hash_of_the_whole_path(tmp_path):
    root = write(tmp_path / "repo", {"docs/adr/0001-결제-규칙.md": adr("결제 규칙")})
    snap = build(root)
    [node] = snap["nodes"]
    assert node["id"] == f"{ADR}0001-{digest('docs/adr/0001-결제-규칙.md')}"
    assert node["title"] == "결제 규칙"
    assert node["props"]["source_file"] == "docs/adr/0001-결제-규칙.md"


def test_two_adrs_whose_names_are_all_korean_are_both_kept_with_distinct_ids(tmp_path):
    root = write(tmp_path / "repo", {"docs/adr/결제.md": adr("결제"), "docs/adr/인증.md": adr("인증")})
    snap = build(root)
    assert ids_by_file(snap) == {"docs/adr/결제.md": f"{ADR}{digest('docs/adr/결제.md')}",
                                 "docs/adr/인증.md": f"{ADR}{digest('docs/adr/인증.md')}"}
    assert len({n["id"] for n in snap["nodes"]}) == 2
    assert {n["title"] for n in snap["nodes"]} == {"결제", "인증"}
    assert skipped(snap) == []


def test_japanese_and_chinese_names_get_distinct_ids_and_titles_keep_their_text(tmp_path):
    root = write(tmp_path / "repo", {"docs/adr/決済ルール.md": adr("決済ルール"), "docs/adr/支付规则.md": adr("支付规则"),
                                      "docs/adr/0003-認証-方針.md": adr("認証方針"), "docs/adr/0003-认证-方针.md": adr("认证方针")})
    snap = build(root)
    found = ids_by_file(snap)
    assert len(set(found.values())) == 4 and skipped(snap) == []
    assert found["docs/adr/0003-認証-方針.md"] == f"{ADR}0003-{digest('docs/adr/0003-認証-方針.md')}"
    assert found["docs/adr/0003-认证-方针.md"] == f"{ADR}0003-{digest('docs/adr/0003-认证-方针.md')}"
    assert {n["title"] for n in snap["nodes"]} == {"決済ルール", "支付规则", "認証方針", "认证方针"}


def test_an_id_stays_ascii_and_is_a_valid_waiver_and_url_id(tmp_path):
    root = write(tmp_path / "repo", {"docs/adr/0001-결제-규칙.md": adr("a"), "docs/adr/決済.md": adr("b"), "docs/adr/café.md": adr("c"),
                                      "docs/postmortems/2026-장애.md": "# 장애\n"})
    for node in build(root)["nodes"]:
        assert node["id"].isascii() and re.fullmatch(r"[a-z0-9:-]+", node["id"])
        assert rules._ID.match(node["id"])


def test_a_name_whose_non_ascii_character_is_only_accented_still_gets_a_hash(tmp_path):
    root = write(tmp_path / "repo", {"docs/adr/0002-café.md": adr("a"), "docs/adr/0002-caf.md": adr("b")})
    found = ids_by_file(build(root))
    assert found["docs/adr/0002-caf.md"] == f"{ADR}0002-caf"
    assert found["docs/adr/0002-café.md"] == f"{ADR}0002-caf-{digest('docs/adr/0002-café.md')}"


def test_an_ascii_name_keeps_the_id_it_always_had(tmp_path):
    root = write(tmp_path / "repo", {
        "docs/adr/0004-retry-payments.md": adr("a"), "docs/adr/api_v2.md": adr("b"), "docs/adr/Mixed Case.v2.md": adr("c"),
        "docs/adr/0005-$weird!.md": adr("d"), "docs/postmortems/2026-10-outage.md": "# Outage\n"})
    assert ids_by_file(build(root)) == {
        "docs/adr/0004-retry-payments.md": f"{ADR}0004-retry-payments",
        "docs/adr/api_v2.md": f"{ADR}api-v2",
        "docs/adr/Mixed Case.v2.md": f"{ADR}mixed-case-v2",
        "docs/adr/0005-$weird!.md": f"{ADR}0005-weird",
        "docs/postmortems/2026-10-outage.md": f"{PM}2026-10-outage"}


def test_postmortem_records_follow_the_same_rule(tmp_path):
    root = write(tmp_path / "repo", {"docs/postmortems/2026-결제-장애.md": "# 결제 장애\n", "docs/postmortems/2026-인증-장애.md": "# 인증 장애\n",
                                      "docs/postmortems/2026-10-outage.md": "# Outage\n"})
    snap = build(root)
    assert ids_by_file(snap) == {
        "docs/postmortems/2026-결제-장애.md": f"{PM}2026-{digest('docs/postmortems/2026-결제-장애.md')}",
        "docs/postmortems/2026-인증-장애.md": f"{PM}2026-{digest('docs/postmortems/2026-인증-장애.md')}",
        "docs/postmortems/2026-10-outage.md": f"{PM}2026-10-outage"}
    assert {n["title"] for n in snap["nodes"]} == {"결제 장애", "인증 장애", "Outage"}
    assert skipped(snap) == []


def test_edges_between_korean_files_use_the_hashed_ids(tmp_path):
    root = write(tmp_path / "repo", {
        "docs/adr/결제.md": adr("결제"),
        "docs/adr/인증.md": adr("인증", 'supersedes: ["결제.md"]'),
        "docs/adr/0003-정책.md": adr("정책", "superseded_by: [\"인증\"]"),
        "docs/postmortems/2026-장애.md": "# 장애\n\nSee [the ADR](../adr/결제.md).\n"})
    snap = build(root)
    found = ids_by_file(snap)
    pay, auth, policy, outage = (found[f] for f in ("docs/adr/결제.md", "docs/adr/인증.md", "docs/adr/0003-정책.md", "docs/postmortems/2026-장애.md"))
    edges = {(e["source"], e["type"], e["target"]) for e in snap["edges"]}
    assert edges == {(auth, "SUPERSEDES", pay), (auth, "SUPERSEDES", policy), (outage, "ABOUT", pay)}


def test_a_codeowners_concept_with_non_ascii_owners_stays_distinct_and_ascii(tmp_path):
    root = write(tmp_path / "repo", {".github/CODEOWNERS": "/docs/ @팀가\n/src/ @팀나\n", "docs/a.md": "x\n", "src/b.py": "x = 1\n"})
    ids = [n["id"] for n in build(root)["nodes"] if n["kind"] == "concept"]
    assert len(ids) == len(set(ids)) == 2
    assert all(i.isascii() and i.startswith("concept:korapp-codeowners-") for i in ids)


def test_the_same_name_in_two_unicode_forms_gets_one_id(tmp_path):
    name = "결제-규칙"
    ids = []
    for form in ("NFC", "NFD"):
        root = write(tmp_path / form, {f"docs/adr/0001-{unicodedata.normalize(form, name)}.md": adr("결제 규칙")})
        [node] = build(root)["nodes"]
        ids.append(node["id"])
    assert ids[0] == ids[1] == f"{ADR}0001-{digest(unicodedata.normalize('NFC', 'docs/adr/0001-' + name + '.md'))}"


def test_an_accented_latin_name_in_two_unicode_forms_gets_one_id(tmp_path):
    ids = []
    for form in ("NFC", "NFD"):
        root = write(tmp_path / form, {f"docs/adr/0001-{unicodedata.normalize(form, 'café')}.md": adr("café")})
        [node] = build(root)["nodes"]
        ids.append(node["id"])
    assert ids[0] == ids[1] == f"{ADR}0001-caf-{digest(unicodedata.normalize('NFC', 'docs/adr/0001-café.md'))}"


def test_a_directory_named_with_non_ascii_letters_gets_a_hash_too(tmp_path):
    root = write(tmp_path / "repo", {"결정/0001-a.md": adr("a"), "결정/0002-b.md": adr("b")})
    snap = init.build(root, "KorApp", adr_dir="결정")
    found = ids_by_file(snap)
    assert found["결정/0001-a.md"] == f"decision:korapp-0001-a-{digest('결정/0001-a.md')}"
    assert found["결정/0002-b.md"] == f"decision:korapp-0002-b-{digest('결정/0002-b.md')}"


def test_a_file_name_that_is_not_utf8_gets_a_hash_instead_of_failing(tmp_path):
    folder = tmp_path / "repo" / "docs" / "adr"
    folder.mkdir(parents=True)
    try:
        with open(os.fsencode(folder) + b"/0001-\xff.md", "wb") as f:
            f.write(adr("a").encode("utf-8"))
        with open(os.fsencode(folder) + b"/0001-\xfe.md", "wb") as f:
            f.write(adr("b").encode("utf-8"))
    except OSError:
        pytest.skip("this file system does not take a file name that is not UTF-8")
    found = ids_by_file(build(tmp_path / "repo"))
    assert len(found) == 2 and len(set(found.values())) == 2
    assert all(i.isascii() and i.startswith(f"{ADR}0001-") for i in found.values())


def test_the_base_commit_reader_builds_the_same_ids_as_the_working_tree(tmp_path):
    root = write(tmp_path / "repo", {
        "docs/adr/결제.md": adr("결제"), "docs/adr/인증.md": adr("인증", 'supersedes: ["결제.md"]'),
        "docs/adr/0003-retry.md": adr("retry"), "docs/postmortems/2026-장애.md": "# 장애\n"})
    local, base = both(root)
    assert local == base
    assert len({i for i, _ in local["decisions"]}) == 3
    assert len(local["edges"]) == 1


def test_the_init_command_keeps_both_korean_adrs(tmp_path, capsys):
    root = write(tmp_path / "repo", {"docs/adr/0001-결제-규칙.md": adr("결제 규칙"), "docs/adr/결제.md": adr("결제"), "docs/adr/인증.md": adr("인증")})
    out = tmp_path / "snapshot.json"
    capsys.readouterr()
    assert cli.main(["init", "--repo-dir", str(root), "--repo", "KorApp", "--out", str(out)]) == 0
    assert json.loads(capsys.readouterr().out)["nodes"] == 3
    assert not any("already taken" in p["reason"] for p in json.loads(out.read_text(encoding="utf-8"))["meta"]["problems"])
