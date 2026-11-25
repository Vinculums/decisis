from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from test_audit import no_network
from decisis import cli, patch

ROOT = Path(__file__).resolve().parents[1]
AUDIT = ROOT / "fixtures" / "audit"
ADR = "---\nstatus: accepted\nrule: {\"advisory_severity_at_least\": \"HIGH\"}\n---\n# No high advisories in café code\n\nThe shop ships no HIGH advisory.\n"


def snapshot_with_an_odd_name(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    adr = repo / "docs" / "adr"
    adr.mkdir(parents=True)
    try:
        (adr / "0001-caf\udce9.md").write_text(ADR, encoding="utf-8")
    except (OSError, UnicodeEncodeError):
        pytest.skip("the file system refuses a name that is not UTF-8")
    out = tmp_path / "snapshot.json"
    assert cli.main(["init", "--repo-dir", str(repo), "--repo", "Demo", "--out", str(out)]) == 0
    assert "\\udce9" in out.read_text(encoding="utf-8")
    return out


def test_audit_and_propose_write_their_json_files_when_the_snapshot_holds_a_name_that_is_not_utf8(tmp_path, capsys, no_network):
    snap = snapshot_with_an_odd_name(tmp_path)
    report, plan = tmp_path / "report.json", tmp_path / "plan.json"
    common = [str(AUDIT / "demo-lockfile.json"), "--repo", "Demo", "--osv-cache", str(AUDIT / "osv-cache.json")]
    capsys.readouterr()
    assert cli.main(["audit", str(snap), *common, "--out", str(report)]) == 0
    text = report.read_text(encoding="utf-8")
    assert json.loads(text)["violations"] > 0 and "\\udce9" in text
    capsys.readouterr()
    cli.main(["propose", str(report), str(snap), *common, "--space", "demo-space", "--out", str(plan)])
    assert json.loads(plan.read_text(encoding="utf-8"))["nodes"]


@pytest.mark.parametrize("command", [["audit", "{snap}", str(AUDIT / "demo-lockfile.json"), "--repo", "Demo", "--osv-cache", str(AUDIT / "osv-cache.json")],
                                     ["impact", "{snap}", "src/"],
                                     ["query", "{snap}", "MATCH (d:Decision) RETURN d.source_file AS f"]])
def test_json_printed_to_stdout_escapes_a_name_that_is_not_utf8(tmp_path, capsys, no_network, command):
    snap = snapshot_with_an_odd_name(tmp_path)
    capsys.readouterr()
    cli.main([part.format(snap=snap) for part in command])
    out = capsys.readouterr().out
    out.encode("utf-8")
    json.loads(out)


def test_the_patch_header_says_where_to_apply_it():
    text = patch.header(patch.Patch(adrs=[], refs=0, skipped=[], left_out=[], text=""))
    assert "relative to the --repo-dir" in text and "git apply --directory=" in text and "from the repository root" not in text
