from __future__ import annotations

from test_audit import no_network
from test_checker_governs import NEWER, RULE, hand, hand_report, propose, replaced
from decisis import commit as wb


def test_a_run_that_holds_records_back_says_so_first_and_the_approve_line_names_what_it_covers(tmp_path, capsys, no_network):
    report = hand_report()
    _, base, _ = propose(tmp_path, capsys, report, hand(), "Demo")
    code, plan, out = propose(tmp_path, capsys, report, replaced(hand(), RULE), "Demo")
    held, kept = len(plan["held"]), len(plan["nodes"])
    assert code == 1 and held and kept and held + kept == len(base["nodes"])
    lines = out.splitlines()
    banner = lines.index(next(line for line in lines if line.startswith("!! ")))
    write_set = lines.index(next(line for line in lines if line.startswith("Write set for space")))
    assert banner < write_set
    assert lines[banner] == f"!! {held} of {held + kept} record(s) failed re-derivation and are held back; this run exits 1."
    assert f"!! Approving writes only the {kept} record(s) in the write set below; a held record is never written." in lines
    assert all(any(line.startswith(f"!!   {h['record']}: ") for line in lines[banner:write_set]) for h in plan["held"])
    assert lines[-1] == (f"Approve the {kept} record(s) listed, without the {held} held back: "
                         f"decisis commit <plan file> --approve {plan['digest']}")
    assert not any(line.startswith("Approve with:") for line in lines)
    assert plan["digest"] == wb.digest(plan) and NEWER


def test_a_run_with_nothing_held_prints_the_same_lines_as_before(tmp_path, capsys, no_network):
    _, plan, out = propose(tmp_path, capsys, hand_report(), hand(), "Demo")
    assert plan["held"] == [] and "!!" not in out
    assert out.rstrip().splitlines()[-1] == f"Approve with: decisis commit <plan file> --approve {plan['digest']}"


def test_a_run_that_holds_every_record_offers_nothing_to_approve():
    plan = {"space": "s", "digest": "d", "nodes": [], "edges": [], "held": [{"record": "record:a", "failed": ["why"]}]}
    text = wb.render(plan)
    assert text.splitlines()[0].startswith("!! 1 of 1 record(s)") and text.endswith("Nothing to approve: every record was held back.")
    assert "--approve" not in text
