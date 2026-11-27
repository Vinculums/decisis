from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

from decisis import init
from decisis.impact import code_path

HERE = Path(__file__).resolve().parent
IN_SAMPLE = ("In-sample, not a held-out result: the matching rules of `--suggest-refs` (link and GitHub URL targets, only "
             "words with a `/` in fenced code blocks, bare words only at the root, the ADR's own directory skipped) were "
             "chosen after looking at these five repositories.")
COMMAND = ("python bench/holdout/score_suggest_refs.py CLONES --out bench/holdout/suggest-refs.json "
           "--table bench/holdout/suggest-refs.md")


def words(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


def clean(path: str) -> str:
    path = path[2:] if path.startswith("./") else path
    return path.rstrip("/")


def ratio(part: int, whole: int) -> float | None:
    return round(part / whole, 3) if whole else None


def score(clone: Path, mapping: dict) -> dict:
    head = subprocess.run(["git", "-C", str(clone), "rev-parse", "HEAD"], capture_output=True, text=True, check=True).stdout.strip()
    if head != mapping["commit"]:
        raise SystemExit(f"{clone} is at {head}, the mapping pins {mapping['commit']}")
    repo = mapping["repo"]
    snap = init.build(clone, repo, suggest_refs=True)
    suggested, sentences = set(), {}
    for n in snap["nodes"]:
        props = n["props"]
        if n["kind"] != "decision" or props.get("code_ref_source") != "suggested":
            continue
        text = words((clone / props["source_file"]).read_text(encoding="utf-8"))
        for e in props["code_ref_evidence"]:
            if words(e["sentence"]) not in text:
                raise SystemExit(f"{props['source_file']}: the evidence sentence is not in the ADR: {e['sentence']!r}")
            pair = (props["source_file"], clean(code_path(e["code_ref"], repo)))
            suggested.add(pair)
            sentences[pair] = e["sentence"]
    mapped = {(adr, clean(r["path"])) for adr, rows in mapping["decisions"].items() for r in rows}
    found = suggested & mapped
    skipped = [p for p in snap["meta"]["problems"] if p["action"] == init.NOT_SUGGESTED]
    return {
        "repo": repo, "repository": mapping["repository"], "commit": mapping["commit"],
        "suggested": len(suggested), "mapped": len(mapped), "matched": len(found),
        "precision": ratio(len(found), len(suggested)), "recall": ratio(len(found), len(mapped)),
        "not_in_mapping": [{"adr": a, "path": p, "sentence": sentences[(a, p)]} for a, p in sorted(suggested - mapped)],
        "not_suggested": [{"adr": a, "path": p, "in_repository": (clone / p).exists()} for a, p in sorted(mapped - suggested)],
        "skipped_tokens": [{"adr": p["file"], "reason": p["reason"]} for p in skipped],
    }


def table(result: dict) -> str:
    rows = ["| Repository | Suggested | Mapped | Matched | Precision | Recall |", "|---|---|---|---|---|---|"]
    for r in [*result["repositories"], result["total"]]:
        shown = [("n/a" if r[k] is None else f"{r[k]:.3f}") for k in ("precision", "recall")]
        rows.append(f"| {r['repo']} | {r['suggested']} | {r['mapped']} | {r['matched']} | {shown[0]} | {shown[1]} |")
    return "\n".join(rows) + f"\n\n{IN_SAMPLE}\n\nMade with `{result['command']}`.\n"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Score `decisis init --suggest-refs` against the hand mapping of each held-out repository.")
    ap.add_argument("clones", type=Path)
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--table", type=Path)
    a = ap.parse_args(argv)
    repos = []
    for d in sorted(p for p in HERE.iterdir() if (p / "mapping.json").is_file()):
        repos.append(score(a.clones / d.name, json.loads((d / "mapping.json").read_text(encoding="utf-8"))))
    total = {k: sum(r[k] for r in repos) for k in ("suggested", "mapped", "matched")}
    total = {"repo": "total", **total, "precision": ratio(total["matched"], total["suggested"]), "recall": ratio(total["matched"], total["mapped"])}
    result = {"command": COMMAND, "tool": "decisis init --suggest-refs", "in_sample": IN_SAMPLE, "repositories": repos, "total": total}
    a.out.write_text(json.dumps(result, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    if a.table:
        a.table.write_text(table(result), encoding="utf-8")
    sys.stdout.write(table(result))
    return 0


if __name__ == "__main__":
    sys.exit(main())
