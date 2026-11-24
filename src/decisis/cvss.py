from __future__ import annotations

import math

WEIGHTS = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62},
    "S": {"U": "U", "C": "C"},
    "C": {"H": 0.56, "L": 0.22, "N": 0.0},
    "I": {"H": 0.56, "L": 0.22, "N": 0.0},
    "A": {"H": 0.56, "L": 0.22, "N": 0.0},
}
PRIVILEGES = {"U": {"N": 0.85, "L": 0.62, "H": 0.27}, "C": {"N": 0.85, "L": 0.68, "H": 0.5}}
BANDS = ((9.0, "CRITICAL"), (7.0, "HIGH"), (4.0, "MODERATE"), (0.1, "LOW"))


def round_up(value: float) -> float:
    whole = round(value * 100000)
    if whole % 10000 == 0:
        return whole / 100000.0
    return (math.floor(whole / 10000) + 1) / 10.0


def metrics(vector: str) -> dict[str, str] | None:
    parts = (vector or "").strip().split("/")
    if not parts or parts[0] not in ("CVSS:3.0", "CVSS:3.1"):
        return None
    out = dict(p.split(":", 1) for p in parts[1:] if ":" in p)
    if any(out.get(k) not in WEIGHTS[k] for k in WEIGHTS) or out.get("PR") not in PRIVILEGES["U"]:
        return None
    return out


def base_score(vector: str) -> float | None:
    m = metrics(vector)
    if m is None:
        return None
    w = {k: WEIGHTS[k][m[k]] for k in ("AV", "AC", "UI", "C", "I", "A")}
    changed = m["S"] == "C"
    iss = 1 - (1 - w["C"]) * (1 - w["I"]) * (1 - w["A"])
    impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if changed else 6.42 * iss
    exploitability = 8.22 * w["AV"] * w["AC"] * PRIVILEGES[m["S"]][m["PR"]] * w["UI"]
    if impact <= 0:
        return 0.0
    return round_up(min((1.08 if changed else 1) * (impact + exploitability), 10))


def band(score: float) -> str:
    return next((name for floor, name in BANDS if score >= floor), "UNKNOWN")
