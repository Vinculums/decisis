from __future__ import annotations

from pathlib import Path

_DIR = Path(__file__).resolve().parent


def load(name: str, **bounds: int) -> str:
    text = (_DIR / f"{name}.cypher").read_text(encoding="utf-8").strip()
    for key, value in bounds.items():
        text = text.replace(f"${key}", str(int(value)))
    return text
