from __future__ import annotations

from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
PRIVATE_PATHS = ["api/graph_algo.py", "store/embedded_backend.py", "_vector_query_guard"]


def public_files():
    files = [ROOT / "README.md", *sorted((ROOT / "fixtures").rglob("*.json")), *sorted((ROOT / "src").rglob("*.py"))]
    return files + [p for p in sorted((ROOT / "tests").glob("*.py")) if p.name != Path(__file__).name]


def private_hits(text: str) -> list[str]:
    return [p for p in PRIVATE_PATHS if p in text]


@pytest.mark.parametrize("path", public_files(), ids=lambda p: str(p.relative_to(ROOT)))
def test_no_public_file_names_a_known_private_path(path):
    assert private_hits(path.read_text(encoding="utf-8")) == []


def test_the_check_catches_a_private_path():
    assert private_hits('{"code_ref": "Demo:store/embedded_backend.py:_vector_query_guard"}') == ["store/embedded_backend.py", "_vector_query_guard"]
    assert private_hits('{"code_ref": "Demo:storage/page_store.py"}') == []
