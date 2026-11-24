import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))


def pytest_collection_modifyitems(config, items):
    if os.environ.get("DECISIS_SLOW") == "1" or "slow" in (config.getoption("markexpr") or ""):
        return
    skip = pytest.mark.skip(reason="slow: set DECISIS_SLOW=1 or pass -m slow to run it")
    for item in items:
        if item.get_closest_marker("slow"):
            item.add_marker(skip)
