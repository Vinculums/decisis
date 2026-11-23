import importlib
import sys

import decisis

MODULES = ("audit", "checkout", "cli", "commit", "compare", "demo", "external", "fake_vinc", "impact", "queries", "sandbox", "semver")

for _name in MODULES:
    _module = importlib.import_module(f"decisis.{_name}")
    sys.modules[f"{__name__}.{_name}"] = _module
    globals()[_name] = _module

__path__ = decisis.__path__
