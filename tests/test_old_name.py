import subprocess
import sys
from pathlib import Path

import decisis.impact


def test_the_old_package_name_resolves_to_the_decisis_modules():
    import vinc_relate
    from vinc_relate import audit, checkout, external, impact, sandbox
    from vinc_relate.queries import load
    from vinc_relate.sandbox import sandbox as box

    assert impact is decisis.impact and vinc_relate.impact is decisis.impact
    assert audit.__name__ == "decisis.audit" and checkout.__name__ == "decisis.checkout"
    assert external.__name__ == "decisis.external" and sandbox.__name__ == "decisis.sandbox"
    assert "*0..2" in load("governing_nodes", hops=2) and box is decisis.sandbox.sandbox


def test_both_commands_are_installed_and_print_the_same_help():
    bindir = Path(sys.executable).parent
    new, old = bindir / "decisis", bindir / "vinc-relate"
    assert new.exists() and old.exists()
    a = subprocess.run([str(new), "--help"], capture_output=True, text=True, check=True).stdout
    b = subprocess.run([str(old), "--help"], capture_output=True, text=True, check=True).stdout
    assert a == b and "decisis" in a
