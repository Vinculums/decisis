from __future__ import annotations

import re

_V = re.compile(r"""
    ^v?
    (?:(?P<epoch>[0-9]+)!)?
    (?P<release>[0-9]+(?:\.[0-9]+)*)
    (?:[-_.]?(?P<pre_l>alpha|a|beta|b|preview|pre|c|rc)[-_.]?(?P<pre_n>[0-9]+)?)?
    (?:-(?P<post_n1>[0-9]+)|[-_.]?(?P<post_l>post|rev|r)[-_.]?(?P<post_n2>[0-9]+)?)?
    (?:[-_.]?(?P<dev_l>dev)[-_.]?(?P<dev_n>[0-9]+)?)?
    (?:\+(?P<local>[a-z0-9]+(?:[-_.][a-z0-9]+)*))?
    $""", re.VERBOSE | re.IGNORECASE)
_PRE = {"a": 0, "alpha": 0, "b": 1, "beta": 1, "c": 2, "rc": 2, "pre": 2, "preview": 2}


def _release(text: str) -> tuple:
    parts = [int(x) for x in text.split(".")]
    while len(parts) > 1 and parts[-1] == 0:
        parts.pop()
    return tuple(parts)


def _local(text: str | None) -> tuple:
    if text is None:
        return (0,)
    return (1, tuple((1, int(x), "") if x.isdigit() else (0, 0, x.lower()) for x in re.split(r"[-_.]", text)))


def key(version: str) -> tuple:
    m = _V.match(version.strip())
    if not m:
        raise ValueError(f"not a PEP 440 version: {version!r}")
    post = m["post_n1"] or m["post_n2"] or ("0" if m["post_l"] else None)
    dev = m["dev_n"] or ("0" if m["dev_l"] else None)
    if m["pre_l"]:
        pre = (1, _PRE[m["pre_l"].lower()], int(m["pre_n"] or 0))
    else:
        pre = (0,) if dev is not None and post is None else (2,)
    return (int(m["epoch"] or 0), _release(m["release"]), pre, (0,) if post is None else (1, int(post)),
            (1,) if dev is None else (0, int(dev)), _local(m["local"]))
