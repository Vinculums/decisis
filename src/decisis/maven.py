from __future__ import annotations

from functools import total_ordering
from itertools import zip_longest

QUALIFIERS = ("alpha", "beta", "milestone", "rc", "snapshot", "", "sp")
ALIASES = {"ga": "", "final": "", "release": "", "cr": "rc"}
SHORT = {"a": "alpha", "b": "beta", "m": "milestone"}
RELEASE = (QUALIFIERS.index(""), "")
DIGITS = "0123456789"


def qualifier(word: str, followed_by_digit: bool = False) -> tuple[int, str]:
    if followed_by_digit and word in SHORT:
        word = SHORT[word]
    word = ALIASES.get(word, word)
    return (QUALIFIERS.index(word), "") if word in QUALIFIERS else (len(QUALIFIERS), word)


def _item(token: str, digit: bool):
    return int(token) if digit else qualifier(token)


def _sublist(current: list, stack: list[list]) -> list:
    child: list = []
    current.append(child)
    stack.append(child)
    return child


def _is_null(item) -> bool:
    if isinstance(item, int):
        return item == 0
    if isinstance(item, tuple):
        return item == RELEASE
    return not item


def _normalize(items: list) -> None:
    for i in range(len(items) - 1, -1, -1):
        if _is_null(items[i]):
            del items[i]
        elif not isinstance(items[i], list):
            break


def parse(text: str) -> list:
    text = text.strip().lower()
    root: list = []
    current, stack, start, digit = root, [root], 0, False
    for i, ch in enumerate(text):
        if ch in ".-":
            current.append(_item(text[start:i], digit) if i > start else 0)
            start = i + 1
            if ch == "-":
                current = _sublist(current, stack)
        elif ch in DIGITS:
            if not digit and i > start:
                current.append(qualifier(text[start:i], True))
                start = i
                current = _sublist(current, stack)
            digit = True
        else:
            if digit and i > start:
                current.append(int(text[start:i]))
                start = i
                current = _sublist(current, stack)
            digit = False
    if len(text) > start:
        if not digit and current:
            current = _sublist(current, stack)
        current.append(_item(text[start:], digit))
    for items in reversed(stack):
        _normalize(items)
    return root


def _sign(a, b) -> int:
    return (a > b) - (a < b)


def _against_null(item) -> int:
    if isinstance(item, int):
        return _sign(item, 0)
    if isinstance(item, tuple):
        return _sign(item, RELEASE)
    return _against_null(item[0]) if item else 0


def _lists(a: list, b: list) -> int:
    for x, y in zip_longest(a, b):
        result = -compare(y, x) if x is None else compare(x, y)
        if result:
            return result
    return 0


def compare(a, b) -> int:
    if b is None:
        return _against_null(a)
    if type(a) is type(b):
        return _lists(a, b) if isinstance(a, list) else _sign(a, b)
    if isinstance(a, int):
        return 1
    if isinstance(b, int):
        return -1
    return -1 if isinstance(a, tuple) else 1


@total_ordering
class Version:
    def __init__(self, text: str):
        self.text = text
        self.items = parse(text)

    def __eq__(self, other) -> bool:
        return isinstance(other, Version) and compare(self.items, other.items) == 0

    def __lt__(self, other: Version) -> bool:
        return compare(self.items, other.items) < 0

    __hash__ = None

    def __repr__(self) -> str:
        return f"Version({self.text!r})"


def key(text: str) -> Version:
    if not isinstance(text, str) or not text.strip():
        raise ValueError(f"not a Maven version: {text!r}")
    return Version(text)
