from __future__ import annotations

from pathlib import Path

import pytest

from decisis import imports

STORE = {"Cargo.toml": '[package]\nname = "p"\n\n[dependencies]\nstore = { package = "shop-db", path = "libs/db" }\n',
         "src/lib.rs": "pub mod db;\npub mod ui;\n", "src/db.rs": "pub struct Pool;\n", "src/ui/widgets.rs": "pub struct Button;\n",
         "libs/db/Cargo.toml": '[package]\nname = "shop-db"\n', "libs/db/src/lib.rs": "pub mod pool;\n", "libs/db/src/pool.rs": "pub struct Pool;\n"}
POOL = (1, "use crate::db::Pool", "repository", "src/db.rs")

TEXT = {
    "a string": 'const S: &str = "use crate::db::a;";',
    "a string with an escaped quote": 'const S: &str = "a \\" use crate::db::a;";',
    "a string over several lines": 'const S: &str = "first\nuse crate::db::a;\nlast";',
    "a string with a line continuation": 'const S: &str = "first \\\nuse crate::db::a;";',
    "a byte string": 'const B: &[u8] = b"use crate::db::a;";',
    "a C string": 'const C: &CStr = c"use crate::db::a;";',
    "a raw string": 'const R: &str = r"use crate::db::a;";',
    "a raw string with one hash": 'const R: &str = r#"use crate::db::a;"#;',
    "a raw string with a quote inside": 'const R: &str = r#"a " use crate::db::a;"#;',
    "a raw string with three hashes": 'const R: &str = r###"a "## use crate::db::a;"###;',
    "a raw string over several lines": 'const R: &str = r#"\nuse crate::db::a;\n"#;',
    "a raw byte string": 'const B: &[u8] = br"use crate::db::a;";',
    "a raw byte string with hashes": 'const B: &[u8] = br##"a "# use crate::db::a;"##;',
    "a raw C string": 'const C: &CStr = cr#"use crate::db::a;"#;',
    "a line comment": "// use crate::db::a;",
    "a doc line comment": "/// use crate::db::a;",
    "an inner doc line comment": "//! use crate::db::a;",
    "a block comment": "/* use crate::db::a; */",
    "a doc block comment": "/** use crate::db::a; */",
    "a block comment over several lines": "/*\nuse crate::db::a;\n*/",
    "a nested block comment": "/* a /* b */ use crate::db::a; /* c */ d */",
    "a mod declaration in a comment": "// mod hidden;",
    "a mod declaration in a string": 'const M: &str = "mod hidden;";',
    "an extern crate in a comment": "// extern crate shop_db;",
    "an extern crate in a string": 'const E: &str = "extern crate shop_db;";',
    "a quote character before a string": "const Q: char = '\"'; const S: &str = \"use crate::db::a;\";",
    "a byte quote character before a string": "const Q: u8 = b'\"'; const S: &str = \"use crate::db::a;\";",
    "an escaped quote character before a string": "const Q: char = '\\''; const S: &str = \"use crate::db::a;\";",
    "a unicode escape character before a string": "const U: char = '\\u{1F600}'; const S: &str = \"use crate::db::a;\";",
    "a slash character before a comment": "const A: char = '/'; /* use crate::db::a; */",
    "lifetimes before a string": "fn f<'a, 'b: 'a>(x: &'a str, y: &'b str) -> &'a str { 'o: loop { break 'o x; } }\nconst S: &str = \"use crate::db::a;\";",
}

BESIDE = {
    "a string": ('const S: &str = "use crate::db::a;"; use crate::db::Pool;', [POOL]),
    "a string over several lines": ('const S: &str = "a\nuse crate::db::a;\nb"; use crate::db::Pool;', [(3, *POOL[1:])]),
    "a byte string": ('const B: &[u8] = b"use crate::db::a;"; use crate::db::Pool;', [POOL]),
    "a raw string with hashes": ('const R: &str = r##"a "# use crate::db::a;"##; use crate::db::Pool;', [POOL]),
    "a raw byte string": ('const B: &[u8] = br#"use crate::db::a;"#; use crate::db::Pool;', [POOL]),
    "a quote character": ("const Q: char = '\"'; use crate::db::Pool;", [POOL]),
    "a block comment before": ("/* use crate::db::a; */ use crate::db::Pool;", [POOL]),
    "a nested block comment before": ("/* a /* use crate::db::a; */ b */ use crate::db::Pool;", [POOL]),
    "a block comment after": ("use crate::db::Pool; /* use crate::db::a; */", [POOL]),
    "a line comment after": ("use crate::db::Pool; // use crate::db::a;", [POOL]),
    "a line comment on the line before": ("// use crate::db::a;\nuse crate::db::Pool;", [(2, *POOL[1:])]),
    "a mod after a comment": ("/* mod gone; */ mod widgets;", [(1, "mod widgets", "repository", "src/ui/widgets.rs")]),
    "a mod after a string": ('const M: &str = "mod gone;"; mod widgets;', [(1, "mod widgets", "repository", "src/ui/widgets.rs")]),
    "an extern crate after a string": ('const E: &str = "extern crate shop_db;"; extern crate shop_db as d;',
                                       [(1, "extern crate shop_db", "repository", "libs/db/src/lib.rs")]),
    "an extern crate after a comment": ("/* extern crate gone; */ extern crate shop_db as d;",
                                        [(1, "extern crate shop_db", "repository", "libs/db/src/lib.rs")]),
}


def read(tmp_path: Path, text: str) -> list[imports.Import]:
    for name, body in {**STORE, "src/ui.rs": text}.items():
        (tmp_path / name).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / name).write_text(body, encoding="utf-8")
    return imports.read(imports.Repo(tmp_path), "src/ui.rs")


def shown(found: list[imports.Import]) -> list[tuple]:
    return [(i.line, i.specifier, i.resolution, i.target) for i in found]


@pytest.mark.parametrize("ending", ["", "\n"])
@pytest.mark.parametrize("case", sorted(TEXT))
def test_rust_text_in_a_string_a_character_context_or_a_comment_gives_no_result_at_all(tmp_path, case, ending):
    assert read(tmp_path, TEXT[case] + ending) == []


@pytest.mark.parametrize("case", sorted(BESIDE))
def test_a_real_rust_use_mod_or_extern_crate_next_to_text_is_still_found_and_judged(tmp_path, case):
    text, expected = BESIDE[case]
    assert shown(read(tmp_path, text)) == expected


def test_every_form_of_rust_text_in_one_file_leaves_only_the_real_use_and_no_disagreement(tmp_path):
    text = "\n".join(TEXT[name] for name in sorted(TEXT)) + "\nuse crate::db::Pool;\n"
    found = read(tmp_path, text)
    assert shown(found) == [(text.count("\n"), "use crate::db::Pool", "repository", "src/db.rs")]
    assert all("disagree" not in i.why for i in found)


def test_the_text_search_still_flags_a_use_after_a_point_the_scanner_could_not_pass_and_nothing_before_it(tmp_path):
    before = "\n".join(TEXT[name] for name in sorted(TEXT))
    text = before + "\n/* never closed\nuse crate::db::Pool;\n"
    found = read(tmp_path, text)
    line = before.count("\n") + 3
    assert [(i.line, i.specifier, i.resolution) for i in found if i.line] == [(line, "use crate::db::Pool", "unresolved")]
    assert "the scanner and the text search disagree" in next(i.why for i in found if i.line)
    assert any(i.line is None and "cannot be scanned to its end" in i.why for i in found)


def test_a_rust_file_with_windows_line_endings_and_a_byte_order_mark_hides_only_its_text_even_when_a_module_walk_read_it_first(tmp_path):
    text = "\ufeff/* use crate::db::a; */\r\nconst S: &str = \"use crate::db::a;\\\r\n\";\r\nuse crate::db::Pool;\r\n"
    files = {**STORE, "src/lib.rs": "pub mod db;\npub mod ui;\nuse crate::ui::Gone;\n"}
    for name, body in files.items():
        (tmp_path / name).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / name).write_text(body, encoding="utf-8")
    (tmp_path / "src/ui.rs").write_bytes(text.encode("utf-8"))
    repo = imports.Repo(tmp_path)
    imports.read(repo, "src/lib.rs")
    assert isinstance(repo.rust_infos.get("src/ui.rs"), dict)
    assert shown(imports.read(repo, "src/ui.rs")) == [(4, "use crate::db::Pool", "repository", "src/db.rs")]
    assert shown(imports.read(imports.Repo(tmp_path), "src/ui.rs")) == [(4, "use crate::db::Pool", "repository", "src/db.rs")]
