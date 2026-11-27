from __future__ import annotations

import json

import pytest

from decisis import rules
from decisis.inventory import bun, cargo, cyclonedx, npm, pnpm, poetry, spdx, uv, yarn

DENY_GPL = rules.parse({"license_denied": ["GPL-3.0-only"]}).rules[0]
ALLOW_MIT = rules.parse({"license_allowed": ["MIT"]}).rules[0]


@pytest.mark.parametrize("depth", [1, 16, 64])
def test_license_tree_accepts_parentheses_up_to_depth_limit(depth):
    expr = "(" * depth + "MIT" + ")" * depth
    assert rules.license_tree(expr) == ("id", "MIT")
    assert rules.verdict(DENY_GPL, {"license_expression": expr}, False)[0] == "not_violated"
    assert rules.verdict(ALLOW_MIT, {"license_expression": expr}, False)[0] == "not_violated"


def test_license_tree_accepts_compound_expression_at_depth_limit():
    expr = "(" * 64 + "MIT OR GPL-3.0-only" + ")" * 64
    assert rules.license_tree(expr) == ("or", (("id", "MIT"), ("id", "GPL-3.0-only")))
    assert rules.verdict(DENY_GPL, {"license_expression": expr}, False)[0] == "not_violated"
    assert rules.verdict(ALLOW_MIT, {"license_expression": expr}, False)[0] == "not_violated"


@pytest.mark.parametrize("depth", [65, 500, 2000])
def test_license_tree_rejects_excessive_parenthesis_nesting_as_unresolved(depth):
    expr = "(" * depth + "MIT" + ")" * depth
    assert rules.license_tree(expr) is None
    assert rules.verdict(DENY_GPL, {"license_expression": expr}, False)[0] == "unresolved"
    assert rules.verdict(ALLOW_MIT, {"license_expression": expr}, False)[0] == "unresolved"


def test_license_tree_rejects_deep_nested_branch_inside_compound_expression():
    expr = "MIT OR " + "(" * 65 + "GPL-3.0-only" + ")" * 65
    assert rules.license_tree(expr) is None
    assert rules.verdict(DENY_GPL, {"license_expression": expr}, False)[0] == "unresolved"


@pytest.mark.parametrize("payload", [
    [],
    None,
    "not-an-object",
    123,
    {"lockfileVersion": "3", "packages": {}},
    {"lockfileVersion": None, "packages": {}},
    {"lockfileVersion": True, "packages": {}},
    {"lockfileVersion": 1, "packages": {}},
    {"lockfileVersion": 3, "packages": None},
    {"lockfileVersion": 3, "packages": []},
    {"lockfileVersion": 3, "packages": "bad"},
    {"lockfileVersion": 3, "packages": {"": None}},
    {"lockfileVersion": 3, "packages": {"node_modules/a": None}},
    {"lockfileVersion": 3, "packages": {"node_modules/a": []}},
    {"lockfileVersion": 3, "packages": {"node_modules/a": "1.0.0"}},
    {"lockfileVersion": 3, "packages": {"node_modules/a": {"version": 123}}},
    {"lockfileVersion": 3, "packages": {"node_modules/a": {"version": None}}},
    {"lockfileVersion": 3, "packages": {"node_modules/a": {"version": ["1.0.0"]}}},
    {"lockfileVersion": 3, "packages": {"node_modules/a": {"version": "1.0.0", "name": 42}}},
    {"lockfileVersion": 3, "packages": {"": {"dependencies": None}}},
    {"lockfileVersion": 3, "packages": {"": {"dependencies": []}}},
    {"lockfileVersion": 3, "packages": {"": {"devDependencies": "bad"}}},
    {"lockfileVersion": 3, "packages": {"": {"optionalDependencies": 123}}},
    {"lockfileVersion": 3, "packages": {"": {"peerDependencies": []}}},
    {"lockfileVersion": 3, "packages": {"node_modules/a": {"version": "1.0.0", "dependencies": None}}},
    {"lockfileVersion": 3, "packages": {"node_modules/a": {"version": "1.0.0", "dependencies": []}}},
    {"lockfileVersion": 3, "packages": {"node_modules/a": {"version": "1.0.0", "optionalDependencies": "bad"}}},
    {"lockfileVersion": 3, "packages": {"node_modules/a": {"version": "1.0.0", "peerDependencies": 1}}},
    {"lockfileVersion": 2, "packages": {"": {}}, "dependencies": None},
    {"lockfileVersion": 2, "packages": {"": {}}, "dependencies": []},
    {"lockfileVersion": 2, "packages": {"": {}}, "dependencies": {"a": "1.0.0"}},
    {"lockfileVersion": 2, "packages": {"": {}}, "dependencies": {"a": {"version": 123}}},
    {"lockfileVersion": 2, "packages": {"": {}}, "dependencies": {"a": {"version": "1.0.0", "dependencies": []}}},
])
def test_npm_malformed_shapes_raise_value_error(payload):
    with pytest.raises(ValueError):
        npm.parse_npm_lock(json.dumps(payload), "Demo")


@pytest.mark.parametrize("text", [
    'package = "bad"\n',
    "package = 123\n",
    '[package]\nname = "a"\n',
    'package = ["a"]\n',
    "package = [123]\n",
    "[[package]]\nname = 123\nversion = \"1.0.0\"\n",
    '[[package]]\nname = ["a"]\nversion = "1.0.0"\n',
    '[[package]]\nname = "a"\nversion = 123\n',
    '[[package]]\nname = "a"\nversion = ["1.0.0"]\n',
    '[[package]]\nname = "a"\nversion = "1.0.0"\nsource = "pypi"\n',
    '[[package]]\nname = "a"\nversion = "1.0.0"\ndependencies = "b"\n',
    '[[package]]\nname = "a"\nversion = "1.0.0"\ndependencies = 123\n',
    '[[package]]\nname = "a"\nversion = "1.0.0"\ndependencies = ["b"]\n',
    '[[package]]\nname = "a"\nversion = "1.0.0"\ndependencies = [{ name = 123 }]\n',
    '[[package]]\nname = "a"\nversion = "1.0.0"\ndependencies = [{ name = "b", version = 123 }]\n',
    '[[package]]\nname = "a"\nversion = "1.0.0"\noptional-dependencies = []\n',
    '[[package]]\nname = "a"\nversion = "1.0.0"\n[package.optional-dependencies]\nextra = "bad"\n',
    '[[package]]\nname = "a"\nversion = "1.0.0"\n[package.optional-dependencies]\nextra = ["b"]\n',
    '[[package]]\nname = "a"\nversion = "1.0.0"\ndev-dependencies = "bad"\n',
    '[[package]]\nname = "a"\nversion = "1.0.0"\n[package.dev-dependencies]\ndev = "bad"\n',
    '[[package]]\nname = "a"\nversion = "1.0.0"\n[package.dev-dependencies]\ndev = ["b"]\n',
])
def test_uv_malformed_shapes_raise_value_error(text):
    with pytest.raises(ValueError):
        uv.read(text, "uv.lock", "Demo")


@pytest.mark.parametrize("text", [
    'metadata = "bad"\n',
    "metadata = []\n",
    'package = "bad"\n',
    "package = 123\n",
    '[package]\nname = "a"\n',
    'package = ["a"]\n',
    '[[package]]\nversion = "1.0.0"\n',
    '[[package]]\nname = 123\nversion = "1.0.0"\n',
    '[[package]]\nname = "a"\nversion = 123\n',
    '[[package]]\nname = "a"\nversion = []\n',
    '[[package]]\nname = "a"\nversion = "1.0.0"\ndependencies = ["b"]\n',
    '[[package]]\nname = "a"\nversion = "1.0.0"\ndependencies = "b"\n',
    '[[package]]\nname = "a"\nversion = "1.0.0"\nsource = "git"\n',
])
def test_poetry_malformed_shapes_raise_value_error(text):
    with pytest.raises(ValueError):
        poetry.read(text, "poetry.lock", "Demo")


@pytest.mark.parametrize("pyproject", [
    'tool = "bad"\n',
    '[tool]\npoetry = "bad"\n',
    '[tool.poetry]\ndependencies = ["a"]\n',
    '[tool.poetry.group]\ndev = "bad"\n',
    'project = "bad"\n',
    '[project]\ndependencies = "bad"\n',
    '[project]\ndependencies = [123]\n',
    '[project.optional-dependencies]\nextra = "bad"\n',
    '[dependency-groups]\ndev = "bad"\n',
])
def test_poetry_malformed_pyproject_sibling_raises_value_error(pyproject):
    lock = '[[package]]\nname = "a"\nversion = "1.0.0"\n'
    with pytest.raises(ValueError):
        poetry.read(lock, "poetry.lock", "Demo", {"pyproject.toml": pyproject})


@pytest.mark.parametrize("payload", [
    [],
    None,
    {"bomFormat": "CycloneDX", "specVersion": "1.5", "metadata": "bad"},
    {"bomFormat": "CycloneDX", "specVersion": "1.5", "metadata": {"component": "bad"}},
    {"bomFormat": "CycloneDX", "specVersion": "1.5", "metadata": {"component": {"bom-ref": []}}},
    {"bomFormat": "CycloneDX", "specVersion": "1.5", "components": None},
    {"bomFormat": "CycloneDX", "specVersion": "1.5", "components": "bad"},
    {"bomFormat": "CycloneDX", "specVersion": "1.5", "components": 123},
    {"bomFormat": "CycloneDX", "specVersion": "1.5", "components": {}},
    {"bomFormat": "CycloneDX", "specVersion": "1.5", "components": [None]},
    {"bomFormat": "CycloneDX", "specVersion": "1.5", "components": ["bad"]},
    {"bomFormat": "CycloneDX", "specVersion": "1.5", "components": [{"name": "a", "components": None}]},
    {"bomFormat": "CycloneDX", "specVersion": "1.5", "components": [{"name": "a", "components": ["bad"]}]},
    {"bomFormat": "CycloneDX", "specVersion": "1.5", "components": [{"name": "a", "version": 123}]},
    {"bomFormat": "CycloneDX", "specVersion": "1.5", "components": [{"name": 123}]},
    {"bomFormat": "CycloneDX", "specVersion": "1.5", "components": [{"name": "a", "bom-ref": []}]},
    {"bomFormat": "CycloneDX", "specVersion": "1.5", "components": [{"name": "a", "licenses": None}]},
    {"bomFormat": "CycloneDX", "specVersion": "1.5", "components": [{"name": "a", "licenses": "MIT"}]},
    {"bomFormat": "CycloneDX", "specVersion": "1.5", "components": [{"name": "a", "licenses": [None]}]},
    {"bomFormat": "CycloneDX", "specVersion": "1.5", "components": [{"name": "a", "licenses": ["MIT"]}]},
    {"bomFormat": "CycloneDX", "specVersion": "1.5", "components": [{"name": "a", "licenses": [{"license": "MIT"}]}]},
    {"bomFormat": "CycloneDX", "specVersion": "1.5", "components": [{"name": "a", "licenses": [{"expression": 123}]}]},
    {"bomFormat": "CycloneDX", "specVersion": "1.5", "components": [{"name": "a", "licenses": [{"license": {"id": 123}}]}]},
    {"bomFormat": "CycloneDX", "specVersion": "1.5", "components": [{"name": "a", "properties": None}]},
    {"bomFormat": "CycloneDX", "specVersion": "1.5", "components": [{"name": "a", "properties": ["bad"]}]},
    {"bomFormat": "CycloneDX", "specVersion": "1.5", "dependencies": None},
    {"bomFormat": "CycloneDX", "specVersion": "1.5", "dependencies": "bad"},
    {"bomFormat": "CycloneDX", "specVersion": "1.5", "dependencies": {}},
    {"bomFormat": "CycloneDX", "specVersion": "1.5", "dependencies": [None]},
    {"bomFormat": "CycloneDX", "specVersion": "1.5", "dependencies": ["a"]},
    {"bomFormat": "CycloneDX", "specVersion": "1.5", "dependencies": [{"ref": []}]},
    {"bomFormat": "CycloneDX", "specVersion": "1.5", "dependencies": [{"ref": "a", "dependsOn": None}]},
    {"bomFormat": "CycloneDX", "specVersion": "1.5", "dependencies": [{"ref": "a", "dependsOn": "b"}]},
    {"bomFormat": "CycloneDX", "specVersion": "1.5", "dependencies": [{"ref": "a", "dependsOn": [123]}]},
])
def test_cyclonedx_malformed_shapes_raise_value_error(payload):
    with pytest.raises(ValueError):
        cyclonedx.read(json.dumps(payload), "bom.cdx.json", "Demo")


@pytest.mark.parametrize("payload", [
    [],
    None,
    {"spdxVersion": "SPDX-2.3", "documentDescribes": None},
    {"spdxVersion": "SPDX-2.3", "documentDescribes": "SPDXRef-root"},
    {"spdxVersion": "SPDX-2.3", "documentDescribes": [123]},
    {"spdxVersion": "SPDX-2.3", "packages": None},
    {"spdxVersion": "SPDX-2.3", "packages": "bad"},
    {"spdxVersion": "SPDX-2.3", "packages": 123},
    {"spdxVersion": "SPDX-2.3", "packages": {}},
    {"spdxVersion": "SPDX-2.3", "packages": [None]},
    {"spdxVersion": "SPDX-2.3", "packages": ["bad"]},
    {"spdxVersion": "SPDX-2.3", "packages": [{}]},
    {"spdxVersion": "SPDX-2.3", "packages": [{"SPDXID": 123}]},
    {"spdxVersion": "SPDX-2.3", "packages": [{"SPDXID": "SPDXRef-a", "versionInfo": 123}]},
    {"spdxVersion": "SPDX-2.3", "packages": [{"SPDXID": "SPDXRef-a", "name": []}]},
    {"spdxVersion": "SPDX-2.3", "packages": [{"SPDXID": "SPDXRef-a", "externalRefs": None}]},
    {"spdxVersion": "SPDX-2.3", "packages": [{"SPDXID": "SPDXRef-a", "externalRefs": "bad"}]},
    {"spdxVersion": "SPDX-2.3", "packages": [{"SPDXID": "SPDXRef-a", "externalRefs": [None]}]},
    {"spdxVersion": "SPDX-2.3", "packages": [{"SPDXID": "SPDXRef-a", "externalRefs": ["bad"]}]},
    {"spdxVersion": "SPDX-2.3", "packages": [{"SPDXID": "SPDXRef-a", "externalRefs": [{"referenceType": []}]}]},
    {"spdxVersion": "SPDX-2.3", "packages": [{"SPDXID": "SPDXRef-a", "externalRefs": [{"referenceType": "purl", "referenceLocator": 123}]}]},
    {"spdxVersion": "SPDX-2.3", "relationships": None},
    {"spdxVersion": "SPDX-2.3", "relationships": "bad"},
    {"spdxVersion": "SPDX-2.3", "relationships": 123},
    {"spdxVersion": "SPDX-2.3", "relationships": {}},
    {"spdxVersion": "SPDX-2.3", "relationships": [None]},
    {"spdxVersion": "SPDX-2.3", "relationships": ["bad"]},
    {"spdxVersion": "SPDX-2.3", "relationships": [{"relationshipType": []}]},
    {"spdxVersion": "SPDX-2.3", "relationships": [{"relationshipType": "DEPENDS_ON", "spdxElementId": []}]},
])
def test_spdx_malformed_shapes_raise_value_error(payload):
    with pytest.raises(ValueError):
        spdx.read(json.dumps(payload), "sbom.spdx.json", "Demo")


@pytest.mark.parametrize("text", [
    "lockfileVersion: '9.0'\npackages: bad\n",
    "lockfileVersion: '9.0'\npackages:\n  - a\n",
    "lockfileVersion: '9.0'\npackages:\n  ms@2.0.0: bad\n",
    "lockfileVersion: '9.0'\nsnapshots: bad\n",
    "lockfileVersion: '9.0'\nsnapshots:\n  ms@2.0.0: bad\n",
    "lockfileVersion: '9.0'\nimporters: bad\n",
    "lockfileVersion: '9.0'\nimporters:\n  .: bad\n",
    "lockfileVersion: '9.0'\nimporters:\n  .:\n    dependencies:\n      - a\n",
    "lockfileVersion: '9.0'\nimporters:\n  .:\n    dependencies:\n      a:\n        - 1.0.0\n",
    "lockfileVersion: '9.0'\npackages:\n  ms@2.0.0:\n    resolution:\n      - bad\n",
    "lockfileVersion: '9.0'\npackages:\n  ms@2.0.0:\n    peerDependencies:\n      - bad\n",
    "lockfileVersion: '9.0'\nsnapshots:\n  ms@2.0.0:\n    dependencies:\n      - bad\n",
])
def test_pnpm_malformed_shapes_raise_value_error(text):
    with pytest.raises(ValueError):
        pnpm.read(text, "pnpm-lock.yaml", "Demo")


@pytest.mark.parametrize("text", [
    'foo@^1.0.0:\n  version:\n    a "1"\n',
    'foo@^1.0.0:\n  version "1.0.0"\n  dependencies "bad"\n',
    'foo@^1.0.0:\n  version "1.0.0"\n  optionalDependencies "bad"\n',
    "__metadata:\n  - bad\n",
    '__metadata:\n  version: 8\n"foo@npm:1.0.0": bad\n',
    '__metadata:\n  version: 8\n"foo@npm:1.0.0":\n  resolution:\n    - bad\n',
    '__metadata:\n  version: 8\n"foo@npm:1.0.0":\n  resolution: "foo@npm:1.0.0"\n  version:\n    - 1.0.0\n',
    '__metadata:\n  version: 8\n"foo@npm:1.0.0":\n  resolution: "foo@npm:1.0.0"\n  dependencies:\n    - bar\n',
    '__metadata:\n  version: 8\n"foo@npm:1.0.0":\n  resolution: "foo@npm:1.0.0"\n  peerDependencies:\n    - bar\n',
    '__metadata:\n  version: 8\n"foo@npm:1.0.0":\n  resolution: "foo@npm:1.0.0"\n  dependenciesMeta:\n    - bar\n',
    '__metadata:\n  version: 8\n"foo@npm:1.0.0":\n  resolution: "foo@npm:1.0.0"\n  dependencies:\n    bar: "1.0.0"\n  dependenciesMeta:\n    bar: bad\n',
])
def test_yarn_malformed_shapes_raise_value_error(text):
    with pytest.raises(ValueError):
        yarn.read(text, "yarn.lock", "Demo")


@pytest.mark.parametrize("payload", [
    [],
    {"lockfileVersion": 1, "packages": None},
    {"lockfileVersion": 1, "packages": []},
    {"lockfileVersion": 1, "packages": {}, "workspaces": None},
    {"lockfileVersion": 1, "packages": {}, "workspaces": []},
    {"lockfileVersion": 1, "packages": {}, "workspaces": {"": None}},
    {"lockfileVersion": 1, "packages": {}, "workspaces": {"": {"name": 123}}},
    {"lockfileVersion": 1, "packages": {}, "workspaces": {"": {"dependencies": None}}},
    {"lockfileVersion": 1, "packages": {}, "workspaces": {"": {"dependencies": []}}},
    {"lockfileVersion": 1, "packages": {"a": None}},
    {"lockfileVersion": 1, "packages": {"a": {}}},
    {"lockfileVersion": 1, "packages": {"a": []}},
    {"lockfileVersion": 1, "packages": {"a": [123]}},
    {"lockfileVersion": 1, "packages": {"a": ["a@1.0.0", "", {"dependencies": None}]}},
    {"lockfileVersion": 1, "packages": {"a": ["a@1.0.0", "", {"dependencies": []}]}},
])
def test_bun_malformed_shapes_raise_value_error(payload):
    with pytest.raises(ValueError):
        bun.read(json.dumps(payload), "bun.lock", "Demo")


@pytest.mark.parametrize("text", [
    'package = "bad"\n',
    "package = 123\n",
    '[package]\nname = "a"\n',
    'package = ["a"]\n',
    '[[package]]\nname = 123\nversion = "1.0.0"\n',
    '[[package]]\nname = ["a"]\nversion = "1.0.0"\n',
    '[[package]]\nname = "a"\nversion = 123\n',
    '[[package]]\nname = "a"\nversion = ["1.0.0"]\n',
    '[[package]]\nname = "a"\nversion = "1.0.0"\nsource = 123\n',
    '[[package]]\nname = "a"\nversion = "1.0.0"\ndependencies = "b 1.0.0"\n',
    '[[package]]\nname = "a"\nversion = "1.0.0"\ndependencies = 123\n',
    '[[package]]\nname = "a"\nversion = "1.0.0"\ndependencies = [123]\n',
    '[[package]]\nname = "a"\nversion = "1.0.0"\ndependencies = [{}]\n',
])
def test_cargo_malformed_shapes_raise_value_error(text):
    with pytest.raises(ValueError):
        cargo.read(text, "Cargo.lock", "Demo")
