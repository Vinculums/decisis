from __future__ import annotations

import io
import json
import os

import pytest

from decisis import checkout as co
from decisis import impact
from decisis.fake_vinc import FakeVinc
from decisis.sandbox import Subgraph


def raw(nodes, edges):
    return {"nodes": nodes, "edges": edges}


def test_normalize_dedupes_by_id_keeps_known_edges_and_drops_dangling_ones():
    a = raw([{"id": "concept:a", "kind": "concept", "label": "A"}, {"id": "concept:b", "kind": "concept", "label": "B"}],
            [{"source": "concept:a", "target": "concept:b", "type": "RELATED_TO", "evidence": "e"},
             {"source": "concept:a", "target": "concept:zzz", "type": "RELATED_TO"},
             {"source": "concept:a", "target": "concept:b", "type": "IN_DOMAIN"}])
    b = raw([{"id": "concept:b", "kind": "concept", "label": "B again"}], [{"source": "concept:a", "target": "concept:b", "type": "related_to"}])
    g = co.normalize([a, b], ["concept:a"], "space-1")
    assert [n["id"] for n in g.nodes] == ["concept:a", "concept:b"]
    assert g.nodes[1]["title"] == "B"
    assert g.edges == [{"source": "concept:a", "target": "concept:b", "type": "RELATED_TO", "evidence": "e"}]
    assert g.meta["space"] == "space-1" and g.meta["seeds"] == ["concept:a"]


def test_a_record_edge_read_through_its_carrier_keeps_its_relation_and_direction():
    g = co.normalize([raw([{"id": "record:r", "kind": "record"}, {"id": "decision:d", "kind": "decision"}],
                          [{"source": "record:r", "target": "decision:d", "type": "ATTACHES_TO", "role": "relates_to", "evidence": "e"},
                           {"source": "record:r", "target": "decision:d", "type": "ATTACHES_TO", "subtype": "about"},
                           {"source": "record:r", "target": "decision:d", "type": "ATTACHES_TO"}])], ["record:r"], None)
    assert g.edges == [{"source": "record:r", "target": "decision:d", "type": "ABOUT", "evidence": ""},
                       {"source": "record:r", "target": "decision:d", "type": "RELATED_TO", "evidence": "e"}]


def test_a_snapshot_whose_counts_disagree_with_its_lists_is_refused():
    g = co.normalize([raw([{"id": "concept:a", "kind": "concept"}], [])], ["concept:a"], None)
    text = co.dump(g).replace('"nodes": 1,', '"nodes": 2,')
    with pytest.raises(ValueError, match="says it has 2 nodes but lists 1"):
        co.load(text)


def test_a_snapshot_round_trips():
    g = co.normalize([raw([{"id": "concept:a", "kind": "concept"}], [])], ["concept:a"], None)
    assert co.load(co.dump(g)) == g


REF = "Vinc:vinc_mcp/community_tools.py"
SEED = "record:community-mcp-tool-buckets-by-surface"
CONCEPT = "concept:community-mcp-surface-trim"
CONCEPT_PROPS = {"code_ref": [REF, "Vinc:vinc_mcp/tools.py"], "keep_bucket": "registry-only"}


class OlderHub(FakeVinc):
    def tool(self, name, args):
        return super().tool(name, {k: v for k, v in args.items() if k != "detail"})


def community_space(hub=FakeVinc) -> FakeVinc:
    nodes = [{"id": SEED, "kind": "record", "title": "Tool buckets", "domain": "product/community",
              "props": {"code_ref": REF, "subject_path": "vinc_mcp/community_tools.py", "counts": {"a": 11, "b": 10, "c": 11}}},
             {"id": CONCEPT, "kind": "concept", "title": "Community MCP surface trim", "domain": "product/community", "props": CONCEPT_PROPS},
             {"id": "decision:keep-the-surface-small", "kind": "decision", "title": "Keep the surface small", "domain": "product/community",
              "props": {"status": "accepted", "subject_path": "vinc_mcp/", "rules": {"review_required": {"paths": ["vinc_mcp/**"]}}}},
             {"id": "concept:far", "kind": "concept", "title": "Far", "domain": "", "props": {"code_ref": "Vinc:far.py"}}]
    edges = [{"source": SEED, "target": CONCEPT, "type": "RELATED_TO", "evidence": "the record names the buckets"},
             {"source": SEED, "target": "decision:keep-the-surface-small", "type": "RELATED_TO", "evidence": "the record cites the decision"},
             {"source": "decision:keep-the-surface-small", "target": CONCEPT, "type": "ABOUT", "evidence": "the limit applies"},
             {"source": CONCEPT, "target": "concept:far", "type": "RELATED_TO", "evidence": "one hop further"}]
    return hub(Subgraph(nodes, edges, {}), name="vinc")


def test_a_checkout_keeps_the_props_of_every_node_it_exports_with_one_read_per_seed():
    fake = community_space()
    g = co.checkout(fake, [SEED], 1)
    by = {n["id"]: n["props"] for n in g.nodes}
    assert set(by) == {SEED, CONCEPT, "decision:keep-the-surface-small"}
    assert by[CONCEPT] == CONCEPT_PROPS
    assert by["decision:keep-the-surface-small"] == {"status": "accepted", "subject_path": "vinc_mcp/", "rules": {"review_required": {"paths": ["vinc_mcp/**"]}}}
    assert by[SEED]["counts"] == {"a": 11, "b": 10, "c": 11}
    assert "props_missing" not in g.meta
    assert fake.calls == ["vinc_graph"]


def test_a_checkout_keeps_the_depth_it_was_given():
    near, wide = community_space(), community_space()
    assert "concept:far" not in {n["id"] for n in co.checkout(near, [SEED], 1).nodes}
    two = co.checkout(wide, [SEED], 2)
    assert {n["id"]: n["props"].get("code_ref") for n in two.nodes}["concept:far"] == "Vinc:far.py"


def test_a_hub_that_ignores_detail_is_named_in_the_meta_and_no_props_are_invented():
    g = co.checkout(community_space(OlderHub), [SEED], 1)
    by = {n["id"]: n["props"] for n in g.nodes}
    assert by[SEED]["code_ref"] == REF
    assert by[CONCEPT] == {} and by["decision:keep-the-surface-small"] == {}
    assert g.meta["props_missing"] == [CONCEPT, "decision:keep-the-surface-small"]


def test_normalize_keeps_a_full_nodes_props_whole_and_drops_only_its_layout_fields():
    node = {"id": CONCEPT, "label": "Trim", "domain": "product/community", "kind": "concept", "degree": 2, "props": CONCEPT_PROPS,
            "tags": ["mcp"], "ts": "2026-11-24T12:04:21.032Z", "content_ts": "2026-11-24", "one_liner": "x", "rev": 7,
            "updated_at": "2026-11-25T15:11:23.862Z", "valid_from": "", "valid_until": "2027-01-01", "ppr": 0.18,
            "x": -0.36, "y": 0.29, "z": -1.15, "x2": -0.41, "y2": -0.91}
    g = co.normalize([raw([node], [])], [CONCEPT], None)
    assert g.nodes == [{"id": CONCEPT, "kind": "concept", "title": "Trim", "domain": "product/community", "valid_until": "2027-01-01", "props": CONCEPT_PROPS}]
    assert "props_missing" not in g.meta


def test_a_node_the_hub_emptied_to_fit_its_size_limit_is_named_but_an_empty_node_in_a_whole_reply_is_not():
    nodes = [{"id": "concept:kept", "kind": "concept", "props": {"code_ref": "a.py"}}, {"id": "concept:emptied", "kind": "concept", "props": {}}]
    shrunk = {"nodes": nodes, "edges": [], "shrunk": {"neighbour_props": 1, "note": "shrunk to fit the result size limit"}}
    assert co.normalize([shrunk], ["concept:kept"], None).meta["props_missing"] == ["concept:emptied"]
    whole = {"nodes": nodes, "edges": [], "shrunk": {"neighbour_props": 0}}
    assert "props_missing" not in co.normalize([whole], ["concept:kept"], None).meta
    assert "props_missing" not in co.normalize([raw(nodes, [])], ["concept:kept"], None).meta


def test_props_a_later_reply_carries_for_a_node_an_earlier_reply_gave_bare_are_kept():
    bare = raw([{"id": "concept:a", "kind": "concept"}, {"id": "concept:b", "kind": "concept"}], [])
    whole = raw([{"id": "concept:b", "kind": "concept", "props": {"code_ref": "b.py"}}], [])
    g = co.normalize([bare, whole], ["concept:a", "concept:b"], None)
    assert {n["id"]: n["props"] for n in g.nodes} == {"concept:a": {}, "concept:b": {"code_ref": "b.py"}}
    assert g.meta["props_missing"] == ["concept:a"]


def test_the_meta_that_names_missing_props_survives_a_round_trip():
    g = co.normalize([raw([{"id": "concept:a", "kind": "concept"}], [])], ["concept:a"], None)
    assert co.load(co.dump(g)).meta["props_missing"] == ["concept:a"]


class FakeResp(io.BytesIO):
    def __init__(self, body, session=None):
        super().__init__(body.encode())
        self.headers = {"Mcp-Session-Id": session} if session else {}

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def test_the_client_initializes_once_names_the_space_and_reads_structured_content():
    sent = []

    def opener(req, timeout):
        body = json.loads(req.data)
        sent.append((body, dict(req.headers)))
        if body["method"] == "initialize":
            return FakeResp('{"result": {}}', session="s1")
        return FakeResp('data: {"result": {"structuredContent": {"nodes": [], "edges": []}}}')

    c = co.VincMCP("tok", space="space-1", opener=opener)
    assert c.tool("vinc_graph", {"seed_id": "concept:a"}) == {"nodes": [], "edges": []}
    c.tool("vinc_graph", {"seed_id": "concept:b"})
    assert [b["method"] for b, _ in sent] == ["initialize", "tools/call", "tools/call"]
    assert sent[1][0]["params"]["arguments"] == {"seed_id": "concept:a", "space": "space-1"}
    assert sent[2][1].get("Mcp-session-id") == "s1"


LIVE = ("VINC_API_KEY", "VINC_LIVE_SEED", "VINC_LIVE_TARGET")


@pytest.mark.skipif(not all(os.environ.get(k) for k in LIVE),
                    reason="the live check needs a read-only VINC_API_KEY, VINC_LIVE_SEED and VINC_LIVE_TARGET (a node with an edge from the seed)")
def test_live_checkout_keeps_ids_direction_and_evidence():
    seed, target = os.environ["VINC_LIVE_SEED"], os.environ["VINC_LIVE_TARGET"]
    g = co.checkout(co.VincMCP.from_env(), [seed], 1)
    ids = [n["id"] for n in g.nodes]
    assert len(ids) == len(set(ids)) and {seed, target} <= set(ids)
    e = next(e for e in g.edges if e["source"] == seed and e["target"] == target)
    assert e["type"] in co.EDGE_TYPES and e["evidence"]


def test_impact_on_a_checkout_lists_a_non_seed_node_whose_code_ref_covers_the_path(tmp_path):
    path = "vinc_mcp/community_tools.py"
    whole = co.load(co.dump(co.checkout(community_space(), [SEED], 1)))
    got = {g["id"]: g for g in impact.run(whole, [path], repo="Vinc", root=tmp_path)["impact"][0]["governing"]}
    assert got[CONCEPT]["hops"] == 0 and got[CONCEPT]["code_ref"] == [{"ref": REF, "match": "exact"}]
    assert got[SEED]["hops"] == 0
    bare = co.load(co.dump(co.checkout(community_space(OlderHub), [SEED], 1)))
    assert [g["id"] for g in impact.run(bare, [path], repo="Vinc", root=tmp_path)["impact"][0]["governing"] if g["hops"] == 0] == [SEED]
    assert bare.meta["props_missing"] == [CONCEPT, "decision:keep-the-surface-small"]
