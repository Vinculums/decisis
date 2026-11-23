from __future__ import annotations

import io
import json
import os

import pytest

from decisis import checkout as co


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
