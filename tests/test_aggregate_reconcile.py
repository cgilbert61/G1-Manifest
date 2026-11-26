"""Aggregation evidence merging, rare-flow protection, reconciliation."""

from estate_graph.aggregate import aggregate
from estate_graph.model import FlowObservation
from estate_graph.reconcile import reconcile


def _obs(source, target, count, first, last, origin, port=443):
    return FlowObservation(
        source=source,
        target=target,
        port=port,
        protocol="TCP",
        count=count,
        first_seen=first,
        last_seen=last,
        origin=origin,
    )


def test_aggregate_merges_evidence_across_sources():
    graph = aggregate(
        [
            _obs("a", "b", 4, 100, 400, "vpc-flow-logs"),
            _obs("a", "b", 3, 50, 900, "hubble"),
        ],
        issued_at=1000,
    )
    assert len(graph.edges) == 1
    ev = graph.edges[0].evidence
    assert ev.flow_count == 7
    assert ev.first_seen == 50
    assert ev.last_seen == 900
    assert ev.sources == ["hubble", "vpc-flow-logs"]
    assert ev.window_seconds == 850


def test_aggregate_low_frequency_flag_keeps_rare_edge():
    graph = aggregate(
        [_obs("a", "ip:203.0.113.66", 1, 10, 20, "vpc-flow-logs")],
        issued_at=1000,
        low_frequency_threshold=3,
    )
    assert len(graph.edges) == 1  # kept, not dropped
    assert graph.edges[0].low_frequency is True
    node = graph.node("ip:203.0.113.66")
    assert node is not None and node.kind == "external"


def test_aggregate_frequent_edge_not_flagged():
    graph = aggregate(
        [_obs("a", "b", 10, 10, 20, "vpc-flow-logs")], issued_at=1000
    )
    assert graph.edges[0].low_frequency is False


def test_demo_reconcile_three_buckets(demo_graph, declared):
    report = reconcile(demo_graph, declared)
    assert report["summary"] == {
        "confirmed": 6,
        "observed_undeclared": 1,
        "declared_unobserved": 1,
    }
    confirmed = {(c["source"], c["target"]) for c in report["confirmed"]}
    assert ("checkout-api", "payments-api") in confirmed
    assert ("auth-service", "ledger-db") in confirmed


def test_demo_reconcile_catches_undeclared_license_flow(demo_graph, declared):
    report = reconcile(demo_graph, declared)
    findings = report["observed_undeclared"]
    assert len(findings) == 1
    f = findings[0]
    assert f["source"] == "checkout-api"
    assert f["target"] == "ip:203.0.113.66"
    assert f["severity"] == "high"  # external, unknown endpoint
    assert f["target_kind"] == "external"
    obs = f["observations"][0]
    assert obs["flow_count"] == 1
    assert obs["first_seen"] == 1795658413  # 2026-11-26T02:00:13Z — 2 a.m.


def test_demo_reconcile_declared_unobserved_is_analytics(demo_graph, declared):
    report = reconcile(demo_graph, declared)
    stale = report["declared_unobserved"]
    assert [(s["source"], s["target"]) for s in stale] == [
        ("payments-api", "analytics-api")
    ]


def test_demo_graph_merges_flowlog_and_hubble_evidence(demo_graph):
    edge = next(
        e
        for e in demo_graph.network_edges()
        if e.pair() == ("checkout-api", "payments-api")
    )
    assert edge.evidence.flow_count == 9  # 6 flow-log + 3 hubble
    assert edge.evidence.sources == ["hubble", "vpc-flow-logs"]


def test_demo_graph_keeps_lineage_on_its_own_layer(demo_graph):
    lineage = [e for e in demo_graph.edges if e.layer == "lineage"]
    assert len(lineage) == 1
    assert lineage[0].source == "aws/s3/payments-events"
    assert lineage[0].target == "postgres/prod/ledger-db"
    # Lineage never leaks into the network reconciliation surface.
    assert all(
        e.layer == "network" for e in demo_graph.network_edges()
    )
