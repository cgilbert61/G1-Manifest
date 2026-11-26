"""Parsers: flow logs, Hubble, declared model, OpenLineage."""

from estate_graph.sources.declared import parse_declared
from estate_graph.sources.flowlog import parse_flow_logs
from estate_graph.sources.hubble import parse_hubble
from estate_graph.sources.lineage import parse_lineage

IP_MAP = {"10.0.1.10": "checkout-api", "10.0.1.11": "payments-api"}

FLOW_TEXT = """\
2 123456789012 eni-1 10.0.1.10 10.0.1.11 51234 8443 6 12 9840 1795680000 1795680120 ACCEPT OK
2 123456789012 eni-1 10.0.1.10 10.0.1.11 51235 8443 6 12 9840 1795683600 1795683720 ACCEPT OK
2 123456789012 eni-1 10.0.1.10 10.0.1.11 51236 8443 6 12 9840 1795687200 1795687320 ACCEPT OK
2 123456789012 eni-1 10.0.3.99 10.0.1.11 60123 22 6 3 180 1795690000 1795690060 REJECT OK
2 123456789012 eni-2 - - - - - - - - - NODATA
"""


def test_flowlog_aggregation_merges_and_windows():
    obs = parse_flow_logs(FLOW_TEXT, IP_MAP)
    assert len(obs) == 1
    o = obs[0]
    assert (o.source, o.target, o.port, o.protocol) == (
        "checkout-api",
        "payments-api",
        8443,
        "TCP",
    )
    assert o.count == 3
    assert o.first_seen == 1795680000
    assert o.last_seen == 1795687320
    assert o.origin == "vpc-flow-logs"


def test_flowlog_skips_reject_and_nodata():
    obs = parse_flow_logs(FLOW_TEXT, IP_MAP)
    assert all(o.target != "ip:10.0.3.99" for o in obs)
    assert all(o.source != "ip:10.0.3.99" for o in obs)


def test_flowlog_unmapped_ip_keeps_ip_identity():
    text = (
        "2 1 eni-1 10.0.1.10 203.0.113.66 49812 443 6 8 5120 "
        "1795658413 1795658458 ACCEPT OK\n"
    )
    obs = parse_flow_logs(text, IP_MAP)
    assert obs[0].target == "ip:203.0.113.66"


HUBBLE_APP_LABEL = """\
{"flow": {"source": {"pod_name": "web-abc", "namespace": "prod", "labels": ["k8s:app=checkout-api"]}, "destination": {"pod_name": "pay-abc", "namespace": "prod", "labels": ["k8s:app=payments-api"]}, "l4": {"TCP": {"destination_port": 8443}}, "verdict": "FORWARDED"}, "time": "2026-11-26T09:15:00Z"}
{"flow": {"source": {"pod_name": "web-abc", "namespace": "prod", "labels": ["k8s:app=checkout-api"]}, "destination": {"pod_name": "pay-abc", "namespace": "prod", "labels": ["k8s:app=payments-api"]}, "l4": {"TCP": {"destination_port": 8443}}, "verdict": "DROPPED"}, "time": "2026-11-26T09:16:00Z"}
"""


def test_hubble_identity_from_app_label_and_verdict_filter():
    obs = parse_hubble(HUBBLE_APP_LABEL)
    assert len(obs) == 1  # the DROPPED flow is not evidence
    o = obs[0]
    assert (o.source, o.target, o.port) == ("checkout-api", "payments-api", 8443)
    assert o.count == 1
    assert o.first_seen == 1795684500  # 2026-11-26T09:15:00Z


def test_hubble_pod_name_prefix_fallback():
    text = (
        '{"source": {"pod_name": "checkout-api-7d9f8c5b4-x2abc", '
        '"namespace": "prod", "labels": []}, '
        '"destination": {"pod_name": "ledger-db-0", "namespace": "prod", '
        '"labels": []}, "destination_port": 5432, "protocol": "TCP", '
        '"verdict": "FORWARDED"}\n'
    )
    obs = parse_hubble(text)
    assert obs[0].source == "checkout-api"
    assert obs[0].target == "ledger-db-0"  # statefulset pod: name kept whole
    assert obs[0].port == 5432


def test_declared_importer_pairs_and_ip_map():
    model = parse_declared(
        {
            "endpoints": {"10.0.0.1": "a"},
            "services": [
                {
                    "service_id": "a",
                    "addresses": ["10.0.0.2"],
                    "allowed_egress_services": ["b", "c"],
                },
                {"service_id": "b", "allowed_egress_services": []},
            ],
        }
    )
    assert model.pairs == {("a", "b"), ("a", "c")}
    assert model.ip_to_service == {"10.0.0.1": "a", "10.0.0.2": "a"}
    assert {n.id for n in model.nodes} == {"a", "b"}
    assert model.targets_of("a") == {"b", "c"}


def test_lineage_importer_marks_lineage_layer():
    edges, nodes = parse_lineage(
        {
            "eventType": "COMPLETE",
            "eventTime": "2026-11-26T03:05:00Z",
            "inputs": [{"namespace": "aws/s3", "name": "payments-events"}],
            "outputs": [{"namespace": "postgres/prod", "name": "ledger-db"}],
        }
    )
    assert len(edges) == 1
    e = edges[0]
    assert e.layer == "lineage"
    assert e.source == "aws/s3/payments-events"
    assert e.target == "postgres/prod/ledger-db"
    assert {n.kind for n in nodes} == {"dataset"}
