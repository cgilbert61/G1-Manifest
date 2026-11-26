from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
DEMO = ROOT / "examples" / "demo_estate"


@pytest.fixture(scope="session")
def demo_dir():
    return DEMO


@pytest.fixture(scope="session")
def declared(demo_dir):
    from estate_graph.sources.declared import load_declared

    return load_declared(demo_dir / "declared_model.json")


@pytest.fixture()
def demo_graph(demo_dir, declared):
    # Function-scoped on purpose: signing a graph sets its expiry in place,
    # and tests must not inherit each other's mutations.
    from estate_graph.aggregate import aggregate
    from estate_graph.sources.flowlog import load_flow_logs
    from estate_graph.sources.hubble import load_hubble
    from estate_graph.sources.lineage import load_lineage

    observations = load_flow_logs(
        demo_dir / "vpc_flow_logs.txt", declared.ip_to_service
    ) + load_hubble(demo_dir / "hubble.jsonl")
    lineage_edges, lineage_nodes = load_lineage(demo_dir / "lineage.json")
    return aggregate(
        observations,
        declared_nodes=declared.nodes,
        extra_edges=lineage_edges,
        extra_nodes=lineage_nodes,
        issued_at=1795716000,  # 2026-11-26T18:00:00Z, fixed for stability
    )
