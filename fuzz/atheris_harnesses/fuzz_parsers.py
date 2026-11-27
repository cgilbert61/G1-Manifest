"""Atheris coverage-guided fuzzer for telemetry parsers (flow logs, Hubble, lineage)."""

import json
import sys

import atheris

with atheris.instrument_imports():
    from estate_graph.sources.flowlog import parse_flow_logs
    from estate_graph.sources.hubble import parse_hubble
    from estate_graph.sources.lineage import parse_lineage


def TestOneInput(data: bytes) -> None:  # noqa: N802
    fdp = atheris.FuzzedDataProvider(data)
    text = fdp.ConsumeUnicodeNoSurrogates(512)
    parse_flow_logs(text, {"10.0.0.1": "checkout-api", "10.0.0.2": "payments-api"})
    parse_hubble(text)
    try:
        parsed = json.loads(text)
    except Exception:
        return
    if isinstance(parsed, dict):
        try:
            parse_lineage(parsed)
        except (TypeError, ValueError, AttributeError):
            pass


if __name__ == "__main__":
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()
