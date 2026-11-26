"""Reproducible end-to-end G1-Manifest demo entrypoint (`python -m examples.run_demo`)."""

from __future__ import annotations

from estate_graph.cli import main


def run() -> int:
    return main(["demo"])


if __name__ == "__main__":
    raise SystemExit(run())
