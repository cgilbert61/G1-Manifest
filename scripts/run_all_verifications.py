"""Run all G1-Manifest verifications and write reports/verification_scorecard.json."""

from __future__ import annotations

import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _run(cmd: list[str]) -> dict:
    proc = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True)
    return {
        "command": " ".join(cmd),
        "returncode": proc.returncode,
        "status": "PASS" if proc.returncode == 0 else "FAIL",
        "tail": (proc.stdout + proc.stderr).strip().splitlines()[-5:],
    }


def main() -> int:
    checks = {
        "unit_and_integration_tests": _run([sys.executable, "-m", "pytest", "-q", "tests/"]),
        "consumer_conformance": _run([sys.executable, "-m", "pytest", "-q", "conformance/"]),
        "end_to_end_demo": _run([sys.executable, "-m", "examples.run_demo"]),
        "compliance_harness": _run([sys.executable, "scripts/compliance_harness.py"]),
    }

    sys.path.insert(0, str(ROOT))
    from benchmarks.bench_graph import run_benchmark

    bench = run_benchmark(iterations=25)
    overall = "PASS" if all(c["status"] == "PASS" for c in checks.values()) else "FAIL"
    scorecard = {
        "project": "G1-Manifest",
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "overall": overall,
        "executed_checks": checks,
        "benchmarks": bench,
    }
    reports_dir = ROOT / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    out = reports_dir / "verification_scorecard.json"
    out.write_text(json.dumps(scorecard, indent=2) + "\n", encoding="utf-8")
    print(f"Verification scorecard ({overall}) -> {out}")
    return 0 if overall == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
