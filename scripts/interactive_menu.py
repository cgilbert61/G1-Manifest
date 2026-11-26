"""Interactive Operator & Auditor Control Menu for G1-Manifest."""

from __future__ import annotations

import subprocess
import sys

MENU = """
=== G1-Manifest Operator & Auditor Menu ===
1. Run end-to-end demo estate pipeline
2. Run local host scan (scan-host -> host-graph.json)
3. Start lightweight HTML witness viewer (port 8088)
4. Run full pytest + conformance suite
5. Run all verifications & generate scorecard
0. Exit
"""


def main() -> int:
    while True:
        print(MENU)
        choice = input("Select option: ").strip()
        if choice == "1":
            subprocess.run([sys.executable, "-m", "examples.run_demo"], check=False)
        elif choice == "2":
            subprocess.run(
                [sys.executable, "-m", "estate_graph.cli", "scan-host", "--out", "host-graph.json"],
                check=False,
            )
        elif choice == "3":
            subprocess.run(
                [sys.executable, "-m", "estate_graph.cli", "serve", "--dir", "views", "--port", "8088", "--demo"],
                check=False,
            )
        elif choice == "4":
            subprocess.run([sys.executable, "-m", "pytest", "-v"], check=False)
        elif choice == "5":
            subprocess.run([sys.executable, "scripts/run_all_verifications.py"], check=False)
        elif choice == "0":
            return 0
        else:
            print("Invalid selection.")


if __name__ == "__main__":
    raise SystemExit(main())
