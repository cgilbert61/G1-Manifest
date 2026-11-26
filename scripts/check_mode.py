"""Check G1-Manifest runtime mode and optional live HTTP endpoint health."""

from __future__ import annotations

import json
import sys
import urllib.request

from estate_graph import SCHEMA_VERSION, __version__


def main() -> int:
    url = sys.argv[1] if len(sys.argv) > 1 else None
    info = {
        "project": "G1-Manifest",
        "version": __version__,
        "schema_version": SCHEMA_VERSION,
        "mode": "offline-cli",
    }
    if url:
        with urllib.request.urlopen(url.rstrip("/") + "/health", timeout=3) as resp:
            info["mode"] = "http-witness-server"
            info["health"] = json.loads(resp.read())
    print(json.dumps(info, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
