# Contributing to G1-Manifest

Thank you for contributing to **G1-Manifest** by **G1163RT Security Labs**.

## Development Setup

```bash
python3 -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e ".[host]" pytest
pytest -v
```

## Architectural Invariants

All contributions MUST preserve the core G1-Manifest invariants:

1. **Evidence Over Declaration:** Every edge carries empirical evidence (counts, first/last seen, sources) — never opinions or silently auto-promoted declarations.
2. **Fail-Closed Verification:** Consumers verify Ed25519 DSSE envelopes and reject bad signatures, unsupported schema versions, or expired graphs without fallback.
3. **Deterministic Rendering & Serialization:** Canonical JSON (`sort_keys=True`, compact separators) and deterministic layered SVG layout must produce byte-identical output for identical inputs.
4. **Offline-Safe Witness Pages:** Rendered `.html` witness pages must remain standalone, read-only, zero-external-asset documents that testify even with JavaScript disabled.
5. **Empirical-Only Reporting:** Compliance harnesses and benchmarks must separate executed checks from narrative mappings and never report `PASS` for unexecuted checks.
6. **UTF-8 Everywhere & Least Privilege:** All file I/O specifies `encoding="utf-8"`, generated private keys are `0600` on POSIX, and containers run as non-root.

## Pull Request Checklist

- [ ] `pytest -v` passes with zero failures (including `tests/` and `conformance/`)
- [ ] `python scripts/run_all_verifications.py` completes cleanly
- [ ] No secrets, private keys, or hardcoded credentials committed
- [ ] Documentation and schemas updated for any contract or CLI changes
- [ ] PR description explains *why* the change is needed and how it was verified
