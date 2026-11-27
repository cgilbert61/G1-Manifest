# G1-Manifest Empirical Fuzz Testing Report

- **Generated:** `2026-11-27T14:44:06Z`
- **Environment:** Windows (`win32`), Python `3.13.9`, `pytest 9.2.0`, `hypothesis 6.170.19`
- **Repository:** `D:\Manifest\g1-estate-graph-prototype\g1-estate-graph`

## Fuzzer Execution Matrix

| Fuzzer | Scope | Status | Empirical Result |
| :--- | :--- | :--- | :--- |
| **Hypothesis** (`fuzz/test_hypothesis_fuzz.py`) | Property-based fuzzing across 10 untrusted-input & security-invariant targets | `EXECUTED` | **10/10 targets PASS** (`1,500` generated examples, `0` failures in `5.07s`) |
| **Atheris** (`fuzz/atheris_harnesses/`) | Coverage-guided `libFuzzer` across 4 harnesses (`fuzz_verify_envelope`, `fuzz_parsers`, `fuzz_render_html`, `fuzz_host_modules`) | `SKIPPED` | Docker Desktop daemon not running locally; wired into `.github/workflows/ci.yml` (`atheris-fuzz` job) and `fuzz/Dockerfile.atheris` |

## Hypothesis Per-Target Empirical Statistics

| Fuzz Target | Passing Examples | Failures | Generate Phase | Security Invariant Verified |
| :--- | ---: | ---: | ---: | :--- |
| `test_fuzz_verify_envelope_fails_closed_on_arbitrary_input` | 150 | 0 | `0.41s` | Arbitrary JSON/dict envelopes always raise `VerificationError` (fail-closed) |
| `test_fuzz_verify_envelope_structured_forgeries_rejected` | 150 | 0 | `0.33s` | Forged DSSE payloads/signatures never verify |
| `test_fuzz_parse_flow_logs_never_crashes` | 150 | 0 | `0.18s` | Arbitrary VPC Flow Log text never causes unhandled exceptions |
| `test_fuzz_parse_hubble_never_crashes` | 150 | 0 | `0.07s` | Arbitrary Hubble JSONL text (including non-dict JSON scalars) never crashes |
| `test_fuzz_parse_uninstall_keys_never_crashes` | 150 | 0 | `0.39s` | Arbitrary Windows Uninstall Registry records deduplicate cleanly without crashes |
| `test_fuzz_parse_distributions_never_crashes` | 150 | 0 | `0.49s` | Arbitrary `pip` metadata produces valid node/edge graphs with no self-loops |
| `test_fuzz_sideloaded_dll_never_masked_by_system_dll` | 150 | 0 | `0.26s` | User-directory DLL sharing a `System32` filename always surfaces as `HIGH` severity |
| `test_fuzz_render_html_deterministic_and_script_safe` | 150 | 0 | `0.24s` | Byte-identical rendering and zero unescaped `<` inside embedded JSON `<script>` block |
| `test_fuzz_safe_html_name_prevents_traversal` | 150 | 0 | `0.08s` | Sanitized view names always end in `.html` with no `/`, `\`, `..`, or null bytes |
| `test_fuzz_sign_verify_roundtrip` | 150 | 0 | `0.14s` | Ed25519 DSSE envelopes verify within TTL and fail closed at exact expiry boundary |

## Edge Cases Discovered & Remediated During Fuzzing

1. **Hubble JSONL non-dict scalar crash (`estate_graph/sources/hubble.py`):**
   - **Minimized failing input:** `text='0'`
   - **Failure:** `AttributeError: 'int' object has no attribute 'get'` when `json.loads(line)` returned a non-dict JSON value.
   - **Fix:** Added `isinstance(..., dict)` guards for `obj`, `flow`, `source`, and `destination`, plus safe `parse_ts` error handling.
2. **Repeated dots in sanitized HTML filenames (`estate_graph/serve.py`):**
   - **Minimized failing input:** `raw='0..0'`
   - **Failure:** `_safe_html_name()` returned `'0..0.html'`, leaving a `..` substring intact.
   - **Fix:** Collapsed consecutive `..` sequences in `_safe_html_name()` before stripping leading/trailing dots and dashes.

## Running Locally

```powershell
# Hypothesis (Windows / macOS / Linux)
.venv\Scripts\pytest -v --hypothesis-show-statistics fuzz/

# Atheris coverage-guided libFuzzer (requires Docker Desktop)
docker build -f fuzz/Dockerfile.atheris -t g1-manifest-fuzz:latest .
docker run --rm g1-manifest-fuzz:latest
```
