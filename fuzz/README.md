# G1-Manifest Fuzz Testing (`Hypothesis` + `Atheris`)

G1-Manifest ships with two complementary Python fuzzing layers covering all untrusted-input boundaries (`verify_envelope`, telemetry parsers, host/DLL reconciliation, HTML/SVG witness rendering, and HTTP path sanitization):

## 1. Property-Based Fuzzing (`Hypothesis` — Windows, macOS, Linux, CI)

```bash
pip install -e ".[host,fuzz]" pytest
pytest -v fuzz/
```

## 2. Coverage-Guided Fuzzing (`Atheris` / `libFuzzer` — Linux / Docker)

```bash
docker build -f fuzz/Dockerfile.atheris -t g1-manifest-fuzz:latest .
docker run --rm g1-manifest-fuzz:latest
# Or run longer sessions:
docker run --rm g1-manifest-fuzz:latest python fuzz/run_atheris.py --runs 25000
```
