# Security Policy

## Supported Versions

| Version | Supported |
| :--- | :--- |
| `0.1.x` / `main` | Yes |

## Reporting a Vulnerability

Please report security vulnerabilities privately to **security@g1163rt.ai**.
Do **not** open a public GitHub issue for security vulnerabilities.

Include as much detail as possible:
- Affected component or endpoint (e.g., DSSE verification, `render.py` escaping, `serve.py` ingestion)
- Steps to reproduce or proof-of-concept payload
- Expected vs. actual security behavior

### Response SLA
- **Acknowledgment:** Within 48 hours
- **Triage & Severity Assessment:** Within 5 business days
- **Remediation / Coordinated Disclosure:** Targeted within 30 days for Critical/High findings

## Security Architecture Highlights
- Cryptographic signing uses **Ed25519** over **DSSEv1 PAE** (`application/vnd.g1163rt.estate-graph+json`).
- Verification fails closed on bad signatures, malformed envelopes, unknown schema versions, or expired graphs.
- Witness HTML rendering escapes all untrusted identifiers for HTML/SVG and Unicode-escapes `<`, `>`, `&` in embedded JSON blobs.
- Container runtime executes as non-root user `appuser`.
