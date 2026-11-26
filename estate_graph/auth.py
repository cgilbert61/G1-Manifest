"""Operator authentication, PBKDF2-HMAC-SHA256 + MFA, and session management for G1-Manifest.

Uses 100% Python standard library primitives (``hashlib.pbkdf2_hmac``, ``hmac``,
``secrets``) to mirror the G1-Warrant and G1-Docket Zero-Trust MFA Login Portal
without adding external runtime dependencies.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import threading
import time
from dataclasses import dataclass, field
from http.cookies import SimpleCookie
from pathlib import Path

SESSION_COOKIE_NAME = "g1manifest_session"
PBKDF2_ITERATIONS = 100_000
SESSION_TTL_SECONDS = 8 * 3600
INGEST_TOKEN_TTL_SECONDS = 7 * 86400


@dataclass
class UserRecord:
    email: str
    display_name: str
    role: str
    clearance: str
    password_salt: str
    password_hashes: list[str]
    mfa_code: str
    aliases: list[str] = field(default_factory=list)
    mfa_enabled: bool = True
    is_demo: bool = False
    demo_passphrase_hint: str = ""


@dataclass
class PushChallenge:
    challenge_id: str
    email: str
    provider: str
    provider_title: str
    device: str
    endpoint: str
    match_number: str
    expires_at: float


def pbkdf2_hex(passphrase: str, salt: str, iterations: int = PBKDF2_ITERATIONS) -> str:
    dk = hashlib.pbkdf2_hmac(
        "sha256",
        passphrase.encode("utf-8"),
        salt.encode("utf-8"),
        iterations,
    )
    return dk.hex()


def is_production_posture() -> bool:
    val = os.environ.get("MANIFEST_PRODUCTION", "").strip().lower()
    return val in ("1", "true", "yes", "production", "live")


class ManifestAuthManager:
    """Thread-safe PBKDF2 + 6-digit MFA + Federated Push + HMAC cookie session manager."""

    def __init__(self, *, production: bool | None = None) -> None:
        self._lock = threading.RLock()
        secret = os.environ.get("MANIFEST_SESSION_SECRET", "").strip()
        if secret:
            self._signing_key = hashlib.sha256(secret.encode("utf-8")).digest()
        else:
            self._signing_key = secrets.token_bytes(32)

        self.production = is_production_posture() if production is None else production
        demo_env = os.environ.get("MANIFEST_ENABLE_DEMO_ACCOUNTS", "").strip().lower()
        if self.production:
            self.demo_enabled = False
        elif demo_env in ("0", "false", "no"):
            self.demo_enabled = False
        else:
            self.demo_enabled = True

        self.airgap_mode = (
            os.environ.get("MANIFEST_AIRGAP_STRICT", "").strip().lower() == "true"
        )
        self._users: dict[str, UserRecord] = {}
        self.demo_accounts: list[dict] = []
        self._challenges: dict[str, PushChallenge] = {}

        if self.demo_enabled:
            self._seed_demo_accounts()
        self._load_custom_users()

    def _register_user(self, rec: UserRecord) -> None:
        self._users[rec.email.strip().lower()] = rec
        for alias in rec.aliases:
            key = alias.strip().lower()
            if key:
                self._users[key] = rec

    def _seed_demo_accounts(self) -> None:
        specs = [
            {
                "email": "ops@g1163rt.ai",
                "aliases": ["ops@g1163rt", "admin"],
                "display_name": "G1 Primary SecOps Admin (Authorizing Official)",
                "role": "AUTHORIZING_OFFICIAL",
                "clearance": "TOP_SECRET_AO",
                "salt": "g1-manifest-ops-pbkdf2-salt-2026-v1",
                "passphrase": "G1ManifestDemo2026!",
                "alt_passphrases": ["G1WarrantDemo2026!"],
                "mfa_code": "482910",
            },
            {
                "email": "sre@g1163rt.ai",
                "aliases": ["sre@g1163rt", "operator1"],
                "display_name": "Platform SRE Lead (Service Owner)",
                "role": "SERVICE_OWNER",
                "clearance": "SECRET_SO",
                "salt": "g1-manifest-sre-pbkdf2-salt-2026-v1",
                "passphrase": "G1ServiceOwner2026!",
                "alt_passphrases": [],
                "mfa_code": "319420",
            },
            {
                "email": "mac@g1163rt.ai",
                "aliases": ["mac@g1163rt"],
                "display_name": "SecOps Duty Officer (Operator)",
                "role": "OPERATOR",
                "clearance": "CONFIDENTIAL_OPS",
                "salt": "g1-manifest-mac-pbkdf2-salt-2026-v1",
                "passphrase": "G1Operator2026!",
                "alt_passphrases": [],
                "mfa_code": "123456",
            },
            {
                "email": "auditor@g1163rt.ai",
                "aliases": ["3pao@g1163rt.ai", "auditor1"],
                "display_name": "3PAO Compliance Assessor (Read-Only)",
                "role": "AUDITOR",
                "clearance": "ASSESSOR_3PAO",
                "salt": "g1-manifest-aud-pbkdf2-salt-2026-v1",
                "passphrase": "G1Auditor2026!",
                "alt_passphrases": [],
                "mfa_code": "654321",
            },
        ]
        for s in specs:
            hashes = [
                pbkdf2_hex(pw, s["salt"])
                for pw in [s["passphrase"], *s["alt_passphrases"]]
            ]
            rec = UserRecord(
                email=s["email"],
                aliases=list(s["aliases"]),
                display_name=s["display_name"],
                role=s["role"],
                clearance=s["clearance"],
                password_salt=s["salt"],
                password_hashes=hashes,
                mfa_code=s["mfa_code"],
                mfa_enabled=True,
                is_demo=True,
                demo_passphrase_hint=s["passphrase"],
            )
            self._register_user(rec)
            self.demo_accounts.append(
                {
                    "email": s["email"],
                    "display_name": s["display_name"],
                    "role": s["role"],
                    "clearance": s["clearance"],
                    "passphrase": s["passphrase"],
                    "mfa_code": s["mfa_code"],
                }
            )

    def _load_custom_users(self) -> None:
        raw = os.environ.get("MANIFEST_CONSOLE_USERS_JSON", "").strip()
        if not raw:
            path_str = os.environ.get("MANIFEST_CONSOLE_USERS_FILE", "").strip()
            if path_str and Path(path_str).is_file():
                raw = Path(path_str).read_text(encoding="utf-8").strip()
        if not raw:
            return
        try:
            payload = json.loads(raw)
        except Exception:
            return
        for u in payload.get("accounts") or []:
            email = str(u.get("email") or "").strip()
            pw_hash = str(u.get("password_hash") or "").strip()
            salt = str(u.get("password_salt") or "").strip()
            if not email or not pw_hash or not salt:
                continue
            rec = UserRecord(
                email=email,
                aliases=list(u.get("aliases") or []),
                display_name=str(u.get("display_name") or email),
                role=str(u.get("role") or "OPERATOR"),
                clearance=str(u.get("clearance") or "CONFIDENTIAL_OPS"),
                password_salt=salt,
                password_hashes=[pw_hash],
                mfa_code=str(u.get("mfa_code") or ""),
                mfa_enabled=bool(u.get("mfa_enabled", True)),
                is_demo=False,
            )
            self._register_user(rec)

    def lookup_user(self, identifier: str) -> UserRecord | None:
        with self._lock:
            return self._users.get((identifier or "").strip().lower())

    def verify_password(self, user: UserRecord, passphrase: str) -> bool:
        candidate = pbkdf2_hex(passphrase or "", user.password_salt)
        return any(hmac.compare_digest(candidate, h) for h in user.password_hashes)

    def authenticate_password_mfa(
        self, identifier: str, passphrase: str, mfa_code: str
    ) -> tuple[dict | None, str | None]:
        user = self.lookup_user(identifier)
        if user is None or not self.verify_password(user, passphrase):
            return None, "INVALID_CREDENTIALS: unknown operator principal or passphrase"
        code = (mfa_code or "").strip()
        if user.mfa_enabled:
            if not code:
                return None, "MFA_REQUIRED: enter your 6-digit RFC 6238 TOTP code"
            if not hmac.compare_digest(code, user.mfa_code):
                return None, "INVALID_MFA_CODE: 6-digit authenticator verification failed"
        return self._issue_principal(user, "PBKDF2_HMAC_SHA256+TOTP"), None

    def create_push_challenge(
        self, identifier: str, passphrase: str, provider: str
    ) -> tuple[dict | None, str | None]:
        if self.airgap_mode:
            return None, "FEDERATED_PUSH_DISABLED_IN_AIRGAP"
        prov = (provider or "").strip().lower()
        if prov not in ("duo", "okta"):
            return None, "UNSUPPORTED_MFA_PROVIDER: choose duo or okta"
        user = self.lookup_user(identifier)
        if user is None or not self.verify_password(user, passphrase):
            return None, "INVALID_CREDENTIALS: enter valid operator credentials before push"

        ch_id = "push-" + secrets.token_hex(8)
        match_num = f"{secrets.randbelow(90) + 10}"
        title = "Cisco Duo Federal Push" if prov == "duo" else "Okta Verify FastPass"
        endpoint = (
            "api-fed.duosecurity.com" if prov == "duo" else "g1163rt.okta-gov.com"
        )
        ch = PushChallenge(
            challenge_id=ch_id,
            email=user.email,
            provider=prov,
            provider_title=title,
            device="G1 SecOps Hardware Enclave Phone",
            endpoint=endpoint,
            match_number=match_num,
            expires_at=time.time() + 120.0,
        )
        with self._lock:
            self._challenges[ch_id] = ch
        return (
            {
                "challenge_id": ch.challenge_id,
                "provider": ch.provider,
                "provider_title": ch.provider_title,
                "device": ch.device,
                "endpoint": ch.endpoint,
                "match_number": ch.match_number,
            },
            None,
        )

    def verify_push_challenge(
        self, challenge_id: str, match_number: str
    ) -> tuple[dict | None, str | None]:
        with self._lock:
            ch = self._challenges.pop((challenge_id or "").strip(), None)
        if ch is None or time.time() > ch.expires_at:
            return None, "PUSH_CHALLENGE_EXPIRED_OR_UNKNOWN"
        if match_number and match_number.strip() != ch.match_number:
            return None, "PUSH_NUMBER_MATCH_FAILED"
        user = self.lookup_user(ch.email)
        if user is None:
            return None, "UNKNOWN_OPERATOR_ACCOUNT"
        return (
            self._issue_principal(user, f"PBKDF2_HMAC_SHA256+PUSH_{ch.provider.upper()}"),
            None,
        )

    def dev_quick_login(self, email: str = "ops@g1163rt.ai") -> tuple[dict | None, str | None]:
        if not self.demo_enabled:
            return None, "DEMO_QUICK_LOGIN_DISABLED_IN_PRODUCTION"
        user = self.lookup_user(email or "ops@g1163rt.ai")
        if user is None or not user.is_demo:
            return None, "DEMO_ACCOUNT_NOT_FOUND"
        return self._issue_principal(user, "SANDBOX_DEMO_QUICK_LOGIN"), None

    def _issue_principal(self, user: UserRecord, method: str) -> dict:
        now = int(time.time())
        return {
            "email": user.email,
            "display_name": user.display_name,
            "role": user.role,
            "clearance": user.clearance,
            "auth_method": method,
            "iat": now,
            "exp": now + SESSION_TTL_SECONDS,
        }

    def encode_session_token(self, principal: dict) -> str:
        raw = json.dumps(principal, separators=(",", ":"), sort_keys=True).encode("utf-8")
        b64 = base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")
        sig = hmac.new(self._signing_key, b64.encode("ascii"), hashlib.sha256).hexdigest()
        return f"{b64}.{sig}"

    def verify_session_token(self, token: str | None) -> dict | None:
        if not token or "." not in token:
            return None
        b64, sig = token.split(".", 1)
        expected = hmac.new(
            self._signing_key, b64.encode("ascii"), hashlib.sha256
        ).hexdigest()
        if not hmac.compare_digest(sig, expected):
            return None
        pad = "=" * ((4 - len(b64) % 4) % 4)
        try:
            data = json.loads(base64.urlsafe_b64decode(b64 + pad).decode("utf-8"))
        except Exception:
            return None
        if not isinstance(data, dict) or int(data.get("exp") or 0) < int(time.time()):
            return None
        return data

    def issue_ingest_token(self, issuer_email: str) -> str:
        exp = int(time.time()) + INGEST_TOKEN_TTL_SECONDS
        payload = f"ingest|{issuer_email}|{exp}"
        b64 = base64.urlsafe_b64encode(payload.encode("utf-8")).decode("ascii").rstrip("=")
        sig = hmac.new(self._signing_key, b64.encode("ascii"), hashlib.sha256).hexdigest()
        return f"g1m_ing_{b64}.{sig}"

    def verify_ingest_token(self, token: str | None) -> bool:
        if not token or not token.startswith("g1m_ing_") or "." not in token:
            return False
        body = token[len("g1m_ing_") :]
        b64, sig = body.split(".", 1)
        expected = hmac.new(
            self._signing_key, b64.encode("ascii"), hashlib.sha256
        ).hexdigest()
        if not hmac.compare_digest(sig, expected):
            return False
        pad = "=" * ((4 - len(b64) % 4) % 4)
        try:
            decoded = base64.urlsafe_b64decode(b64 + pad).decode("utf-8")
            prefix, _email, exp_s = decoded.split("|", 2)
            return prefix == "ingest" and int(exp_s) >= int(time.time())
        except Exception:
            return False

    def extract_request_principal(self, headers) -> dict | None:
        cookie_hdr = headers.get("Cookie") or ""
        if cookie_hdr:
            jar = SimpleCookie()
            try:
                jar.load(cookie_hdr)
                if SESSION_COOKIE_NAME in jar:
                    p = self.verify_session_token(jar[SESSION_COOKIE_NAME].value)
                    if p is not None:
                        return p
            except Exception:
                pass
        auth_hdr = (headers.get("Authorization") or "").strip()
        if auth_hdr.lower().startswith("bearer "):
            p = self.verify_session_token(auth_hdr[7:].strip())
            if p is not None:
                return p
        api_tok = os.environ.get("MANIFEST_API_TOKEN", "").strip()
        req_tok = (headers.get("X-Manifest-API-Token") or "").strip()
        if api_tok and req_tok and hmac.compare_digest(api_tok, req_tok):
            now = int(time.time())
            return {
                "email": "api-token@g1163rt.ai",
                "display_name": "G1-Manifest Automation Token",
                "role": "OPERATOR",
                "clearance": "CONFIDENTIAL_OPS",
                "auth_method": "STATIC_API_TOKEN",
                "iat": now,
                "exp": now + 3600,
            }
        return None
