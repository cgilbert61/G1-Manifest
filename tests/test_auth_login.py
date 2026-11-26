"""End-to-end tests for G1-Manifest Zero-Trust MFA Login Portal and RBAC."""

from __future__ import annotations

import http.cookiejar
import json
import threading
import urllib.error
import urllib.request

import pytest

from estate_graph.auth import ManifestAuthManager, pbkdf2_hex
from estate_graph.serve import make_handler, ThreadingHTTPServer


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _start_auth_server(tmp_path, *, production: bool = False):
    views_dir = tmp_path / "views"
    views_dir.mkdir(parents=True, exist_ok=True)
    (views_dir / "demo_view.html").write_text("<h1>VERIFIED WITNESS</h1>", encoding="utf-8")
    keys_dir = tmp_path / "keys"
    auth_mgr = ManifestAuthManager(production=production)
    handler = make_handler(
        views_dir, keys_dir, require_auth=True, auth_manager=auth_mgr
    )
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, server.server_address[1]


def test_login_portal_totp_push_rbac_and_logout(tmp_path):
    server, port = _start_auth_server(tmp_path)
    base = f"http://127.0.0.1:{port}"
    try:
        # 1. /health and /api/keys/public.pem remain accessible without auth
        with urllib.request.urlopen(f"{base}/health") as r:
            assert r.status == 200
            assert json.loads(r.read())["status"] == "ok"

        # 2. Unauthenticated GET / serves the MFA Login Portal
        with urllib.request.urlopen(f"{base}/") as r:
            html_body = r.read().decode("utf-8")
            assert "SecOps Administrative &amp; MFA Portal" in html_body
            assert "ops@g1163rt.ai" in html_body

        # 3. Unauthenticated GET /demo_view.html redirects 302 to /login
        no_redir = urllib.request.build_opener(_NoRedirect())
        with pytest.raises(urllib.error.HTTPError) as exc:
            no_redir.open(f"{base}/demo_view.html")
        assert exc.value.code == 302
        assert "/login" in exc.value.headers["Location"]

        # 4. Unauthenticated POST /api/scan/demo returns 401
        unauth_post = urllib.request.Request(
            f"{base}/api/scan/demo",
            data=b"{}",
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with pytest.raises(urllib.error.HTTPError) as exc401:
            urllib.request.urlopen(unauth_post)
        assert exc401.value.code == 401

        # 5. Wrong MFA code returns 401
        bad_login = urllib.request.Request(
            f"{base}/api/auth/login",
            data=json.dumps(
                {
                    "email": "ops@g1163rt.ai",
                    "password": "G1ManifestDemo2026!",
                    "mfa_code": "000000",
                }
            ).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with pytest.raises(urllib.error.HTTPError) as exc_mfa:
            urllib.request.urlopen(bad_login)
        assert exc_mfa.value.code == 401

        # 6. Valid PBKDF2 + 6-digit TOTP login sets HttpOnly cookie and unlocks Console & witness pages
        jar = http.cookiejar.CookieJar()
        opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
        good_login = urllib.request.Request(
            f"{base}/api/auth/login",
            data=json.dumps(
                {
                    "email": "ops@g1163rt.ai",
                    "password": "G1ManifestDemo2026!",
                    "mfa_code": "482910",
                }
            ).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with opener.open(good_login) as r:
            res = json.loads(r.read())
            assert res["authenticated"] is True
            assert res["principal"]["role"] == "AUTHORIZING_OFFICIAL"

        with opener.open(f"{base}/") as r:
            dash = r.read().decode("utf-8")
            assert "Available Witness Pages" in dash
            assert "ops@g1163rt.ai" in dash
            assert "Sign Out" in dash

        with opener.open(f"{base}/demo_view.html") as r:
            assert "VERIFIED WITNESS" in r.read().decode("utf-8")

        # 7. Downloaded macos scanner embeds X-Manifest-Ingest-Token that authorizes headless /api/ingest/host
        with opener.open(f"{base}/api/agent/macos.command") as r:
            cmd_text = r.read().decode("utf-8")
            assert "X-Manifest-Ingest-Token: g1m_ing_" in cmd_text
            ing_tok = cmd_text.split('X-Manifest-Ingest-Token: ')[1].split('"')[0]

        ingest_req = urllib.request.Request(
            f"{base}/api/ingest/host",
            data=json.dumps(
                {
                    "hostname": "SCAN-MAC",
                    "platform": "macos",
                    "app_records": [
                        {
                            "name": "Safari",
                            "version": "18.0",
                            "publisher": "com.apple.Safari",
                            "install_location": "/Applications/Safari.app",
                            "source": "macos-applications",
                        }
                    ],
                    "processes": [
                        {
                            "name": "Safari",
                            "modules": ["/Applications/Safari.app/Contents/MacOS/Safari"],
                        }
                    ],
                }
            ).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "X-Manifest-Ingest-Token": ing_tok,
            },
            method="POST",
        )
        with urllib.request.urlopen(ingest_req) as r:
            assert json.loads(r.read())["ok"] is True

        # 8. Federated Push challenge + number match works
        jar2 = http.cookiejar.CookieJar()
        op2 = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar2))
        ch_req = urllib.request.Request(
            f"{base}/api/auth/push-challenge",
            data=json.dumps(
                {
                    "email": "sre@g1163rt.ai",
                    "password": "G1ServiceOwner2026!",
                    "provider": "duo",
                }
            ).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with op2.open(ch_req) as r:
            ch = json.loads(r.read())
            assert len(ch["match_number"]) == 2

        ver_req = urllib.request.Request(
            f"{base}/api/auth/push-verify",
            data=json.dumps(
                {
                    "challenge_id": ch["challenge_id"],
                    "match_number": ch["match_number"],
                }
            ).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with op2.open(ver_req) as r:
            assert json.loads(r.read())["authenticated"] is True

        # 9. AUDITOR role can read witness pages but is blocked (403) on mutating routes
        jar_aud = http.cookiejar.CookieJar()
        op_aud = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar_aud))
        aud_login = urllib.request.Request(
            f"{base}/api/auth/login",
            data=json.dumps(
                {
                    "email": "auditor@g1163rt.ai",
                    "password": "G1Auditor2026!",
                    "mfa_code": "654321",
                }
            ).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with op_aud.open(aud_login) as r:
            assert json.loads(r.read())["principal"]["role"] == "AUDITOR"

        with op_aud.open(f"{base}/demo_view.html") as r:
            assert r.status == 200

        rot_req = urllib.request.Request(
            f"{base}/api/keys/rotate",
            data=b"{}",
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with pytest.raises(urllib.error.HTTPError) as exc_403:
            op_aud.open(rot_req)
        assert exc_403.value.code == 403

        # 10. Logout clears session cookie
        logout_req = urllib.request.Request(
            f"{base}/api/auth/logout",
            data=b"{}",
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with opener.open(logout_req) as r:
            assert json.loads(r.read())["authenticated"] is False
        with opener.open(f"{base}/api/auth/status") as r:
            assert json.loads(r.read())["authenticated"] is False
    finally:
        server.shutdown()
        server.server_close()


def test_production_posture_disables_demo_accounts_and_quick_login(tmp_path, monkeypatch):
    salt = "prod-salt-01"
    pw_hash = pbkdf2_hex("StrongProdPass2026!", salt)
    monkeypatch.setenv(
        "MANIFEST_CONSOLE_USERS_JSON",
        json.dumps(
            {
                "accounts": [
                    {
                        "email": "secops@agency.gov",
                        "display_name": "Agency SecOps",
                        "role": "OPERATOR",
                        "clearance": "SECRET",
                        "password_salt": salt,
                        "password_hash": pw_hash,
                        "mfa_code": "918273",
                        "mfa_enabled": True,
                    }
                ]
            }
        ),
    )
    server, port = _start_auth_server(tmp_path, production=True)
    base = f"http://127.0.0.1:{port}"
    try:
        with urllib.request.urlopen(f"{base}/api/auth/mfa-providers") as r:
            mfa = json.loads(r.read())
            assert mfa["demo_accounts_enabled"] is False
            assert mfa["demo_accounts"] == []

        quick_req = urllib.request.Request(
            f"{base}/api/auth/dev-quick-login",
            data=b"{}",
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with pytest.raises(urllib.error.HTTPError) as exc:
            urllib.request.urlopen(quick_req)
        assert exc.value.code == 403
    finally:
        server.shutdown()
        server.server_close()
