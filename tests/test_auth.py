"""Tests for authenticated scanning feature."""

from __future__ import annotations

import httpx
import pytest
from pydantic import ValidationError

from infraprobe.http import _strip_auth_on_cross_origin_redirect, scanner_client
from infraprobe.models import (
    BasicAuth,
    BearerAuth,
    CookieAuth,
    HeaderAuth,
    ScanRequest,
    SingleCheckRequest,
)

# ---------------------------------------------------------------------------
# Model validation
# ---------------------------------------------------------------------------


class TestAuthModels:
    def test_header_auth_valid(self):
        auth = HeaderAuth(type="header", headers={"X-API-Key": "abc123"})
        assert auth.headers == {"X-API-Key": "abc123"}

    def test_header_auth_multiple_headers(self):
        auth = HeaderAuth(type="header", headers={"Authorization": "Bearer tok", "X-Custom": "val"})
        assert len(auth.headers) == 2

    def test_header_auth_empty_headers_rejected(self):
        with pytest.raises(ValidationError):
            HeaderAuth(type="header", headers={})

    def test_header_auth_too_many_headers_rejected(self):
        headers = {f"X-Header-{i}": f"val{i}" for i in range(11)}
        with pytest.raises(ValidationError):
            HeaderAuth(type="header", headers=headers)

    def test_header_auth_hop_by_hop_host_rejected(self):
        with pytest.raises(ValidationError, match="[Ff]orbidden"):
            HeaderAuth(type="header", headers={"Host": "evil.com"})

    def test_header_auth_hop_by_hop_content_length_rejected(self):
        with pytest.raises(ValidationError, match="[Ff]orbidden"):
            HeaderAuth(type="header", headers={"Content-Length": "0"})

    def test_header_auth_hop_by_hop_transfer_encoding_rejected(self):
        with pytest.raises(ValidationError, match="[Ff]orbidden"):
            HeaderAuth(type="header", headers={"Transfer-Encoding": "chunked"})

    def test_header_auth_hop_by_hop_connection_rejected(self):
        with pytest.raises(ValidationError, match="[Ff]orbidden"):
            HeaderAuth(type="header", headers={"Connection": "keep-alive"})

    def test_header_auth_hop_by_hop_case_insensitive(self):
        with pytest.raises(ValidationError, match="[Ff]orbidden"):
            HeaderAuth(type="header", headers={"HOST": "evil.com"})

    def test_basic_auth_valid(self):
        auth = BasicAuth(type="basic", username="admin", password="pass123")
        assert auth.username == "admin"
        assert auth.password == "pass123"

    def test_basic_auth_username_too_long(self):
        with pytest.raises(ValidationError):
            BasicAuth(type="basic", username="a" * 257, password="ok")

    def test_basic_auth_password_too_long(self):
        with pytest.raises(ValidationError):
            BasicAuth(type="basic", username="ok", password="p" * 257)

    def test_bearer_auth_valid(self):
        auth = BearerAuth(type="bearer", token="eyJhbGciOiJIUzI1NiIs")
        assert auth.token == "eyJhbGciOiJIUzI1NiIs"

    def test_bearer_auth_token_too_long(self):
        with pytest.raises(ValidationError):
            BearerAuth(type="bearer", token="t" * 8193)

    def test_cookie_auth_valid(self):
        auth = CookieAuth(type="cookie", cookies={"session_id": "abc123"})
        assert auth.cookies == {"session_id": "abc123"}

    def test_cookie_auth_empty_rejected(self):
        with pytest.raises(ValidationError):
            CookieAuth(type="cookie", cookies={})

    def test_cookie_auth_too_many_rejected(self):
        cookies = {f"cookie_{i}": f"val{i}" for i in range(21)}
        with pytest.raises(ValidationError):
            CookieAuth(type="cookie", cookies=cookies)


# ---------------------------------------------------------------------------
# Discriminated union parsing
# ---------------------------------------------------------------------------


class TestAuthConfigDiscriminator:
    def test_parse_bearer_from_dict(self):
        req = SingleCheckRequest(target="example.com", auth={"type": "bearer", "token": "tok123"})
        assert isinstance(req.auth, BearerAuth)
        assert req.auth.token == "tok123"

    def test_parse_basic_from_dict(self):
        req = SingleCheckRequest(target="example.com", auth={"type": "basic", "username": "u", "password": "p"})
        assert isinstance(req.auth, BasicAuth)

    def test_parse_header_from_dict(self):
        req = SingleCheckRequest(target="example.com", auth={"type": "header", "headers": {"X-Key": "val"}})
        assert isinstance(req.auth, HeaderAuth)

    def test_parse_cookie_from_dict(self):
        req = SingleCheckRequest(target="example.com", auth={"type": "cookie", "cookies": {"s": "v"}})
        assert isinstance(req.auth, CookieAuth)

    def test_invalid_type_rejected(self):
        with pytest.raises(ValidationError):
            SingleCheckRequest(target="example.com", auth={"type": "oauth2", "token": "x"})

    def test_auth_none_by_default(self):
        req = SingleCheckRequest(target="example.com")
        assert req.auth is None

    def test_auth_on_scan_request(self):
        req = ScanRequest(targets=["example.com"], auth={"type": "bearer", "token": "tok"})
        assert isinstance(req.auth, BearerAuth)

    def test_auth_on_scan_request_with_checks(self):
        req = ScanRequest(targets=["example.com"], checks=["headers"], auth={"type": "bearer", "token": "tok"})
        assert isinstance(req.auth, BearerAuth)


# ---------------------------------------------------------------------------
# exclude=True — auth must not appear in serialized output
# ---------------------------------------------------------------------------


class TestAuthExclude:
    def test_single_check_request_excludes_auth(self):
        req = SingleCheckRequest(target="example.com", auth={"type": "bearer", "token": "secret"})
        dumped = req.model_dump()
        assert "auth" not in dumped

    def test_scan_request_excludes_auth(self):
        req = ScanRequest(targets=["example.com"], auth={"type": "basic", "username": "u", "password": "p"})
        dumped = req.model_dump()
        assert "auth" not in dumped

    def test_scan_request_with_checks_excludes_auth(self):
        req = ScanRequest(targets=["example.com"], checks=["headers"], auth={"type": "bearer", "token": "tok"})
        dumped = req.model_dump()
        assert "auth" not in dumped

    def test_scan_request_json_excludes_auth(self):
        req = ScanRequest(targets=["example.com"], auth={"type": "bearer", "token": "secret"})
        json_str = req.model_dump_json()
        assert "secret" not in json_str
        assert "auth" not in json_str


# ---------------------------------------------------------------------------
# scanner_client() auth application
# ---------------------------------------------------------------------------


class TestScannerClientAuth:
    def test_no_auth(self):
        client = scanner_client(5.0)
        assert "authorization" not in {k.lower() for k in client.headers}

    def test_bearer_auth_sets_header(self):
        auth = BearerAuth(type="bearer", token="mytoken123")
        client = scanner_client(5.0, auth=auth)
        assert client.headers["authorization"] == "Bearer mytoken123"

    def test_header_auth_sets_custom_headers(self):
        auth = HeaderAuth(type="header", headers={"X-API-Key": "key123", "X-Custom": "val"})
        client = scanner_client(5.0, auth=auth)
        assert client.headers["x-api-key"] == "key123"
        assert client.headers["x-custom"] == "val"

    def test_basic_auth_sets_auth(self):
        auth = BasicAuth(type="basic", username="user", password="pass")
        client = scanner_client(5.0, auth=auth)
        # httpx stores BasicAuth in _auth, and applies it per-request
        assert client._auth is not None

    def test_cookie_auth_sets_cookies(self):
        auth = CookieAuth(type="cookie", cookies={"session": "abc"})
        client = scanner_client(5.0, auth=auth)
        assert client.cookies.get("session") == "abc"

    def test_auth_enables_redirect_stripping_hook(self):
        auth = BearerAuth(type="bearer", token="tok")
        client = scanner_client(5.0, auth=auth)
        assert _strip_auth_on_cross_origin_redirect in client._event_hooks["response"]

    def test_no_auth_no_redirect_hook(self):
        client = scanner_client(5.0)
        hooks = client._event_hooks.get("response", [])
        assert _strip_auth_on_cross_origin_redirect not in hooks


# ---------------------------------------------------------------------------
# Cross-origin redirect credential stripping
# ---------------------------------------------------------------------------


class TestCrossOriginRedirectStripping:
    async def test_same_origin_keeps_auth(self):
        request = httpx.Request("GET", "https://example.com/page1")
        next_request = httpx.Request("GET", "https://example.com/page2", headers={"Authorization": "Bearer tok"})
        response = httpx.Response(302, request=request)
        response.next_request = next_request  # httpx internal, but we need it for testing

        await _strip_auth_on_cross_origin_redirect(response)
        assert "authorization" in next_request.headers

    async def test_cross_origin_strips_auth(self):
        request = httpx.Request("GET", "https://example.com/page1")
        next_request = httpx.Request(
            "GET",
            "https://evil.com/steal",
            headers={"Authorization": "Bearer tok", "Cookie": "session=abc"},
        )
        response = httpx.Response(302, request=request)
        response.next_request = next_request

        await _strip_auth_on_cross_origin_redirect(response)
        assert "authorization" not in next_request.headers
        assert "cookie" not in next_request.headers

    async def test_no_next_request_is_noop(self):
        request = httpx.Request("GET", "https://example.com/page1")
        response = httpx.Response(200, request=request)
        # next_request is None by default
        await _strip_auth_on_cross_origin_redirect(response)  # should not raise


# ---------------------------------------------------------------------------
# End-to-end API tests
# ---------------------------------------------------------------------------

pytestmark_integration = pytest.mark.integration


class TestAuthAPI:
    """API-level tests that auth field is accepted and doesn't break responses."""

    def test_scan_accepts_auth_field(self, client):
        """POST /v1/scan with auth field doesn't blow up (uses DNS check which ignores auth)."""
        resp = client.post(
            "/v1/scan",
            json={
                "targets": ["example.com"],
                "checks": ["dns"],
                "auth": {"type": "bearer", "token": "test-token"},
            },
        )
        assert resp.status_code == 202
        # Auth should not appear in response
        assert "auth" not in resp.text or '"auth"' not in resp.text

    def test_single_check_accepts_auth_field(self, client):
        """POST /v1/check/dns with auth field works (DNS ignores auth)."""
        resp = client.post(
            "/v1/check/dns",
            json={
                "target": "example.com",
                "auth": {"type": "basic", "username": "user", "password": "pass"},
            },
        )
        assert resp.status_code == 200

    def test_scan_without_auth_still_works(self, client):
        """Existing behavior — no auth field, still works."""
        resp = client.post(
            "/v1/scan",
            json={"targets": ["example.com"], "checks": ["dns"]},
        )
        assert resp.status_code == 202

    def test_invalid_auth_type_rejected(self, client):
        """Invalid auth type returns 422."""
        resp = client.post(
            "/v1/check/dns",
            json={
                "target": "example.com",
                "auth": {"type": "oauth2", "token": "x"},
            },
        )
        assert resp.status_code == 422

    def test_auth_excluded_from_async_job_response(self, client):
        """POST /v1/scan with auth → GET /v1/scan/{job_id} shouldn't leak auth."""
        resp = client.post(
            "/v1/scan",
            json={
                "targets": ["example.com"],
                "checks": ["dns"],
                "auth": {"type": "bearer", "token": "super-secret-token"},
            },
        )
        assert resp.status_code == 202
        job_id = resp.json()["job_id"]

        # Poll for result — the token must not appear
        import time

        for _ in range(20):
            poll = client.get(f"/v1/scan/{job_id}")
            if poll.json()["status"] in ("completed", "failed"):
                break
            time.sleep(0.3)

        poll_data = poll.text
        assert "super-secret-token" not in poll_data

    def test_scan_domain_accepts_auth(self, client):
        resp = client.post(
            "/v1/scan",
            json={
                "targets": ["example.com"],
                "checks": ["dns"],
                "auth": {"type": "bearer", "token": "tok"},
            },
        )
        assert resp.status_code == 202

    def test_check_domain_accepts_auth(self, client):
        resp = client.post(
            "/v1/check/dns",
            json={
                "target": "example.com",
                "auth": {"type": "bearer", "token": "tok"},
            },
        )
        assert resp.status_code == 200

    def test_hop_by_hop_header_rejected_via_api(self, client):
        resp = client.post(
            "/v1/check/dns",
            json={
                "target": "example.com",
                "auth": {"type": "header", "headers": {"Host": "evil.com"}},
            },
        )
        assert resp.status_code == 422
