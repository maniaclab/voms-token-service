"""Integration tests for POST /v1/mint through the ASGI stack.

The voms-proxy-init the app invokes is a real executable shell script on
PATH (see conftest) — nothing is mocked at the Python level.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

import pytest
from structlog.testing import capture_logs

from tests.conftest import FAKE_CORRECT_PASSPHRASE, _install_fake_bin
from voms_token_service import app as app_module
from voms_token_service.config import Settings
from voms_token_service.minting import CredentialPermissionsError

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

    import httpx

    from tests.conftest import FakeVomsProxyInit


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _body(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "unixname": "gstark",
        "uid": 12345,
        "gid": 12345,
        "passphrase": FAKE_CORRECT_PASSPHRASE,
    }
    payload.update(overrides)
    return payload


def _audit_events(cap_logs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [entry for entry in cap_logs if entry.get("event") == "audit"]


@pytest.mark.usefixtures("fake_voms_proxy_init")
class TestHappyPath:
    async def test_returns_minted_proxy(
        self, client: httpx.AsyncClient, make_token: Callable[..., str]
    ) -> None:
        resp = await client.post("/v1/mint", headers=_auth(make_token()), json=_body())
        assert resp.status_code == 200
        body = resp.json()
        assert "BEGIN CERTIFICATE" in body["pem"]
        assert body["dn"]
        assert isinstance(body["voms_attributes"], list)

    async def test_expires_at_is_iso8601_utc_in_the_future(
        self, client: httpx.AsyncClient, make_token: Callable[..., str]
    ) -> None:
        resp = await client.post("/v1/mint", headers=_auth(make_token()), json=_body())
        expires_at = datetime.fromisoformat(resp.json()["expires_at"])
        assert expires_at.tzinfo is not None
        assert expires_at > datetime.now(UTC)

    async def test_default_voms_and_valid_are_used_when_omitted(
        self,
        client: httpx.AsyncClient,
        make_token: Callable[..., str],
        fake_voms_proxy_init: FakeVomsProxyInit,
    ) -> None:
        resp = await client.post("/v1/mint", headers=_auth(make_token()), json=_body())
        assert resp.status_code == 200
        recorded = fake_voms_proxy_init.args_file.read_text().split()
        assert recorded[recorded.index("--voms") + 1] == "atlas"
        assert recorded[recorded.index("--valid") + 1] == "192:00"

    async def test_explicit_voms_and_valid_override_defaults(
        self,
        client: httpx.AsyncClient,
        make_token: Callable[..., str],
        fake_voms_proxy_init: FakeVomsProxyInit,
    ) -> None:
        resp = await client.post(
            "/v1/mint",
            headers=_auth(make_token()),
            json=_body(voms="cms", valid="24:00"),
        )
        assert resp.status_code == 200
        recorded = fake_voms_proxy_init.args_file.read_text().split()
        assert recorded[recorded.index("--voms") + 1] == "cms"
        assert recorded[recorded.index("--valid") + 1] == "24:00"

    async def test_home_paths_use_unixname_from_body(
        self,
        client: httpx.AsyncClient,
        make_token: Callable[..., str],
        settings: Settings,
        fake_voms_proxy_init: FakeVomsProxyInit,
    ) -> None:
        await client.post(
            "/v1/mint",
            headers=_auth(make_token()),
            json=_body(unixname="alice"),
        )
        recorded = fake_voms_proxy_init.args_file.read_text().split()
        assert recorded[recorded.index("--cert") + 1] == (
            f"{settings.home_root}/alice/.globus/usercert.pem"
        )
        assert recorded[recorded.index("--key") + 1] == (
            f"{settings.home_root}/alice/.globus/userkey.pem"
        )

    async def test_audit_line_carries_required_fields(
        self, client: httpx.AsyncClient, make_token: Callable[..., str]
    ) -> None:
        with capture_logs() as cap_logs:
            resp = await client.post(
                "/v1/mint",
                headers={**_auth(make_token()), "X-Request-ID": "req-42"},
                json=_body(),
            )
        assert resp.status_code == 200
        (audit,) = _audit_events(cap_logs)
        assert audit["subject"] == "af-user-subject"
        assert audit["unixname"] == "gstark"
        assert audit["outcome"] == "issued"
        assert audit["jti"]
        assert audit["request_id"] == "req-42"
        assert audit["dn_sha256"]

    async def test_no_log_line_ever_contains_the_passphrase_or_pem(
        self, client: httpx.AsyncClient, make_token: Callable[..., str]
    ) -> None:
        broker_token = make_token()
        with capture_logs() as cap_logs:
            resp = await client.post(
                "/v1/mint", headers=_auth(broker_token), json=_body()
            )
        assert resp.status_code == 200
        logged = repr(cap_logs)
        assert FAKE_CORRECT_PASSPHRASE not in logged
        assert broker_token not in logged
        assert "BEGIN CERTIFICATE" not in logged
        assert resp.json()["dn"] not in logged


class TestAuthenticationFailures:
    async def test_missing_authorization_header_is_401(
        self, client: httpx.AsyncClient
    ) -> None:
        resp = await client.post("/v1/mint", json=_body())
        assert resp.status_code == 401

    async def test_expired_token_is_401(
        self, client: httpx.AsyncClient, make_token: Callable[..., str]
    ) -> None:
        resp = await client.post(
            "/v1/mint",
            headers=_auth(make_token(expires_in=-60)),
            json=_body(),
        )
        assert resp.status_code == 401
        assert resp.headers["WWW-Authenticate"] == "Bearer"

    async def test_wrong_audience_is_401(
        self, client: httpx.AsyncClient, make_token: Callable[..., str]
    ) -> None:
        resp = await client.post(
            "/v1/mint",
            headers=_auth(make_token(audience="not-us")),
            json=_body(),
        )
        assert resp.status_code == 401

    async def test_wrong_issuer_is_401(
        self, client: httpx.AsyncClient, make_token: Callable[..., str]
    ) -> None:
        resp = await client.post(
            "/v1/mint",
            headers=_auth(make_token(issuer="https://evil.example")),
            json=_body(),
        )
        assert resp.status_code == 401

    async def test_denied_request_is_audited(
        self, client: httpx.AsyncClient, make_token: Callable[..., str]
    ) -> None:
        with capture_logs() as cap_logs:
            await client.post(
                "/v1/mint",
                headers=_auth(make_token(expires_in=-60)),
                json=_body(),
            )
        (audit,) = _audit_events(cap_logs)
        assert audit["outcome"] == "denied"


@pytest.mark.usefixtures("fake_voms_proxy_init")
class TestBadPassphrase:
    async def test_wrong_passphrase_is_400(
        self, client: httpx.AsyncClient, make_token: Callable[..., str]
    ) -> None:
        resp = await client.post(
            "/v1/mint",
            headers=_auth(make_token()),
            json=_body(passphrase="totally-wrong"),
        )
        assert resp.status_code == 400
        assert resp.json()["detail"] == "bad passphrase"

    async def test_bad_passphrase_is_audited_as_denied(
        self, client: httpx.AsyncClient, make_token: Callable[..., str]
    ) -> None:
        with capture_logs() as cap_logs:
            resp = await client.post(
                "/v1/mint",
                headers=_auth(make_token()),
                json=_body(passphrase="totally-wrong"),
            )
        assert resp.status_code == 400
        (audit,) = _audit_events(cap_logs)
        assert audit["outcome"] == "denied"


class TestMintingInfraFailure:
    async def test_binary_failure_is_502_with_generic_detail(
        self,
        client: httpx.AsyncClient,
        make_token: Callable[..., str],
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        _install_fake_bin(
            tmp_path,
            monkeypatch,
            'IFS= read -r _\necho "VOMS server voms2.cern.ch unreachable" >&2\nexit 1',
        )
        with capture_logs() as cap_logs:
            resp = await client.post(
                "/v1/mint", headers=_auth(make_token()), json=_body()
            )
        assert resp.status_code == 502
        assert "voms2.cern.ch" not in resp.text
        (audit,) = _audit_events(cap_logs)
        assert audit["outcome"] == "error"


class TestReadyz:
    @pytest.mark.usefixtures("fake_voms_proxy_init")
    async def test_ready_when_binary_present_and_jwks_fetchable(
        self, client: httpx.AsyncClient
    ) -> None:
        resp = await client.get("/readyz")
        assert resp.status_code == 200
        assert resp.json() == {"status": "ready"}

    async def test_503_when_binary_missing(
        self, make_client: Callable[[Settings], httpx.AsyncClient]
    ) -> None:
        settings = Settings(
            _env_file=None,
            broker_jwks_url="https://broker.test/jwks",
            broker_issuer="https://broker.test",
            voms_proxy_init_bin="/nonexistent/voms-proxy-init",
        )
        async with make_client(settings) as client:
            resp = await client.get("/readyz")
        assert resp.status_code == 503
        assert "voms-proxy-init" in resp.json()["detail"]


class TestCredentialPermissionsResponse:
    async def test_permission_rejection_is_422_with_actionable_detail(
        self,
        client: httpx.AsyncClient,
        make_token: Callable[..., str],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        async def failing_mint(*args: Any, **kwargs: Any):
            raise CredentialPermissionsError

        monkeypatch.setattr(app_module, "mint_proxy", failing_mint)

        resp = await client.post(
            "/v1/mint",
            json={
                "unixname": "gstark",
                "uid": 12345,
                "gid": 12345,
                "passphrase": FAKE_CORRECT_PASSPHRASE,
            },
            headers=_auth(make_token()),
        )

        assert resp.status_code == 422
        assert "chmod 400" in resp.json()["detail"]


class TestMintUnixnameValidation:
    async def test_traversal_unixname_is_422_and_never_reaches_minting(
        self,
        client: httpx.AsyncClient,
        make_token: Callable[..., str],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:

        called = False

        async def recording_mint(*args: Any, **kwargs: Any):
            nonlocal called
            called = True
            raise AssertionError("mint_proxy must not be reached")

        monkeypatch.setattr(app_module, "mint_proxy", recording_mint)

        resp = await client.post(
            "/v1/mint",
            json={
                "unixname": "../root",
                "uid": 12345,
                "gid": 12345,
                "passphrase": FAKE_CORRECT_PASSPHRASE,
            },
            headers=_auth(make_token()),
        )

        assert resp.status_code == 422
        assert called is False
