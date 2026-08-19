"""Integration tests for GET /v1/preflight/{unixname} through the ASGI stack.

Complements tests/test_preflight.py (which exercises run_preflight and
validate_unixname directly): this file owns auth, routing, response-shape,
and the never-touch-the-filesystem-on-invalid-input guarantee.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import pytest

import voms_token_service.app as app_module
from voms_token_service.config import Settings

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

    import httpx


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _write_pair(
    home_root: Path,
    unixname: str,
    *,
    usercert_mode: int = 0o444,
    userkey_mode: int = 0o400,
) -> None:
    d = home_root / unixname / ".globus"
    d.mkdir(parents=True)
    (d / "usercert.pem").write_text("cert")
    (d / "usercert.pem").chmod(usercert_mode)
    (d / "userkey.pem").write_text("key")
    (d / "userkey.pem").chmod(userkey_mode)


@pytest.fixture
def homes_settings(tmp_path: Path) -> Settings:
    return Settings(
        _env_file=None,
        broker_jwks_url="https://broker.test/jwks",
        broker_issuer="https://broker.test",
        home_root=str(tmp_path / "homes"),
    )


@pytest.fixture
async def homes_client(
    make_client: Callable[[Settings], httpx.AsyncClient],
    homes_settings: Settings,
) -> Any:
    async with make_client(homes_settings) as test_client:
        yield test_client


@pytest.mark.usefixtures("stub_jwks_fetch")
class TestHappyPath:
    async def test_returns_full_ok_checklist(
        self,
        homes_client: httpx.AsyncClient,
        make_token: Callable[..., str],
        homes_settings: Settings,
        tmp_path: Path,
    ) -> None:
        _write_pair(tmp_path / "homes", "gstark")

        resp = await homes_client.get(
            "/v1/preflight/gstark", headers=_auth(make_token())
        )

        assert resp.status_code == 200
        body = resp.json()
        assert body["unixname"] == "gstark"
        assert body["root"] == f"{homes_settings.home_root}/gstark/.globus"
        assert body["ok"] is True

        by_name = {c["name"]: c for c in body["checks"]}
        # response_model_exclude_none drops mode/readable_by_service on the
        # directory check, matching the API-spec example exactly.
        assert "mode" not in by_name["globus_dir"]
        assert "readable_by_service" not in by_name["globus_dir"]
        assert by_name["globus_dir"] == {
            "name": "globus_dir",
            "path": f"{homes_settings.home_root}/gstark/.globus",
            "exists": True,
            "ok": True,
        }

        assert by_name["usercert"]["ok"] is True
        assert by_name["usercert"]["mode"] == "0444"
        assert by_name["usercert"]["readable_by_service"] is True

        assert by_name["userkey"]["ok"] is True
        assert by_name["userkey"]["mode"] == "0400"
        assert by_name["userkey"]["readable_by_service"] is True


@pytest.mark.usefixtures("stub_jwks_fetch")
class TestMissingCredentials:
    async def test_missing_globus_dir_is_200_with_ok_false(
        self, homes_client: httpx.AsyncClient, make_token: Callable[..., str]
    ) -> None:
        resp = await homes_client.get(
            "/v1/preflight/nouser", headers=_auth(make_token())
        )

        assert resp.status_code == 200
        body = resp.json()
        assert body["ok"] is False
        by_name = {c["name"]: c for c in body["checks"]}
        assert by_name["globus_dir"]["exists"] is False
        assert "copy your grid certificate" in by_name["globus_dir"]["detail"]
        assert by_name["usercert"]["exists"] is False
        assert by_name["userkey"]["exists"] is False


@pytest.mark.usefixtures("stub_jwks_fetch")
class TestLooseKeyMode:
    async def test_group_readable_key_is_flagged_but_still_200(
        self,
        homes_client: httpx.AsyncClient,
        make_token: Callable[..., str],
        tmp_path: Path,
    ) -> None:
        _write_pair(tmp_path / "homes", "gstark", userkey_mode=0o644)

        resp = await homes_client.get(
            "/v1/preflight/gstark", headers=_auth(make_token())
        )

        assert resp.status_code == 200
        body = resp.json()
        assert body["ok"] is False
        by_name = {c["name"]: c for c in body["checks"]}
        assert by_name["userkey"]["ok"] is False
        assert "chmod 400" in by_name["userkey"]["detail"]


class TestAuthenticationRequired:
    async def test_missing_authorization_header_is_401(
        self, homes_client: httpx.AsyncClient
    ) -> None:
        resp = await homes_client.get("/v1/preflight/gstark")
        assert resp.status_code == 401

    @pytest.mark.usefixtures("stub_jwks_fetch")
    async def test_expired_token_is_401(
        self, homes_client: httpx.AsyncClient, make_token: Callable[..., str]
    ) -> None:
        resp = await homes_client.get(
            "/v1/preflight/gstark",
            headers=_auth(make_token(expires_in=-60)),
        )
        assert resp.status_code == 401


@pytest.mark.usefixtures("stub_jwks_fetch")
class TestTraversalRejection:
    @pytest.mark.parametrize(
        "raw_segment",
        [
            "%2e%2e",  # decodes to ".." — the actual attack this must catch
            "%2e",  # decodes to "."
            ".hidden",
        ],
    )
    async def test_unsafe_unixname_is_422_and_never_touches_the_filesystem(
        self,
        homes_client: httpx.AsyncClient,
        make_token: Callable[..., str],
        monkeypatch: pytest.MonkeyPatch,
        raw_segment: str,
    ) -> None:
        def _fail_if_called(*args: Any, **kwargs: Any) -> Any:
            msg = "run_preflight must not be called for an unsafe unixname"
            raise AssertionError(msg)

        monkeypatch.setattr(app_module, "run_preflight", _fail_if_called)

        resp = await homes_client.get(
            f"/v1/preflight/{raw_segment}", headers=_auth(make_token())
        )

        assert resp.status_code == 422

    async def test_literal_dot_dot_segment_is_removed_by_routing_before_it_arrives(
        self, homes_client: httpx.AsyncClient, make_token: Callable[..., str]
    ) -> None:
        # A literal ".." path segment (unlike its %2e%2e-encoded form above)
        # is normalized away by Starlette's own routing before any route
        # matches, so this never reaches our handler at all — 404, not 422.
        # Still "never touches the filesystem", just one layer further out.
        resp = await homes_client.get("/v1/preflight/..", headers=_auth(make_token()))
        assert resp.status_code == 404

    async def test_embedded_slash_attempt_is_rejected_by_routing(
        self, homes_client: httpx.AsyncClient, make_token: Callable[..., str]
    ) -> None:
        # An absolute-path-style attempt ("/etc/passwd") requires an
        # encoded "/" inside the single path segment; Starlette decodes
        # %2F to a literal separator before route matching, so this also
        # never reaches our handler — 404, not 422.
        resp = await homes_client.get(
            "/v1/preflight/%2Fetc%2Fpasswd", headers=_auth(make_token())
        )
        assert resp.status_code == 404
