"""Unit tests for Settings (env-driven configuration)."""

from __future__ import annotations

from typing import TYPE_CHECKING

from voms_token_service.config import Settings, get_settings

if TYPE_CHECKING:
    import pytest


class TestDefaults:
    def test_expected_audience_defaults_to_service_name(self) -> None:
        assert Settings(_env_file=None).expected_audience == "voms-token-service"

    def test_home_root_default(self) -> None:
        assert Settings(_env_file=None).home_root == "/home"

    def test_voms_proxy_init_bin_default(self) -> None:
        assert Settings(_env_file=None).voms_proxy_init_bin == "voms-proxy-init"

    def test_voms_proxy_info_bin_default(self) -> None:
        assert Settings(_env_file=None).voms_proxy_info_bin == "voms-proxy-info"

    def test_default_voms_default(self) -> None:
        assert Settings(_env_file=None).default_voms == "atlas"

    def test_default_valid_default(self) -> None:
        assert Settings(_env_file=None).default_valid == "192:00"

    def test_proxy_init_timeout_default(self) -> None:
        assert Settings(_env_file=None).proxy_init_timeout_seconds == 60

    def test_jwks_cache_ttl_default(self) -> None:
        assert Settings(_env_file=None).jwks_cache_ttl_seconds == 300


class TestEnvOverrides:
    def test_env_vars_override_defaults(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("BROKER_JWKS_URL", "https://broker.example/jwks")
        monkeypatch.setenv("BROKER_ISSUER", "https://broker.example")
        monkeypatch.setenv("EXPECTED_AUDIENCE", "other-audience")
        monkeypatch.setenv("HOME_ROOT", "/data/homes")
        monkeypatch.setenv("VOMS_PROXY_INIT_BIN", "/opt/voms/bin/voms-proxy-init")
        monkeypatch.setenv("VOMS_PROXY_INFO_BIN", "/opt/voms/bin/voms-proxy-info")
        monkeypatch.setenv("DEFAULT_VOMS", "cms")
        monkeypatch.setenv("DEFAULT_VALID", "24:00")
        monkeypatch.setenv("PROXY_INIT_TIMEOUT_SECONDS", "30")

        settings = Settings(_env_file=None)
        assert settings.broker_jwks_url == "https://broker.example/jwks"
        assert settings.broker_issuer == "https://broker.example"
        assert settings.expected_audience == "other-audience"
        assert settings.home_root == "/data/homes"
        assert settings.voms_proxy_init_bin == "/opt/voms/bin/voms-proxy-init"
        assert settings.voms_proxy_info_bin == "/opt/voms/bin/voms-proxy-info"
        assert settings.default_voms == "cms"
        assert settings.default_valid == "24:00"
        assert settings.proxy_init_timeout_seconds == 30


def test_get_settings_is_cached() -> None:
    assert get_settings() is get_settings()
