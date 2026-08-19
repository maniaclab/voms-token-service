"""Unit tests for the shared Globus credential path helpers.

minting.py (mint_proxy) and preflight.py (the credential-preflight endpoint)
both need {home_root}/{unixname}/.globus/{usercert,userkey}.pem; this module
is the single place that construction lives so the two code paths can never
drift apart.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from voms_token_service.config import Settings
from voms_token_service.paths import globus_dir, usercert_path, userkey_path


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    return Settings(_env_file=None, home_root=str(tmp_path / "homes"))


class TestGlobusDir:
    def test_joins_home_root_unixname_and_dot_globus(self, settings: Settings) -> None:
        assert globus_dir(settings, "gstark") == (
            Path(settings.home_root) / "gstark" / ".globus"
        )


class TestUsercertAndUserkeyPath:
    def test_usercert_path_is_under_globus_dir(self, settings: Settings) -> None:
        assert usercert_path(settings, "gstark") == globus_dir(settings, "gstark") / (
            "usercert.pem"
        )

    def test_userkey_path_is_under_globus_dir(self, settings: Settings) -> None:
        assert userkey_path(settings, "gstark") == globus_dir(settings, "gstark") / (
            "userkey.pem"
        )
