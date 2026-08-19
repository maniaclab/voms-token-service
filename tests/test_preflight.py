"""Unit tests for credential-preflight checks (no ASGI layer involved).

Exercises run_preflight/validate_unixname directly against a real (tmp_path)
homes tree — the same "real filesystem, no python-level mocking of stat/open"
spirit as test_minting.py, except here the filesystem *is* the thing under
test rather than a subprocess.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

import voms_token_service.preflight as preflight_module
from voms_token_service.config import Settings
from voms_token_service.paths import globus_dir
from voms_token_service.preflight import (
    InvalidUnixnameError,
    run_preflight,
    validate_unixname,
)

if TYPE_CHECKING:
    from pathlib import Path


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    return Settings(_env_file=None, home_root=str(tmp_path / "homes"))


def _write_pair(
    settings: Settings,
    unixname: str,
    *,
    usercert_mode: int = 0o444,
    userkey_mode: int = 0o400,
) -> tuple[Path, Path]:
    d = globus_dir(settings, unixname)
    d.mkdir(parents=True)
    usercert = d / "usercert.pem"
    userkey = d / "userkey.pem"
    usercert.write_text("cert")
    userkey.write_text("key")
    usercert.chmod(usercert_mode)
    userkey.chmod(userkey_mode)
    return usercert, userkey


class TestValidateUnixname:
    @pytest.mark.parametrize(
        "unixname", ["gstark", "alice_2", "a", "user-name", "user.name", "USER1"]
    )
    def test_accepts_normal_unixnames(self, unixname: str) -> None:
        validate_unixname(unixname)  # must not raise

    @pytest.mark.parametrize(
        "unixname",
        ["..", ".", "../etc", "/etc/passwd", "a/b", ".hidden", ""],
    )
    def test_rejects_traversal_and_unsafe_names(self, unixname: str) -> None:
        with pytest.raises(InvalidUnixnameError):
            validate_unixname(unixname)


class TestRunPreflightHappyPath:
    def test_all_checks_ok_when_dir_and_files_are_sane(
        self, settings: Settings
    ) -> None:
        _write_pair(settings, "gstark")
        result = run_preflight(settings, "gstark")

        assert result.ok is True
        assert result.unixname == "gstark"
        assert result.root == str(globus_dir(settings, "gstark"))

        by_name = {c.name: c for c in result.checks}
        assert by_name["globus_dir"].ok is True
        assert by_name["globus_dir"].exists is True
        assert by_name["globus_dir"].detail is None

        assert by_name["usercert"].ok is True
        assert by_name["usercert"].exists is True
        assert by_name["usercert"].readable_by_service is True
        assert by_name["usercert"].mode == "0444"

        assert by_name["userkey"].ok is True
        assert by_name["userkey"].exists is True
        assert by_name["userkey"].readable_by_service is True
        assert by_name["userkey"].mode == "0400"


class TestRunPreflightMissingDir:
    def test_missing_dir_short_circuits_all_checks(self, settings: Settings) -> None:
        result = run_preflight(settings, "nouser")

        assert result.ok is False
        by_name = {c.name: c for c in result.checks}

        assert by_name["globus_dir"].exists is False
        assert by_name["globus_dir"].ok is False
        assert by_name["globus_dir"].detail is not None
        assert "copy your grid certificate" in by_name["globus_dir"].detail

        assert by_name["usercert"].exists is False
        assert by_name["usercert"].ok is False
        assert by_name["userkey"].exists is False
        assert by_name["userkey"].ok is False


class TestRunPreflightMissingFiles:
    def test_missing_usercert_is_flagged(self, settings: Settings) -> None:
        d = globus_dir(settings, "gstark")
        d.mkdir(parents=True)
        (d / "userkey.pem").write_text("key")
        (d / "userkey.pem").chmod(0o400)

        result = run_preflight(settings, "gstark")

        by_name = {c.name: c for c in result.checks}
        assert by_name["globus_dir"].ok is True
        assert by_name["usercert"].exists is False
        assert by_name["usercert"].ok is False
        assert by_name["userkey"].ok is True
        assert result.ok is False

    def test_missing_userkey_is_flagged(self, settings: Settings) -> None:
        d = globus_dir(settings, "gstark")
        d.mkdir(parents=True)
        (d / "usercert.pem").write_text("cert")
        (d / "usercert.pem").chmod(0o444)

        result = run_preflight(settings, "gstark")

        by_name = {c.name: c for c in result.checks}
        assert by_name["usercert"].ok is True
        assert by_name["userkey"].exists is False
        assert by_name["userkey"].ok is False
        assert result.ok is False


class TestRunPreflightLooseKeyMode:
    @pytest.mark.parametrize("mode", [0o644, 0o640, 0o604, 0o660, 0o444])
    def test_group_or_other_accessible_key_is_flagged(
        self, settings: Settings, mode: int
    ) -> None:
        _write_pair(settings, "gstark", userkey_mode=mode)
        result = run_preflight(settings, "gstark")

        key_check = next(c for c in result.checks if c.name == "userkey")
        assert key_check.ok is False
        assert key_check.readable_by_service is True
        assert key_check.mode == format(mode, "04o")
        assert key_check.detail is not None
        assert "chmod 400" in key_check.detail
        assert result.ok is False

    def test_owner_only_key_mode_0600_is_ok(self, settings: Settings) -> None:
        # No group/other bits set — acceptable even though it's not 0400.
        _write_pair(settings, "gstark", userkey_mode=0o600)
        result = run_preflight(settings, "gstark")
        key_check = next(c for c in result.checks if c.name == "userkey")
        assert key_check.ok is True

    def test_usercert_loose_mode_is_still_ok(self, settings: Settings) -> None:
        # "Any mode is acceptable for the cert."
        _write_pair(settings, "gstark", usercert_mode=0o644)
        result = run_preflight(settings, "gstark")
        cert_check = next(c for c in result.checks if c.name == "usercert")
        assert cert_check.ok is True


class TestRunPreflightUnreadableFile:
    def test_chmod_000_key_is_flagged_unless_process_bypasses_dac(
        self, settings: Settings
    ) -> None:
        _usercert, userkey = _write_pair(settings, "gstark", userkey_mode=0o000)
        try:
            with userkey.open("rb"):
                pass
        except OSError:
            pass
        else:
            pytest.skip(
                "test process can bypass file permissions (likely running as root)"
            )

        result = run_preflight(settings, "gstark")
        key_check = next(c for c in result.checks if c.name == "userkey")
        assert key_check.readable_by_service is False
        assert key_check.ok is False
        assert key_check.detail is not None

    def test_service_read_probe_failure_is_surfaced_with_errno(
        self, settings: Settings, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _write_pair(settings, "gstark")

        original_probe = preflight_module._probe_readable

        def _fake_probe(path: Path) -> tuple[bool, str | None]:
            if path.name == "userkey.pem":
                return False, "Permission denied (errno 13)"
            return original_probe(path)

        monkeypatch.setattr(preflight_module, "_probe_readable", _fake_probe)

        result = run_preflight(settings, "gstark")
        key_check = next(c for c in result.checks if c.name == "userkey")
        assert key_check.readable_by_service is False
        assert key_check.ok is False
        assert key_check.detail is not None
        assert "13" in key_check.detail


class TestRunPreflightNotARegularFile:
    def test_usercert_that_is_a_directory_is_flagged(self, settings: Settings) -> None:
        d = globus_dir(settings, "gstark")
        d.mkdir(parents=True)
        (d / "usercert.pem").mkdir()
        (d / "userkey.pem").write_text("key")
        (d / "userkey.pem").chmod(0o400)

        result = run_preflight(settings, "gstark")
        cert_check = next(c for c in result.checks if c.name == "usercert")
        assert cert_check.exists is True
        assert cert_check.ok is False
