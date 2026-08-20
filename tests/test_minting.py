"""Integration tests for VOMS proxy minting via a real (fake) voms-proxy-init subprocess.

No Python-level mocking here: the binary under test is an executable shell
script on PATH, exactly how the real voms-proxy-init is invoked.
"""

from __future__ import annotations

import subprocess
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING

import pytest
from cryptography import x509 as cx509
from structlog.testing import capture_logs

from tests.conftest import FAKE_CORRECT_PASSPHRASE, _install_fake_bin
from voms_token_service import minting
from voms_token_service.config import Settings
from voms_token_service.minting import (
    BadPassphraseError,
    CredentialPermissionsError,
    MintingError,
    mint_proxy,
)

if TYPE_CHECKING:
    from tests.conftest import FakeVomsProxyInit


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    # The user's home must exist (in production it always does — it's the
    # NFS-mounted real home): the minted proxy is written there.
    (tmp_path / "homes" / "gstark").mkdir(parents=True)
    return Settings(
        _env_file=None,
        home_root=str(tmp_path / "homes"),
        # See tests/conftest.py::settings for why this defaults nonexistent.
        voms_proxy_info_bin="/nonexistent/voms-proxy-info",
    )


def _passphrase(text: str = FAKE_CORRECT_PASSPHRASE) -> bytearray:
    return bytearray(text.encode())


def _write_fake_voms_proxy_info(path: Path, body: str) -> Path:
    """Write an executable fake voms-proxy-info script at an explicit *path*.

    Unlike ``_install_fake_bin`` (which always names the script
    ``voms-proxy-init`` and installs it via PATH), this writes to whatever
    path the caller passes and returns it for direct use as
    ``Settings(voms_proxy_info_bin=...)`` — sidestepping PATH lookup
    entirely so these tests never risk picking up a real voms-proxy-info
    that happens to be installed in the test environment.
    """
    path.write_text(f"#!/bin/sh\n{body}\n")
    path.chmod(0o755)
    return path


class TestMintProxySuccess:
    async def test_returns_pem_with_certificate_and_key(
        self, fake_voms_proxy_init: FakeVomsProxyInit, settings: Settings
    ) -> None:
        minted = await mint_proxy(
            "gstark", _passphrase(), "atlas", "192:00", settings, uid=12345, gid=12345
        )
        assert "BEGIN CERTIFICATE" in minted.pem
        assert "PRIVATE KEY" in minted.pem

    async def test_dn_and_expiry_match_independent_parse(
        self,
        fake_voms_proxy_init: FakeVomsProxyInit,
        settings: Settings,
        fake_proxy_pem: bytes,
    ) -> None:
        minted = await mint_proxy(
            "gstark", _passphrase(), "atlas", "192:00", settings, uid=12345, gid=12345
        )
        first_block = fake_proxy_pem.split(b"-----END CERTIFICATE-----")[0]
        cert = cx509.load_pem_x509_certificate(
            first_block + b"-----END CERTIFICATE-----\n"
        )
        assert minted.dn == cert.issuer.rfc4514_string()
        assert minted.expires_at == cert.not_valid_after_utc

    async def test_expires_at_is_timezone_aware_utc(
        self, fake_voms_proxy_init: FakeVomsProxyInit, settings: Settings
    ) -> None:
        minted = await mint_proxy(
            "gstark", _passphrase(), "atlas", "192:00", settings, uid=12345, gid=12345
        )
        assert minted.expires_at.tzinfo is not None
        assert minted.expires_at > datetime.now(UTC)

    async def test_invoked_with_expected_flags_in_order(
        self, fake_voms_proxy_init: FakeVomsProxyInit, settings: Settings
    ) -> None:
        await mint_proxy(
            "gstark", _passphrase(), "atlas", "192:00", settings, uid=12345, gid=12345
        )
        recorded = fake_voms_proxy_init.args_file.read_text().split()
        usercert = f"{settings.home_root}/gstark/.globus/usercert.pem"
        userkey = f"{settings.home_root}/gstark/.globus/userkey.pem"
        assert recorded == [
            "--rfc",
            "--voms",
            "atlas",
            "--valid",
            "192:00",
            "--cert",
            usercert,
            "--key",
            userkey,
            "--out",
            recorded[recorded.index("--out") + 1],
            "--pwstdin",
        ]

    async def test_passphrase_never_appears_in_argv(
        self, fake_voms_proxy_init: FakeVomsProxyInit, settings: Settings
    ) -> None:
        await mint_proxy(
            "gstark", _passphrase(), "atlas", "192:00", settings, uid=12345, gid=12345
        )
        recorded = fake_voms_proxy_init.args_file.read_text()
        assert FAKE_CORRECT_PASSPHRASE not in recorded

    async def test_passphrase_buffer_is_zeroed_after_success(
        self, fake_voms_proxy_init: FakeVomsProxyInit, settings: Settings
    ) -> None:
        buf = _passphrase()
        await mint_proxy(
            "gstark", buf, "atlas", "192:00", settings, uid=12345, gid=12345
        )
        assert buf == bytearray(len(buf))


class TestMintProxyBadPassphrase:
    async def test_wrong_passphrase_raises_bad_passphrase_error(
        self, fake_voms_proxy_init: FakeVomsProxyInit, settings: Settings
    ) -> None:
        with pytest.raises(BadPassphraseError):
            await mint_proxy(
                "gstark",
                _passphrase("wrong-passphrase"),
                "atlas",
                "192:00",
                settings,
                uid=12345,
                gid=12345,
            )

    async def test_bad_passphrase_error_does_not_leak_stderr(
        self, fake_voms_proxy_init: FakeVomsProxyInit, settings: Settings
    ) -> None:
        with pytest.raises(BadPassphraseError) as excinfo:
            await mint_proxy(
                "gstark",
                _passphrase("wrong-passphrase"),
                "atlas",
                "192:00",
                settings,
                uid=12345,
                gid=12345,
            )
        assert "bad decrypt" not in str(excinfo.value)

    async def test_passphrase_buffer_is_zeroed_after_failure(
        self, fake_voms_proxy_init: FakeVomsProxyInit, settings: Settings
    ) -> None:
        buf = _passphrase("wrong-passphrase")
        with pytest.raises(BadPassphraseError):
            await mint_proxy(
                "gstark", buf, "atlas", "192:00", settings, uid=12345, gid=12345
            )
        assert buf == bytearray(len(buf))


class TestMintProxyInfraFailures:
    async def test_missing_binary_raises_minting_error(
        self, settings: Settings
    ) -> None:
        missing = Settings(
            _env_file=None,
            home_root=settings.home_root,
            voms_proxy_init_bin="/nonexistent/voms-proxy-init",
        )
        with pytest.raises(MintingError):
            await mint_proxy(
                "gstark",
                _passphrase(),
                "atlas",
                "192:00",
                missing,
                uid=12345,
                gid=12345,
            )

    async def test_nonzero_exit_raises_minting_error_without_leaking_stderr(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, settings: Settings
    ) -> None:
        _install_fake_bin(
            tmp_path,
            monkeypatch,
            'IFS= read -r _\necho "VOMS server voms2.cern.ch unreachable" >&2\nexit 1',
        )
        with pytest.raises(MintingError) as excinfo:
            await mint_proxy(
                "gstark",
                _passphrase(),
                "atlas",
                "192:00",
                settings,
                uid=12345,
                gid=12345,
            )
        assert "voms2.cern.ch" not in str(excinfo.value)

    async def test_timeout_raises_minting_error(
        self, hanging_voms_proxy_init: Path, settings: Settings
    ) -> None:
        fast_timeout = Settings(
            _env_file=None,
            home_root=settings.home_root,
            proxy_init_timeout_seconds=1,
        )
        with pytest.raises(MintingError):
            await mint_proxy(
                "gstark",
                _passphrase(),
                "atlas",
                "192:00",
                fast_timeout,
                uid=12345,
                gid=12345,
            )

    async def test_empty_output_file_raises_minting_error(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, settings: Settings
    ) -> None:
        _install_fake_bin(
            tmp_path,
            monkeypatch,
            'IFS= read -r _\nout=""\nwhile [ $# -gt 0 ]; do case "$1" in --out) out="$2"; shift 2 ;; *) shift ;; esac done\n'
            'touch "$out"\nexit 0',
        )
        with pytest.raises(MintingError):
            await mint_proxy(
                "gstark",
                _passphrase(),
                "atlas",
                "192:00",
                settings,
                uid=12345,
                gid=12345,
            )


class TestImpersonation:
    """voms-proxy-init requires the key be OWNED by the effective uid, so the
    service must run the child as the requesting user when it is root."""

    @staticmethod
    def _recording_run(recorded: dict, fake_proxy_pem: bytes):
        def fake_run(argv, **kwargs):
            if argv[0] == "bash" and "mkdir" in argv[2]:
                # The impersonated workdir prep: do what the child would.
                recorded["prep_user"] = kwargs.get("user")
                Path(argv[-1]).mkdir(mode=0o700, parents=True, exist_ok=True)
                return subprocess.CompletedProcess(argv, 0, b"", b"")
            if argv[0] == "bash" and "cat" in argv[2]:
                # The impersonated read-back (+ cleanup) of the minted proxy.
                recorded["readback_argv"] = argv
                recorded["readback_user"] = kwargs.get("user")
                return subprocess.CompletedProcess(argv, 0, fake_proxy_pem, b"")
            if "--all" in argv:
                # The impersonated nickname lookup, run before the read-back
                # above deletes out_path.
                recorded["nickname_argv"] = argv
                recorded["nickname_user"] = kwargs.get("user")
                return subprocess.CompletedProcess(
                    argv, 0, b"attribute : nickname = gstark (atlas)\n", b""
                )
            recorded["argv"] = argv
            recorded.update({k: v for k, v in kwargs.items() if k != "input"})
            out = Path(argv[argv.index("--out") + 1])
            out.write_bytes(fake_proxy_pem)
            return subprocess.CompletedProcess(argv, 0, b"", b"")

        return fake_run

    async def test_runs_child_as_user_when_root(
        self, settings: Settings, fake_proxy_pem: bytes, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        recorded: dict = {}
        chowns: list[tuple[str, int, int]] = []
        monkeypatch.setattr(minting.os, "geteuid", lambda: 0)
        monkeypatch.setattr(
            minting.os, "chown", lambda p, u, g: chowns.append((str(p), u, g))
        )
        monkeypatch.setattr(
            minting.subprocess, "run", self._recording_run(recorded, fake_proxy_pem)
        )

        minted = await mint_proxy(
            "gstark", _passphrase(), "atlas", "192:00", settings, uid=4321, gid=8765
        )

        assert recorded["user"] == 4321
        assert recorded["group"] == 8765
        assert recorded["extra_groups"] == []
        # Workdir prep, the nickname lookup, and read-back are ALSO
        # impersonated — root never touches user-owned files or dirs.
        assert recorded["prep_user"] == 4321
        assert recorded["nickname_user"] == 4321
        assert recorded["readback_user"] == 4321
        assert minted.nickname == "gstark"
        # No chown anywhere: the child creates its own 0700 dir under
        # umask 077, so no ownership fixups are ever needed.
        assert chowns == []

    async def test_no_impersonation_when_not_root(
        self, settings: Settings, fake_proxy_pem: bytes, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        recorded: dict = {}
        chowns: list[tuple[str, int, int]] = []
        monkeypatch.setattr(minting.os, "geteuid", lambda: 1000)
        monkeypatch.setattr(
            minting.os, "chown", lambda p, u, g: chowns.append((str(p), u, g))
        )
        monkeypatch.setattr(
            minting.subprocess, "run", self._recording_run(recorded, fake_proxy_pem)
        )

        minted = await mint_proxy(
            "gstark", _passphrase(), "atlas", "192:00", settings, uid=4321, gid=8765
        )

        assert recorded["user"] is None
        assert recorded["group"] is None
        assert recorded["extra_groups"] is None
        assert recorded["nickname_user"] is None
        assert minted.nickname == "gstark"
        assert chowns == []


class TestCredentialPermissions:
    async def test_sslutils_ownership_error_is_distinct_and_actionable(
        self, settings: Settings, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        stderr = (
            b"sslutils.c:3099:error:400003F9:lib(128)::bad file system "
            b"permissions on private key\n    key must only be readable by "
            b"the user\n        File=/home/gstark/.globus/userkey.pem"
        )

        def failing_run(argv, **kwargs):
            return subprocess.CompletedProcess(argv, 3, b"", stderr)

        monkeypatch.setattr(minting.subprocess, "run", failing_run)

        with pytest.raises(CredentialPermissionsError, match="chmod 400"):
            await mint_proxy(
                "gstark",
                _passphrase(),
                "atlas",
                "192:00",
                settings,
                uid=4321,
                gid=8765,
            )


class TestExtractNickname:
    """Unit tests for the pure ``--all``-output parser, independent of any subprocess."""

    def test_extracts_nickname_for_matching_vo(self) -> None:
        output = "attribute : /atlas/Role=NULL/Capability=NULL\nattribute : nickname = gstark (atlas)\n"
        assert minting._extract_nickname(output, "atlas") == "gstark"

    def test_returns_none_when_attribute_absent(self) -> None:
        output = "attribute : /atlas/Role=NULL/Capability=NULL\ntimeleft  : 191:59:59\n"
        assert minting._extract_nickname(output, "atlas") is None

    def test_multi_attribute_output_still_finds_nickname(self) -> None:
        output = (
            "subject   : /DC=ch/DC=cern/CN=Test User\n"
            "issuer    : /DC=ch/DC=cern/CN=Test User\n"
            "=== VO atlas extension information ===\n"
            "VO        : atlas\n"
            "attribute : /atlas/Role=NULL/Capability=NULL\n"
            "attribute : /atlas/uchicago/Role=NULL/Capability=NULL\n"
            "attribute : nickname = gstark (atlas)\n"
            "timeleft  : 191:59:59\n"
        )
        assert minting._extract_nickname(output, "atlas") == "gstark"

    def test_filters_by_vo_ignoring_other_vos_nickname(self) -> None:
        output = "attribute : nickname = someoneelse (cms)\nattribute : nickname = gstark (atlas)\n"
        assert minting._extract_nickname(output, "atlas") == "gstark"

    def test_returns_none_when_only_other_vo_nickname_present(self) -> None:
        output = "attribute : nickname = someoneelse (cms)\n"
        assert minting._extract_nickname(output, "atlas") is None

    def test_returns_none_on_unparseable_output(self) -> None:
        assert (
            minting._extract_nickname("garbage\nnot voms-proxy-info output\n", "atlas")
            is None
        )


class TestNicknameExtractionIntegration:
    """Integration tests for mint_proxy's nickname lookup via a real (fake) voms-proxy-info subprocess.

    Like TestMintProxySuccess, no Python-level mocking: the fake
    voms-proxy-info is an executable shell script, invoked exactly as
    settings.voms_proxy_info_bin names it.
    """

    async def test_nickname_present_in_minted_proxy(
        self,
        fake_voms_proxy_init: FakeVomsProxyInit,
        settings: Settings,
        tmp_path: Path,
    ) -> None:
        info_bin = _write_fake_voms_proxy_info(
            tmp_path / "fake-voms-proxy-info",
            'echo "attribute : nickname = gstark (atlas)"\nexit 0',
        )
        settings = Settings(
            _env_file=None,
            home_root=settings.home_root,
            voms_proxy_info_bin=str(info_bin),
        )

        minted = await mint_proxy(
            "gstark", _passphrase(), "atlas", "192:00", settings, uid=12345, gid=12345
        )

        assert minted.nickname == "gstark"

    async def test_nickname_lookup_invoked_with_file_and_all_flags(
        self,
        fake_voms_proxy_init: FakeVomsProxyInit,
        settings: Settings,
        tmp_path: Path,
    ) -> None:
        args_file = tmp_path / "voms_info_args.txt"
        info_bin = _write_fake_voms_proxy_info(
            tmp_path / "fake-voms-proxy-info",
            f'echo "$@" > "{args_file}"\necho "attribute : nickname = gstark (atlas)"\nexit 0',
        )
        settings = Settings(
            _env_file=None,
            home_root=settings.home_root,
            voms_proxy_info_bin=str(info_bin),
        )

        await mint_proxy(
            "gstark", _passphrase(), "atlas", "192:00", settings, uid=12345, gid=12345
        )

        recorded = args_file.read_text().split()
        assert recorded[recorded.index("--file") + 1]
        assert "--all" in recorded

    async def test_nickname_none_when_attribute_absent(
        self,
        fake_voms_proxy_init: FakeVomsProxyInit,
        settings: Settings,
        tmp_path: Path,
    ) -> None:
        info_bin = _write_fake_voms_proxy_info(
            tmp_path / "fake-voms-proxy-info", 'echo "no nickname here"\nexit 0'
        )
        settings = Settings(
            _env_file=None,
            home_root=settings.home_root,
            voms_proxy_info_bin=str(info_bin),
        )

        minted = await mint_proxy(
            "gstark", _passphrase(), "atlas", "192:00", settings, uid=12345, gid=12345
        )

        assert minted.nickname is None
        assert "BEGIN CERTIFICATE" in minted.pem

    async def test_mint_still_succeeds_when_binary_missing(
        self,
        fake_voms_proxy_init: FakeVomsProxyInit,
        settings: Settings,
    ) -> None:
        # settings' voms_proxy_info_bin already points at a nonexistent
        # path (see the settings fixture above).
        minted = await mint_proxy(
            "gstark", _passphrase(), "atlas", "192:00", settings, uid=12345, gid=12345
        )

        assert minted.nickname is None
        assert "BEGIN CERTIFICATE" in minted.pem

    async def test_mint_still_succeeds_on_nonzero_exit(
        self,
        fake_voms_proxy_init: FakeVomsProxyInit,
        settings: Settings,
        tmp_path: Path,
    ) -> None:
        info_bin = _write_fake_voms_proxy_info(
            tmp_path / "fake-voms-proxy-info",
            'echo "no such proxy file" >&2\nexit 1',
        )
        settings = Settings(
            _env_file=None,
            home_root=settings.home_root,
            voms_proxy_info_bin=str(info_bin),
        )

        minted = await mint_proxy(
            "gstark", _passphrase(), "atlas", "192:00", settings, uid=12345, gid=12345
        )

        assert minted.nickname is None
        assert "BEGIN CERTIFICATE" in minted.pem

    async def test_extraction_failure_is_logged_as_warning_not_error(
        self,
        fake_voms_proxy_init: FakeVomsProxyInit,
        settings: Settings,
    ) -> None:
        with capture_logs() as cap_logs:
            await mint_proxy(
                "gstark",
                _passphrase(),
                "atlas",
                "192:00",
                settings,
                uid=12345,
                gid=12345,
            )

        warnings = [entry for entry in cap_logs if entry.get("log_level") == "warning"]
        assert warnings
        assert any(entry.get("event") == "voms_proxy_info_failed" for entry in warnings)
