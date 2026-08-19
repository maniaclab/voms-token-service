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
    from pathlib import Path

    from tests.conftest import FakeVomsProxyInit


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    return Settings(_env_file=None, home_root=str(tmp_path / "homes"))


def _passphrase(text: str = FAKE_CORRECT_PASSPHRASE) -> bytearray:
    return bytearray(text.encode())


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

        await mint_proxy(
            "gstark", _passphrase(), "atlas", "192:00", settings, uid=4321, gid=8765
        )

        assert recorded["user"] == 4321
        assert recorded["group"] == 8765
        assert recorded["extra_groups"] == []
        # The per-request tmpdir must be writable by the child.
        assert chowns and chowns[0][1:] == (4321, 8765)

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

        await mint_proxy(
            "gstark", _passphrase(), "atlas", "192:00", settings, uid=4321, gid=8765
        )

        assert recorded["user"] is None
        assert recorded["group"] is None
        assert recorded["extra_groups"] is None
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
