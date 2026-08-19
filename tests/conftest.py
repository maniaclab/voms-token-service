"""Shared fixtures: RSA keypair, stubbed JWKS fetch, a broker-token factory,
and a fake ``voms-proxy-init`` executable that writes a real (self-signed)
proxy certificate so minting.py's cryptography-based parsing has something
real to parse.

The JWKS is never fetched over the network in tests — ``stub_jwks_fetch``
replaces ``identity._fetch_jwks`` (the single network boundary) with an
in-process stub serving keys generated here.
"""

from __future__ import annotations

import asyncio
import json
import os
import time
import uuid
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any, NamedTuple

import httpx
import jwt
import pytest
from cryptography import x509 as cx509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from fastapi import HTTPException

from voms_token_service import identity
from voms_token_service.app import create_app
from voms_token_service.config import Settings

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Callable
    from pathlib import Path

TEST_KID = "test-signing-key"

# The passphrase the fake voms-proxy-init treats as "correct". Any other
# stdin content is treated as a bad passphrase, mirroring a real openssl
# "bad decrypt" failure.
FAKE_CORRECT_PASSPHRASE = "correct-horse-battery-staple"


@pytest.fixture(scope="session")
def rsa_private_key() -> rsa.RSAPrivateKey:
    # 2048 bits keeps per-session generation fast while staying a realistic
    # RS256 key size.
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(scope="session")
def other_rsa_private_key() -> rsa.RSAPrivateKey:
    """A second keypair NOT in the served JWKS — for wrong-signature tests."""
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(scope="session")
def jwks(rsa_private_key: rsa.RSAPrivateKey) -> list[dict[str, Any]]:
    jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(rsa_private_key.public_key()))
    jwk.update({"kid": TEST_KID, "alg": "RS256", "use": "sig"})
    return [jwk]


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    # The minted proxy is written into the user's home ($HOME/x509_u$UID),
    # so the endpoint tests' user ("gstark") needs a home under a tmp
    # home_root — in production the NFS-mounted real home always exists.
    (tmp_path / "homes" / "gstark").mkdir(parents=True, exist_ok=True)
    return Settings(
        _env_file=None,
        broker_jwks_url="https://broker.test/jwks",
        broker_issuer="https://broker.test",
        home_root=str(tmp_path / "homes"),
        # Nonexistent by default so mint tests stay hermetic: the nickname
        # lookup fails closed (None, a logged warning) without shelling out
        # to whatever real voms-proxy-info happens to be on PATH. Tests that
        # care about nickname extraction override this explicitly.
        voms_proxy_info_bin="/nonexistent/voms-proxy-info",
    )


class JwksFetchStub:
    """Callable standing in for ``identity._fetch_jwks``.

    Counts calls, can be told to fail (mimicking the real fetch's 502), and
    can delay to expose single-flight behavior.
    """

    def __init__(self, keys: list[dict[str, Any]]) -> None:
        self.keys = keys
        self.calls = 0
        self.fail = False
        self.delay = 0.0

    async def __call__(self, jwks_url: str) -> list[dict[str, Any]]:
        self.calls += 1
        if self.delay:
            await asyncio.sleep(self.delay)
        if self.fail:
            raise HTTPException(
                status_code=502,
                detail=f"Unable to reach JWKS endpoint: {jwks_url}",
            )
        return self.keys


@pytest.fixture
def stub_jwks_fetch(
    jwks: list[dict[str, Any]], monkeypatch: pytest.MonkeyPatch
) -> JwksFetchStub:
    identity._jwks_cache.clear()
    stub = JwksFetchStub(jwks)
    monkeypatch.setattr(identity, "_fetch_jwks", stub)
    return stub


@pytest.fixture
def make_token(
    rsa_private_key: rsa.RSAPrivateKey, settings: Settings
) -> Callable[..., str]:
    """Factory for AF Broker Identity Tokens with controllable claims."""

    def _make(
        *,
        sub: str = "af-user-subject",
        issuer: str | None = None,
        audience: str | None = None,
        key: rsa.RSAPrivateKey | None = None,
        kid: str | None = TEST_KID,
        expires_in: int = 300,
        omit: tuple[str, ...] = (),
        extra: dict[str, Any] | None = None,
    ) -> str:
        now = int(time.time())
        claims: dict[str, Any] = {
            "iss": issuer or settings.broker_issuer,
            "sub": sub,
            "aud": audience or settings.expected_audience,
            "exp": now + expires_in,
            "iat": now,
            "jti": str(uuid.uuid4()),
        }
        if extra:
            claims.update(extra)
        for claim in omit:
            claims.pop(claim, None)
        headers = {"kid": kid} if kid is not None else None
        return jwt.encode(
            claims, key or rsa_private_key, algorithm="RS256", headers=headers
        )

    return _make


@pytest.fixture(scope="session")
def fake_proxy_pem() -> bytes:
    """A real, self-signed X.509 certificate PEM standing in for a minted proxy.

    Not an actual RFC 3820 proxy chain — just enough of a real certificate
    (subject/issuer DN, notAfter) for minting.py's cryptography-based parser
    to exercise against real ASN.1, rather than a hand-rolled fake it would
    have to special-case.
    """
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = cx509.Name(
        [
            cx509.NameAttribute(NameOID.COUNTRY_NAME, "CH"),
            cx509.NameAttribute(NameOID.ORGANIZATION_NAME, "CERN"),
            cx509.NameAttribute(NameOID.COMMON_NAME, "Test User"),
            cx509.NameAttribute(NameOID.COMMON_NAME, "proxy"),
        ]
    )
    cert = (
        cx509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(cx509.random_serial_number())
        .not_valid_before(datetime.now(UTC) - timedelta(minutes=5))
        .not_valid_after(datetime.now(UTC) + timedelta(hours=192))
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM) + key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )


class FakeVomsProxyInit(NamedTuple):
    path: Path
    args_file: Path


def _install_fake_bin(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, body: str
) -> Path:
    """Write an executable ``voms-proxy-init`` shell script into a tmpdir and prepend that tmpdir to PATH."""
    bin_dir = tmp_path / "fake-bin"
    bin_dir.mkdir(exist_ok=True)
    script = bin_dir / "voms-proxy-init"
    script.write_text(f"#!/bin/sh\n{body}\n")
    script.chmod(0o755)
    monkeypatch.setenv("PATH", f"{bin_dir}{os.pathsep}{os.environ['PATH']}")
    return script


# Shared shell fragment: parse argv looking for the value following --out,
# then read the passphrase from stdin (voms-proxy-init's real --pwstdin
# behavior) and compare it to FAKE_CORRECT_PASSPHRASE. On success, copies the
# pre-generated fake proxy PEM to the --out path; on mismatch, fails the way
# openssl's PEM routines fail on a wrong key passphrase.
_FAKE_BIN_DISPATCH = f"""
out=""
while [ $# -gt 0 ]; do
  case "$1" in
    --out) out="$2"; shift 2 ;;
    *) shift ;;
  esac
done
IFS= read -r passphrase
if [ "$passphrase" = "{FAKE_CORRECT_PASSPHRASE}" ]; then
  cp "$FAKE_PROXY_PEM_PATH" "$out"
  exit 0
else
  echo "unable to load Private Key" >&2
  echo "140736319512224:error:0906A065:PEM routines:PEM_do_header:bad decrypt:pem_lib.c:461:" >&2
  exit 1
fi
"""


@pytest.fixture
def fake_voms_proxy_init(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    fake_proxy_pem: bytes,
) -> FakeVomsProxyInit:
    """A fake voms-proxy-init on PATH: records its argv, writes a real proxy PEM to --out."""
    args_file = tmp_path / "voms_args.txt"
    proxy_pem_path = tmp_path / "fake_proxy_source.pem"
    proxy_pem_path.write_bytes(fake_proxy_pem)
    monkeypatch.setenv("FAKE_PROXY_PEM_PATH", str(proxy_pem_path))
    script = _install_fake_bin(
        tmp_path,
        monkeypatch,
        f'echo "$@" > "{args_file}"\n{_FAKE_BIN_DISPATCH}',
    )
    return FakeVomsProxyInit(path=script, args_file=args_file)


@pytest.fixture
def hanging_voms_proxy_init(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A fake voms-proxy-init that never returns — for timeout tests."""
    return _install_fake_bin(tmp_path, monkeypatch, "sleep 100")


@pytest.fixture
def make_client(
    stub_jwks_fetch: JwksFetchStub,
) -> Callable[[Settings], httpx.AsyncClient]:
    """Factory building an ASGI test client around a fresh app for *settings*."""

    def _make(settings: Settings) -> httpx.AsyncClient:
        app = create_app(settings)
        return httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        )

    return _make


@pytest.fixture
async def client(
    make_client: Callable[[Settings], httpx.AsyncClient], settings: Settings
) -> AsyncIterator[httpx.AsyncClient]:
    async with make_client(settings) as test_client:
        yield test_client
