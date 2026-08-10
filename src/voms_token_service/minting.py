"""VOMS proxy minting via the ``voms-proxy-init`` CLI.

The user's Globus private-key passphrase is the only secret this service
receives that it does not itself own. It is transmitted to voms-proxy-init
over the subprocess's stdin (``--pwstdin``) — never on argv, never logged —
and the buffer holding it is zeroed in place immediately after use. The
minted proxy is written to a private per-request tmpdir that is always
removed once its contents have been read back into memory.
"""

from __future__ import annotations

import asyncio
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

import structlog
from cryptography import x509

if TYPE_CHECKING:
    from datetime import datetime

    from voms_token_service.config import Settings

logger = structlog.get_logger(__name__)


class MintingError(Exception):
    """Raised when voms-proxy-init fails for a reason other than a bad passphrase.

    The message is deliberately generic: stderr from the binary is logged
    server-side (it can reference VOMS server hostnames or filesystem paths)
    and must never reach the client.
    """


class BadPassphraseError(Exception):
    """Raised when voms-proxy-init fails because the private key passphrase was wrong."""


@dataclass(frozen=True)
class MintedProxy:
    pem: str
    dn: str
    voms_attributes: list[str]
    expires_at: datetime


def _zero_bytearray(buf: bytearray) -> None:
    """Overwrite *buf* in place with NUL bytes.

    Unlike rebinding an immutable ``bytes`` object, mutating a ``bytearray``
    genuinely clears the underlying buffer, so a secret held in one is
    erased once this returns.
    """
    for i in range(len(buf)):
        buf[i] = 0


# Substrings openssl's PEM routines print when a private key fails to
# decrypt with the given passphrase. This is how a bad passphrase is told
# apart from any other voms-proxy-init failure (unreachable VOMS server,
# missing cert files, expired EEC, ...), which must instead surface as a
# generic 502 rather than the specific 400 the broker treats differently
# for rate limiting.
_BAD_PASSPHRASE_MARKERS: tuple[str, ...] = (
    "bad decrypt",
    "bad pass phrase",
    "bad password",
)


def _is_bad_passphrase(stderr: str) -> bool:
    lowered = stderr.lower()
    return any(marker in lowered for marker in _BAD_PASSPHRASE_MARKERS)


async def mint_proxy(
    unixname: str,
    passphrase: bytearray,
    voms: str,
    valid: str,
    settings: Settings,
) -> MintedProxy:
    """Mint a VOMS proxy for *unixname* by shelling out to voms-proxy-init.

    Runs::

        voms-proxy-init --rfc --voms <voms> --valid <valid> \\
            --cert <usercert> --key <userkey> --out <tmpfile> --pwstdin

    in a private tmpdir, feeding *passphrase* on stdin. Takes ownership of
    *passphrase* and zeros it (and the stdin buffer built from it) before
    returning, on every path — success, bad passphrase, or infra failure.

    The subprocess call is synchronous (``subprocess.run``, offloaded to a
    thread via ``run_in_executor``) rather than ``asyncio.create_subprocess_exec``
    — mirroring af-mcp-platform's own local-dev VOMS minting path
    (``credentials/x509.py:_mint_local``) — so the timeout is enforced by
    the stdlib's own process-group kill on expiry, not by cancelling an
    asyncio subprocess transport mid-flight.
    """
    usercert = Path(settings.home_root) / unixname / ".globus" / "usercert.pem"
    userkey = Path(settings.home_root) / unixname / ".globus" / "userkey.pem"

    tmpdir = Path(tempfile.mkdtemp(prefix="voms-proxy-"))
    out_path = tmpdir / "proxy.pem"
    argv = [
        settings.voms_proxy_init_bin,
        "--rfc",
        "--voms",
        voms,
        "--valid",
        valid,
        "--cert",
        str(usercert),
        "--key",
        str(userkey),
        "--out",
        str(out_path),
        "--pwstdin",
    ]

    # Convert to bytes only at the subprocess I/O boundary; the trailing
    # newline mirrors what a human typing the passphrase at a terminal
    # prompt would send.
    stdin_payload = bytearray(passphrase)
    stdin_payload.extend(b"\n")
    try:
        loop = asyncio.get_running_loop()
        try:
            result = await loop.run_in_executor(
                None,
                lambda: subprocess.run(
                    argv,
                    input=bytes(stdin_payload),
                    capture_output=True,
                    check=False,
                    timeout=settings.proxy_init_timeout_seconds,
                ),
            )
        except OSError as exc:
            # Binary missing or not executable.
            logger.exception(
                "voms_proxy_init_spawn_failed",
                binary=settings.voms_proxy_init_bin,
                error=str(exc),
            )
            raise MintingError("failed to invoke voms-proxy-init") from exc
        except subprocess.TimeoutExpired as exc:
            logger.exception(
                "voms_proxy_init_timed_out",
                unixname=unixname,
                timeout=settings.proxy_init_timeout_seconds,
            )
            raise MintingError("voms-proxy-init timed out") from exc
    finally:
        _zero_bytearray(stdin_payload)
        _zero_bytearray(passphrase)

    try:
        if result.returncode != 0:
            stderr_text = result.stderr.decode(errors="replace").strip()
            if _is_bad_passphrase(stderr_text):
                raise BadPassphraseError("bad passphrase")
            logger.error(
                "voms_proxy_init_failed",
                returncode=result.returncode,
                stderr=stderr_text,
                unixname=unixname,
            )
            raise MintingError(f"voms-proxy-init exited {result.returncode}")

        proxy_pem = _read_proxy_file(out_path, unixname)
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)

    dn, voms_attributes, expires_at = _parse_proxy_pem(proxy_pem)
    return MintedProxy(
        pem=proxy_pem.decode(),
        dn=dn,
        voms_attributes=voms_attributes,
        expires_at=expires_at,
    )


def _read_proxy_file(out_path: Path, unixname: str) -> bytes:
    """Read the minted proxy PEM, raising MintingError if it is missing or empty."""
    try:
        proxy_pem = out_path.read_bytes()
    except OSError as exc:
        logger.exception("voms_proxy_init_no_output", unixname=unixname)
        raise MintingError("voms-proxy-init produced no proxy file") from exc
    if not proxy_pem:
        logger.error("voms_proxy_init_empty_output", unixname=unixname)
        raise MintingError("voms-proxy-init produced an empty proxy file")
    return proxy_pem


def _parse_proxy_pem(proxy_pem: bytes) -> tuple[str, list[str], datetime]:
    """Parse a PEM proxy file and extract DN, VOMS attributes, and notAfter.

    Parsed directly with the ``cryptography`` library rather than by
    shelling out to a second binary (``voms-proxy-info``) — this service's
    entire design point is shelling out to exactly one binary
    (voms-proxy-init). The proxy PEM may contain multiple certs (the proxy
    chain) plus a private key; only the first certificate block — the newly
    minted proxy cert, whose *issuer* is the user's own identity — carries
    the DN and validity this service reports (mirrors
    af-mcp-platform's credentials/x509.py:_parse_proxy_pem).
    """
    pem_blocks = proxy_pem.split(b"-----END CERTIFICATE-----")
    first_cert_pem = pem_blocks[0] + b"-----END CERTIFICATE-----\n"
    cert = x509.load_pem_x509_certificate(first_cert_pem)

    dn = cert.issuer.rfc4514_string()
    expires_at = cert.not_valid_after_utc

    voms_attributes: list[str] = []
    try:
        # VOMS AC OID: 1.3.6.1.4.1.8005.100.100.5
        voms_oid = x509.ObjectIdentifier("1.3.6.1.4.1.8005.100.100.5")
        ext = cert.extensions.get_extension_for_oid(voms_oid)
        raw_ext = ext.value
        voms_attributes = [f"<voms_ac_bytes:{len(raw_ext.value)}b>"]  # type: ignore[attr-defined]
    except x509.ExtensionNotFound:
        pass

    return dn, voms_attributes, expires_at
