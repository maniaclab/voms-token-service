"""VOMS proxy minting via the ``voms-proxy-init`` CLI.

The user's Globus private-key passphrase is the only secret this service
receives that it does not itself own. It is transmitted to voms-proxy-init
over the subprocess's stdin (``--pwstdin``) — never on argv, never logged —
and the buffer holding it is zeroed in place immediately after use. The
minted proxy is written to a per-user pod-tmpfs dir ({proxy_tmp_root}/
{unixname}) that the impersonated child CREATES ITSELF under umask 077 — so
it is owned by the real uid, mode 0700, scoped to that user, and needs no
chown/CAP_CHOWN. The read-back+cleanup is a second impersonated subprocess
(cat && rm -f of the exact file — nothing recursive exists in this service),
so root never touches user-owned files or dirs at all, and the homes mount
stays read-only.
"""

from __future__ import annotations

import asyncio
import os
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

import structlog
from cryptography import x509

from voms_token_service.paths import (
    proxy_out_dir,
    proxy_out_path,
    user_home,
    usercert_path,
    userkey_path,
)

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


_CREDENTIAL_PERMISSIONS_DETAIL = (
    "~/.globus/userkey.pem must be owned by you and readable only by you "
    "(mode 0400 or 0600). Fix with: chmod 400 ~/.globus/userkey.pem"
)


class CredentialPermissionsError(Exception):
    """Raised when voms-proxy-init rejects the user's key file ownership/permissions.

    Distinct from BadPassphraseError (must NOT count against the broker's
    unlock rate limiter) and from MintingError (retrying cannot help — the
    user has to fix their files). The message is a fixed, user-actionable
    string, never voms-proxy-init's stderr.
    """

    def __init__(self) -> None:
        super().__init__(_CREDENTIAL_PERMISSIONS_DETAIL)


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


# Substrings grid sslutils prints when it rejects the key file itself. The
# check behind these is ownership + mode: the key must be OWNED by the
# process's effective uid and carry no group/other bits — which is also why
# minting impersonates the requesting user (see mint_proxy).
_CREDENTIAL_PERMISSION_MARKERS: tuple[str, ...] = (
    "bad file system permissions",
    "key must only be readable",
)


def _is_credential_permissions(stderr: str) -> bool:
    lowered = stderr.lower()
    return any(marker in lowered for marker in _CREDENTIAL_PERMISSION_MARKERS)


async def mint_proxy(
    unixname: str,
    passphrase: bytearray,
    voms: str,
    valid: str,
    settings: Settings,
    *,
    uid: int,
    gid: int,
) -> MintedProxy:
    """Mint a VOMS proxy for *unixname* by shelling out to voms-proxy-init.

    Runs::

        voms-proxy-init --rfc --voms <voms> --valid <valid> \\
            --cert <usercert> --key <userkey> --out <tmpfile> --pwstdin

    writing the proxy to $HOME/x509_u$UID in the user's own home, feeding
    *passphrase* on stdin. Takes ownership of
    *passphrase* and zeros it (and the stdin buffer built from it) before
    returning, on every path — success, bad passphrase, or infra failure.

    The subprocess call is synchronous (``subprocess.run``, offloaded to a
    thread via ``run_in_executor``) rather than ``asyncio.create_subprocess_exec``
    — mirroring af-mcp-platform's own local-dev VOMS minting path
    (``credentials/x509.py:_mint_local``) — so the timeout is enforced by
    the stdlib's own process-group kill on expiry, not by cancelling an
    asyncio subprocess transport mid-flight.
    """
    usercert = usercert_path(settings, unixname)
    userkey = userkey_path(settings, unixname)

    home = user_home(settings, unixname)
    out_dir = proxy_out_dir(settings, unixname)
    out_path = proxy_out_path(settings, unixname, uid)

    # voms-proxy-init requires the key file be OWNED by the process's
    # effective uid (grid sslutils checks ownership, not just mode), so when
    # running as root — the production pod — the child runs AS the
    # requesting user (CAP_SETUID/CAP_SETGID in the chart); the homes key
    # read then carries the real uid (correct NFS semantics, mount stays
    # read-only). HOME points at the user's home so the binary's incidental
    # dotfile lookups don't hit root's. Outside the pod (tests, local dev as
    # non-root) no impersonation is possible or needed.
    run_user: int | None = None
    run_group: int | None = None
    run_extra_groups: list[int] | None = None
    if os.geteuid() == 0:
        run_user, run_group, run_extra_groups = uid, gid, []
    child_env = {**os.environ, "HOME": str(home)}

    # The per-user working dir is created BY the impersonated child under
    # umask 077 (owned real uid, mode 0700 — no chown, no CAP_CHOWN).
    # mkdir -p is idempotent for the same user's next mint; in the
    # (unreachable within this pod's threat model) case of a wrong-owner
    # dir already existing, the proxy write simply fails closed. There is
    # deliberately NO recursive deletion anywhere in this service: an
    # rm -rf on a config-derived path is a wipe waiting for a
    # misconfiguration. "$1" positional args keep unixname-derived paths
    # out of shell interpolation.
    if run_user is not None:
        prep = await _run_as_user(
            [
                "bash",
                "-c",
                'umask 077; mkdir -p "$1"',
                "bash",
                str(out_dir),
            ],
            run_user=run_user,
            run_group=run_group,
            run_extra_groups=run_extra_groups,
            env=child_env,
        )
        if prep.returncode != 0:
            logger.error(
                "voms_proxy_workdir_failed",
                unixname=unixname,
                uid=uid,
                stderr=prep.stderr.decode(errors="replace").strip(),
            )
            raise MintingError("failed to prepare the proxy working directory")
    else:
        out_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
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
                    user=run_user,
                    group=run_group,
                    extra_groups=run_extra_groups,
                    env=child_env,
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
            if _is_credential_permissions(stderr_text):
                logger.error(
                    "voms_proxy_init_credential_permissions",
                    returncode=result.returncode,
                    stderr=stderr_text,
                    unixname=unixname,
                    uid=uid,
                    gid=gid,
                )
                raise CredentialPermissionsError
            logger.error(
                "voms_proxy_init_failed",
                returncode=result.returncode,
                stderr=stderr_text,
                unixname=unixname,
                uid=uid,
                gid=gid,
            )
            raise MintingError(f"voms-proxy-init exited {result.returncode}")

        proxy_pem = await _read_proxy_as_user(
            out_path,
            unixname,
            run_user=run_user,
            run_group=run_group,
            run_extra_groups=run_extra_groups,
        )
    finally:
        # The proxy file deliberately persists in the user's home (their
        # own 0600 session proxy, per the login-node convention); there is
        # no pod-side temp state to clean up.
        pass

    dn, voms_attributes, expires_at = _parse_proxy_pem(proxy_pem)
    return MintedProxy(
        pem=proxy_pem.decode(),
        dn=dn,
        voms_attributes=voms_attributes,
        expires_at=expires_at,
    )


async def _run_as_user(
    argv: list[str],
    *,
    run_user: int | None,
    run_group: int | None,
    run_extra_groups: list[int] | None,
    env: dict[str, str] | None = None,
    timeout: float = 30,
) -> subprocess.CompletedProcess[bytes]:
    """Run a short impersonated helper subprocess off the event loop."""
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(
        None,
        lambda: subprocess.run(
            argv,
            capture_output=True,
            check=False,
            timeout=timeout,
            user=run_user,
            group=run_group,
            extra_groups=run_extra_groups,
            env=env,
        ),
    )


async def _read_proxy_as_user(
    out_path: Path,
    unixname: str,
    *,
    run_user: int | None,
    run_group: int | None,
    run_extra_groups: list[int] | None,
) -> bytes:
    """Read the minted proxy PEM back, as the user when impersonating.

    The file is 0600, owned by the user, in the 0700 per-user tmpfs dir the
    impersonated child created — so the read (and the cleanup of that dir)
    also runs as the user: root never needs read or directory-write access
    to user-owned files. Raises MintingError if missing or empty.
    """
    if run_user is not None:
        # rm -f of the exact file only (never recursive, never a derived
        # directory); rm prints nothing, so stdout is purely the PEM. The
        # empty 0700 per-user dir persists on pod tmpfs and is reused.
        result = await _run_as_user(
            [
                "bash",
                "-c",
                'cat "$1" && rm -f -- "$1"',
                "bash",
                str(out_path),
            ],
            run_user=run_user,
            run_group=run_group,
            run_extra_groups=run_extra_groups,
        )
        if result.returncode != 0:
            logger.error(
                "voms_proxy_init_no_output",
                unixname=unixname,
                stderr=result.stderr.decode(errors="replace").strip(),
            )
            raise MintingError("voms-proxy-init produced no proxy file")
        proxy_pem = result.stdout
    else:
        try:
            proxy_pem = out_path.read_bytes()
        except OSError as exc:
            logger.exception("voms_proxy_init_no_output", unixname=unixname)
            raise MintingError("voms-proxy-init produced no proxy file") from exc
        finally:
            out_path.unlink(missing_ok=True)
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
