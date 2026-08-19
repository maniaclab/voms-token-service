"""Credential preflight checks for the AF portal's "Grid Certificates" checklist.

Read-only diagnostics: every check only stats or open()+close()s a file
under {settings.home_root}/{unixname}/.globus — never reads file contents.
This doubles as a mount/root-squash diagnostic: a file with permission bits
that look fine can still be unreadable if the NFS export or this pod's
CAP_DAC_READ_SEARCH doesn't behave the way the mode suggests, and an actual
open() is the only way to find that out.
"""

from __future__ import annotations

import re
import stat
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from voms_token_service.paths import globus_dir, usercert_path, userkey_path

if TYPE_CHECKING:
    from pathlib import Path

    from voms_token_service.config import Settings

# A single safe path segment: must start with an alphanumeric or underscore,
# then alphanumeric/underscore/dot/hyphen. This blocks a leading "." (so
# ".", ".." and dotfile-style names can never reach
# {home_root}/{unixname}) and "/" outright (defense in depth — FastAPI's
# default path-segment routing already can't deliver a decoded "/" here,
# since Starlette matches routes against the still-encoded path and 404s
# rather than treating %2F as a literal separator).
_UNIXNAME_PATTERN = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]*$")


class InvalidUnixnameError(ValueError):
    """Raised by validate_unixname when *unixname* is not a safe path segment."""


def validate_unixname(unixname: str) -> None:
    """Reject any unixname that could escape {home_root}/{unixname}/.globus.

    POST /v1/mint (minting.py) applies no equivalent check on its own
    unixname field today — that endpoint only ever hands the resulting path
    to voms-proxy-init's --cert/--key flags, which simply fails to find a
    bogus path. This endpoint instead stats and open()s files under the
    resulting path directly, which makes an unsanitized unixname a directly
    exploitable path-traversal primitive, so it gets its own explicit check.
    """
    if not _UNIXNAME_PATTERN.fullmatch(unixname):
        raise InvalidUnixnameError(unixname)


@dataclass(frozen=True)
class CredentialCheck:
    name: str
    path: str
    exists: bool
    ok: bool
    mode: str | None = None
    readable_by_service: bool | None = None
    detail: str | None = None


@dataclass(frozen=True)
class PreflightResult:
    unixname: str
    root: str
    ok: bool
    checks: list[CredentialCheck] = field(default_factory=list)


def _probe_readable(path: Path) -> tuple[bool, str | None]:
    """Attempt to open *path* for reading, then close without reading any bytes.

    This never reads file contents — it is a pure probe of whether the
    service's own process can open the file at all, which is the honest
    test of the homes mount + DAC/root-squash reality (see module
    docstring).
    """
    try:
        with path.open("rb"):
            pass
    except OSError as exc:
        return False, f"{exc.strerror or exc.__class__.__name__} (errno {exc.errno})"
    return True, None


def _mode_octal(mode_int: int) -> str:
    return format(mode_int, "04o")


def _missing_dir_detail(settings: Settings, unixname: str) -> str:
    return (
        "no .globus directory — copy your grid certificate to "
        f"{settings.home_root}/{unixname}/.globus/"
    )


def _check_cert_file(
    *, name: str, path: Path, enforce_private_mode: bool, missing_detail: str
) -> CredentialCheck:
    if not path.exists():
        return CredentialCheck(
            name=name, path=str(path), exists=False, ok=False, detail=missing_detail
        )
    if not path.is_file():
        return CredentialCheck(
            name=name,
            path=str(path),
            exists=True,
            ok=False,
            detail=f"{path.name} exists but is not a regular file",
        )

    mode_int = stat.S_IMODE(path.stat().st_mode)
    mode = _mode_octal(mode_int)
    readable, read_detail = _probe_readable(path)

    if not readable:
        return CredentialCheck(
            name=name,
            path=str(path),
            exists=True,
            mode=mode,
            readable_by_service=False,
            ok=False,
            detail=f"service cannot read {path.name}: {read_detail}",
        )

    if enforce_private_mode and mode_int & 0o077:
        return CredentialCheck(
            name=name,
            path=str(path),
            exists=True,
            mode=mode,
            readable_by_service=True,
            ok=False,
            detail=(
                f"{path.name} must not be group/other-accessible (found {mode}); "
                f"run: chmod 400 ~/.globus/{path.name}"
            ),
        )

    return CredentialCheck(
        name=name,
        path=str(path),
        exists=True,
        mode=mode,
        readable_by_service=True,
        ok=True,
    )


def run_preflight(settings: Settings, unixname: str) -> PreflightResult:
    """Run all credential-preflight checks for *unixname*.

    Callers MUST call validate_unixname(unixname) first and handle
    InvalidUnixnameError — this function does not re-validate, so the
    "invalid input never touches the filesystem" guarantee stays visible at
    a single call site (app.py) rather than being duplicated here.
    """
    root = globus_dir(settings, unixname)
    dir_exists = root.is_dir()

    checks: list[CredentialCheck] = [
        CredentialCheck(
            name="globus_dir",
            path=str(root),
            exists=dir_exists,
            ok=dir_exists,
            detail=None if dir_exists else _missing_dir_detail(settings, unixname),
        )
    ]

    if not dir_exists:
        missing_detail = _missing_dir_detail(settings, unixname)
        checks.append(
            CredentialCheck(
                name="usercert",
                path=str(usercert_path(settings, unixname)),
                exists=False,
                ok=False,
                detail=missing_detail,
            )
        )
        checks.append(
            CredentialCheck(
                name="userkey",
                path=str(userkey_path(settings, unixname)),
                exists=False,
                ok=False,
                detail=missing_detail,
            )
        )
    else:
        checks.append(
            _check_cert_file(
                name="usercert",
                path=usercert_path(settings, unixname),
                enforce_private_mode=False,
                missing_detail="usercert.pem not found",
            )
        )
        checks.append(
            _check_cert_file(
                name="userkey",
                path=userkey_path(settings, unixname),
                enforce_private_mode=True,
                missing_detail="userkey.pem not found",
            )
        )

    ok = all(check.ok for check in checks)
    return PreflightResult(unixname=unixname, root=str(root), ok=ok, checks=checks)
