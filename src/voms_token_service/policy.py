"""Mint policy enforcement: cap caller-supplied `valid`, allowlist `voms`.

The broker only proves the caller is who they say they are, not that they
should be allowed to mint a month-long proxy or a proxy for an arbitrary VO
(maniaclab/voms-token-service#10) — both limits are operator-set via
Settings.max_valid/Settings.allowed_voms (chart values `config.maxValid`/
`config.allowedVoms`) and enforced here, against the request in app.py,
before voms-proxy-init ever runs.
"""

from __future__ import annotations

import re

# voms-proxy-init's own `--valid` format: "<hours>:<minutes>", minutes
# zero-padded to two digits and capped at 59 (there is no rollover — e.g.
# "24:60" is invalid, not "25:00").
_VALID_PATTERN = re.compile(r"^(\d+):([0-5][0-9])$")


class InvalidValidError(ValueError):
    """Raised when a caller-supplied `valid` is not a well-formed H:MM duration."""


class ValidTooLongError(ValueError):
    """Raised when a caller-supplied `valid` exceeds Settings.max_valid."""


class VomsNotAllowedError(ValueError):
    """Raised when a caller-supplied `voms` is not in Settings.allowed_voms."""


def _parse_valid_minutes(valid: str) -> int:
    """Parse a `--valid` "H:MM" string into total minutes, or raise InvalidValidError."""
    match = _VALID_PATTERN.match(valid)
    if match is None:
        raise InvalidValidError(f"valid must be an H:MM duration, got {valid!r}")
    hours, minutes = match.groups()
    return int(hours) * 60 + int(minutes)


def check_valid(valid: str, *, max_valid: str) -> None:
    """Raise if *valid* is malformed or exceeds *max_valid* (both "H:MM" strings)."""
    requested_minutes = _parse_valid_minutes(valid)
    max_minutes = _parse_valid_minutes(max_valid)
    if requested_minutes > max_minutes:
        raise ValidTooLongError(
            f"valid {valid!r} exceeds the policy maximum {max_valid!r}"
        )


def check_voms(voms: str, *, allowed_voms: list[str]) -> None:
    """Raise VomsNotAllowedError if *voms* is not in *allowed_voms*."""
    if voms not in allowed_voms:
        raise VomsNotAllowedError(
            f"voms {voms!r} is not allowed (allowed: {', '.join(allowed_voms)})"
        )
