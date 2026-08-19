"""Shared filesystem path construction for a user's Globus credential directory.

Both ``minting.py`` (``mint_proxy``) and ``preflight.py`` (the
credential-preflight endpoint) read the same
``{home_root}/{unixname}/.globus/{usercert,userkey}.pem`` layout; this is the
single place that path is built so the two code paths can never drift apart.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from voms_token_service.config import Settings


def user_home(settings: Settings, unixname: str) -> Path:
    """The user's home directory under the mounted homes root."""
    return Path(settings.home_root) / unixname


def proxy_out_dir(settings: Settings, unixname: str) -> Path:
    """Per-user working dir for a mint: pod-local tmpfs, created by the impersonated child (owned uid, 0700)."""
    return Path(settings.proxy_tmp_root) / unixname


def proxy_out_path(settings: Settings, unixname: str, uid: int) -> Path:
    """Where the minted proxy is written inside the per-user tmpfs dir."""
    return proxy_out_dir(settings, unixname) / settings.proxy_filename_template.format(
        uid=uid
    )


def globus_dir(settings: Settings, unixname: str) -> Path:
    """The per-user Globus credential directory: ``{home_root}/{unixname}/.globus``."""
    return Path(settings.home_root) / unixname / ".globus"


def usercert_path(settings: Settings, unixname: str) -> Path:
    return globus_dir(settings, unixname) / "usercert.pem"


def userkey_path(settings: Settings, unixname: str) -> Path:
    return globus_dir(settings, unixname) / "userkey.pem"
