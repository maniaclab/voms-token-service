from __future__ import annotations

from functools import lru_cache
from typing import Any

from pydantic import Field
from pydantic_settings import BaseSettings

# pydantic-settings matches env vars to field names case-insensitively, so the
# uppercase env var names (BROKER_JWKS_URL, ...) map to these fields without
# explicit aliases.


class Settings(BaseSettings):
    # Route handlers receive Settings via ``Depends``. FastAPI builds a request
    # model from the callable's signature, and the pydantic-settings
    # ``BaseSettings.__init__`` exposes private (``_cli_parse_args`` ...)
    # parameters that FastAPI cannot turn into fields. Overriding ``__init__``
    # with a plain ``**data`` signature keeps env loading intact while giving
    # FastAPI a clean signature to introspect.
    def __init__(self, **data: Any) -> None:
        super().__init__(**data)

    # Where the broker publishes the JWKS for its AF Broker Identity Token
    # signing keys (maniaclab/af-mcp-platform#162). The default points at a
    # broker running locally; production deployments must set BROKER_JWKS_URL
    # explicitly (see the Helm chart).
    broker_jwks_url: str = "http://localhost:8080/.well-known/jwks.json"

    # Required `iss` claim on inbound AF Broker Identity Tokens.
    broker_issuer: str = "https://mcp.af.uchicago.edu"

    # Required `aud` claim — this service's own identity in the protocol.
    expected_audience: str = "voms-token-service"

    # Root of the NFS-mounted home directories this pod reads from. The
    # user's certificate pair is expected at
    # ``{home_root}/{unixname}/.globus/{usercert,userkey}.pem``. This is a
    # deliberate departure from literal ``~<user>`` shell expansion: the
    # container never runs a shell as the target user, it just reads a path
    # under the mounted homes PVC.
    home_root: str = "/home"
    # Pod-local root under which each mint gets a per-user working dir
    # (``{proxy_tmp_root}/{unixname}``, created BY the impersonated child
    # under umask 077 — owned by the real uid, mode 0700). Lives on the
    # pod's tmpfs /tmp; the proxy never touches shared storage and the
    # homes mount stays read-only.
    proxy_tmp_root: str = "/tmp/x509"
    # Proxy filename inside that dir; ``{uid}`` is substituted.
    proxy_filename_template: str = "x509_u{uid}"

    # Path to (or bare name of, resolved via PATH) the voms-proxy-init
    # binary. Configurable so tests can substitute a fake executable and
    # non-standard installs can point elsewhere.
    voms_proxy_init_bin: str = "voms-proxy-init"

    # Defaults applied when the mint request omits `voms`/`valid`.
    default_voms: str = "atlas"
    default_valid: str = "192:00"

    # Wall-clock bound on the voms-proxy-init subprocess. A VOMS server that
    # never responds (or a hung network call) must not hang the request
    # forever; a timeout is treated as an infra failure (502), not a bad
    # passphrase.
    proxy_init_timeout_seconds: int = Field(default=60, gt=0)

    # How long a fetched JWKS is served from the in-process cache before a
    # refresh is attempted. A failed refresh serves the stale entry instead of
    # taking token verification down with it (see identity.py).
    jwks_cache_ttl_seconds: int = 300

    log_level: str = "INFO"

    model_config = {"env_file": ".env", "extra": "ignore"}


@lru_cache
def get_settings() -> Settings:
    """Return a process-wide cached Settings instance.

    Use as a FastAPI dependency (``Depends(get_settings)``) so ``.env`` is read
    once at first access rather than re-instantiated on every request.
    """
    return Settings()
