"""FastAPI application: one minting endpoint plus health probes.

Authorization model: none beyond identity, by design. The af-mcp-broker has
already authenticated and authorized the user before minting the AF Broker
Identity Token this service verifies; a valid token proves the call
genuinely came from the broker. The unixname/uid/gid to mint a proxy for
come from the request body — the broker asserts them there because it (not
this service) resolved the caller's POSIX identity from the directory. Do
not add capability logic here based on token claims.
"""

from __future__ import annotations

import hashlib
import shutil
import uuid
from dataclasses import asdict
from typing import Annotated

import structlog
from fastapi import APIRouter, Depends, FastAPI, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field, SecretStr

from voms_token_service.config import Settings, get_settings
from voms_token_service.identity import get_jwks, peek_sub, verify_broker_token
from voms_token_service.logging import configure_logging
from voms_token_service.minting import (
    BadPassphraseError,
    CredentialPermissionsError,
    MintingError,
    mint_proxy,
)
from voms_token_service.preflight import (
    InvalidUnixnameError,
    PreflightResult,
    run_preflight,
    validate_unixname,
)

logger = structlog.get_logger(__name__)

# ``auto_error=False`` so a missing header is audited before the 401 is raised.
_bearer_scheme = HTTPBearer(auto_error=False)

router = APIRouter()


class MintRequest(BaseModel):
    unixname: str
    uid: int
    gid: int
    passphrase: SecretStr
    voms: str | None = Field(default=None)
    valid: str | None = Field(default=None)


class MintResponse(BaseModel):
    pem: str
    dn: str
    voms_attributes: list[str]
    expires_at: str  # ISO8601 UTC


class PreflightCheck(BaseModel):
    name: str
    path: str
    exists: bool
    ok: bool
    mode: str | None = None
    readable_by_service: bool | None = None
    detail: str | None = None


class PreflightResponse(BaseModel):
    unixname: str
    root: str
    ok: bool
    checks: list[PreflightCheck]


def _to_preflight_response(result: PreflightResult) -> PreflightResponse:
    return PreflightResponse(
        unixname=result.unixname,
        root=result.root,
        ok=result.ok,
        checks=[PreflightCheck(**asdict(check)) for check in result.checks],
    )


def _audit(
    *,
    subject: str | None,
    unixname: str | None,
    dn_sha256: str | None,
    jti: str | None,
    outcome: str,  # "issued" | "denied" | "error"
    request_id: str,
) -> None:
    """One structlog JSON audit line per request.

    NEVER include the passphrase or the minted proxy PEM here — only the
    unixname and a hash of the DN, per the API contract. See also
    logging.SensitiveValueRedactProcessor for the backstop.
    """
    logger.info(
        "audit",
        subject=subject,
        unixname=unixname,
        dn_sha256=dn_sha256,
        jti=jti,
        outcome=outcome,
        request_id=request_id,
    )


@router.post("/v1/mint", response_model=MintResponse)
async def mint(
    request: Request,
    body: MintRequest,
    credentials: Annotated[
        HTTPAuthorizationCredentials | None, Depends(_bearer_scheme)
    ],
) -> MintResponse:
    settings: Settings = request.app.state.settings
    request_id = request.headers.get("x-request-id") or str(uuid.uuid4())

    if credentials is None:
        _audit(
            subject=None,
            unixname=None,
            dn_sha256=None,
            jti=None,
            outcome="denied",
            request_id=request_id,
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        claims = await verify_broker_token(credentials.credentials, settings)
    except HTTPException as exc:
        # 401 (invalid token) is a denial; anything else (e.g. the JWKS
        # fetch's 502) is a platform error, not the caller's fault.
        outcome = (
            "denied" if exc.status_code == status.HTTP_401_UNAUTHORIZED else "error"
        )
        _audit(
            subject=peek_sub(credentials.credentials),
            unixname=body.unixname,
            dn_sha256=None,
            jti=None,
            outcome=outcome,
            request_id=request_id,
        )
        raise

    subject: str = claims["sub"]
    jti: str | None = claims.get("jti")

    # Same path-safety gate as /v1/preflight: unixname becomes a filesystem
    # path component, so reject anything unsafe before touching paths.
    try:
        validate_unixname(body.unixname)
    except InvalidUnixnameError:
        _audit(
            subject=subject,
            unixname=None,
            dn_sha256=None,
            jti=jti,
            outcome="denied",
            request_id=request_id,
        )
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="invalid unixname",
        ) from None

    voms = body.voms or settings.default_voms
    valid = body.valid or settings.default_valid

    # Copy the passphrase into a mutable buffer at the earliest point
    # possible; mint_proxy takes ownership of it and zeros it (success or
    # failure) before returning. Only the pydantic SecretStr original is out
    # of reach of that discipline.
    passphrase_buf = bytearray(body.passphrase.get_secret_value().encode())
    try:
        minted = await mint_proxy(
            body.unixname,
            passphrase_buf,
            voms,
            valid,
            settings,
            uid=body.uid,
            gid=body.gid,
        )
    except BadPassphraseError:
        _audit(
            subject=subject,
            unixname=body.unixname,
            dn_sha256=None,
            jti=jti,
            outcome="denied",
            request_id=request_id,
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="bad passphrase",
        ) from None
    except CredentialPermissionsError as exc:
        # User-actionable (fix file ownership/mode) — 422 so the broker
        # neither counts it against the passphrase rate limiter (400) nor
        # tells the user to "retry later" (502). The message is a fixed
        # string from minting.py, never voms-proxy-init's stderr.
        _audit(
            subject=subject,
            unixname=body.unixname,
            dn_sha256=None,
            jti=jti,
            outcome="denied",
            request_id=request_id,
        )
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(exc),
        ) from None
    except MintingError as exc:
        # Generic detail only — voms-proxy-init's stderr was logged
        # server-side by minting.py and must never reach the client.
        _audit(
            subject=subject,
            unixname=body.unixname,
            dn_sha256=None,
            jti=jti,
            outcome="error",
            request_id=request_id,
        )
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Proxy minting failed.",
        ) from exc

    dn_sha256 = hashlib.sha256(minted.dn.encode()).hexdigest()
    _audit(
        subject=subject,
        unixname=body.unixname,
        dn_sha256=dn_sha256,
        jti=jti,
        outcome="issued",
        request_id=request_id,
    )
    return MintResponse(
        pem=minted.pem,
        dn=minted.dn,
        voms_attributes=minted.voms_attributes,
        expires_at=minted.expires_at.isoformat(),
    )


@router.get(
    "/v1/preflight/{unixname}",
    response_model=PreflightResponse,
    response_model_exclude_none=True,
)
async def preflight(
    unixname: str,
    request: Request,
    credentials: Annotated[
        HTTPAuthorizationCredentials | None, Depends(_bearer_scheme)
    ],
) -> PreflightResponse:
    """Grid-certificate readiness checklist for the AF portal, authenticated
    exactly like /v1/mint. Always 200 once authenticated — a missing
    directory or a bad key mode is data (``ok: false`` on the relevant
    check), not an error. Never reads credential file contents; every check
    only stats or open()+close()s a file.
    """
    settings: Settings = request.app.state.settings

    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )
    await verify_broker_token(credentials.credentials, settings)

    try:
        validate_unixname(unixname)
    except InvalidUnixnameError:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="invalid unixname",
        ) from None

    result = run_preflight(settings, unixname)
    return _to_preflight_response(result)


@router.get("/healthz")
async def healthz() -> dict[str, str]:
    return {"status": "ok"}


@router.get("/readyz")
async def readyz(request: Request) -> dict[str, str]:
    """Ready only when voms-proxy-init is executable and the broker JWKS is fetchable."""
    settings: Settings = request.app.state.settings
    problems: list[str] = []
    if shutil.which(settings.voms_proxy_init_bin) is None:
        problems.append(
            f"voms-proxy-init binary not found or not executable: "
            f"{settings.voms_proxy_init_bin}"
        )
    try:
        await get_jwks(settings)
    except HTTPException:
        problems.append(f"broker JWKS endpoint unreachable: {settings.broker_jwks_url}")
    if problems:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="; ".join(problems),
        )
    return {"status": "ready"}


def create_app(settings: Settings | None = None) -> FastAPI:
    """Build the application; tests pass explicit Settings, production uses env."""
    if settings is None:
        settings = get_settings()
    configure_logging(settings.log_level)
    application = FastAPI(
        title="voms-token-service",
        description="VOMS proxy minting for the AF MCP platform",
        version="0.1.3",
    )
    application.state.settings = settings
    application.include_router(router)
    return application


app = create_app()
