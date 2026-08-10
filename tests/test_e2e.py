"""End-to-end test against a real deployment — never faked.

Requires a real deployed voms-token-service (with real ~/.globus certs
mounted, a real voms-proxy-init, and real VOMS server connectivity), a real
af-mcp-broker minting AF Broker Identity Tokens, and a real Globus passphrase
for a real AF user. None of that can be faked without defeating the point of
an e2e test, so this module is skipped unless explicitly opted into:

    VOMS_E2E=1 \\
    VOMS_TOKEN_SERVICE_URL=https://voms-token.af.uchicago.edu \\
    AF_BROKER_IDENTITY_TOKEN=<freshly-minted broker token> \\
    VOMS_E2E_UNIXNAME=<real unixname> \\
    VOMS_E2E_UID=<real uid> \\
    VOMS_E2E_GID=<real gid> \\
    VOMS_E2E_PASSPHRASE=<real Globus key passphrase> \\
    pixi run test

The broker token must be freshly minted (they are short-lived) with
aud=voms-token-service.
"""

from __future__ import annotations

import os

import httpx
import pytest

pytestmark = pytest.mark.skipif(
    os.environ.get("VOMS_E2E") != "1",
    reason="requires a real deployment, broker, and Globus passphrase; set VOMS_E2E=1 to run",
)


async def test_mint_proxy_against_real_service() -> None:
    base_url = os.environ["VOMS_TOKEN_SERVICE_URL"]
    broker_token = os.environ["AF_BROKER_IDENTITY_TOKEN"]

    async with httpx.AsyncClient() as client:
        resp = await client.post(
            f"{base_url}/v1/mint",
            headers={"Authorization": f"Bearer {broker_token}"},
            json={
                "unixname": os.environ["VOMS_E2E_UNIXNAME"],
                "uid": int(os.environ["VOMS_E2E_UID"]),
                "gid": int(os.environ["VOMS_E2E_GID"]),
                "passphrase": os.environ["VOMS_E2E_PASSPHRASE"],
            },
            timeout=60.0,
        )

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert "BEGIN CERTIFICATE" in body["pem"]
    assert body["dn"]
    assert body["expires_at"]
