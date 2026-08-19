# voms-token-service

VOMS proxy minting for the UChicago ATLAS Analysis Facility MCP platform. A
deliberately tiny, auditable service: one minting endpoint, verified against
one credential type, shelling out to one binary.

## Why this service exists

Minting a VOMS proxy for a user requires reading their
`~/.globus/{usercert,userkey}.pem` and the passphrase that unlocks the
private key. Both are trust-domain-defining: the passphrase must never reach
the [af-mcp-broker](https://github.com/maniaclab/af-mcp-platform) (a
different trust domain holding many other credentials), and the NFS-backed
homes filesystem must not be mounted anywhere near it either.

This service is the **only** component in the platform that mounts user home
directories. It receives a user's identity (asserted by the broker, which
already resolved it from the directory) plus their Globus passphrase over
HTTPS, runs `voms-proxy-init` against that user's own certificate pair, and
returns the proxy PEM in the response body. The proxy is staged in a
per-user 0700 dir on the pod's own tmpfs — created, written, read back, and
removed entirely by impersonated subprocesses running AS the requesting
user, so the service process never touches user-owned files as root and the
homes mount stays read-only. Nothing is written to shared storage; the
passphrase lives only in memory and is zeroed immediately after use.

```
 LLM client                af-mcp-platform                 voms-token-service
     |                          |                                |
     |  MCP tool call           |                                |
     +------------------------->|                                |
     |                 [broker authenticates &                   |
     |                  authorizes the user, resolves             |
     |                  their POSIX identity]                     |
     |                          |  POST /v1/mint                 |
     |                          |  Bearer: AF Broker              |
     |                          |  Identity Token (RS256)         |
     |                          |  {unixname, uid, gid,           |
     |                          |   passphrase, voms, valid}      |
     |                          +------------------------------->|
     |                          |                        voms-token-service
     |                          |                                |
     |                          |                    verify JWT (broker JWKS)
     |                          |                    read ~<unixname>/.globus/*
     |                          |                                |
     |                          |                    voms-proxy-init --rfc
     |                          |                      --voms <voms>
     |                          |                      --valid <valid>
     |                          |                      --cert <usercert>
     |                          |                      --key <userkey>
     |                          |                      --out <tmpfile>
     |                          |                      --pwstdin
     |                          |                                |
     |                          |                    [passphrase zeroed from
     |                          |                     memory immediately;
     |                          |                     tmpdir removed after]
     |                          |<-------------------------------+
     |                          |  {pem, dn, voms_attributes,   |
     |                          |   expires_at}                  |
```

## The credential it verifies

This is a consumer of the **AF Broker Identity Token** internal protocol
([maniaclab/af-mcp-platform#162](https://github.com/maniaclab/af-mcp-platform/issues/162)),
the same protocol [condor-token-service](https://github.com/maniaclab/condor-token-service)
consumes: a short-lived RS256 JWT minted by the broker with claims
`iss`/`sub`/`aud`/`exp`/`iat`/`jti`. These are **identity assertions, not
capability claims** — the broker has already authorized the call before
minting the token, and this service derives no authorization from token
claims. A missing or invalid token is refused (401).

**Unlike condor-token-service**, the `unixname`/`uid`/`gid` to mint a proxy
for come from the **request body**, not the token: the broker resolves a
caller's POSIX identity from the directory per-request and asserts it
directly, so there is nothing gained by round-tripping it through the token
as well. The token's only job here is proving the call genuinely came from
the broker.

Verification fetches the broker's JWKS from `BROKER_JWKS_URL` (TTL-cached,
single-flight refresh, stale-served on fetch failure), then enforces
signature, issuer, audience, and expiry — the same JWKS caching discipline as
condor-token-service's `identity.py`. Every request produces exactly one JSON
audit line — subject, unixname, `sha256(dn)`, broker-token `jti`, outcome
(`issued|denied|error`), request id — and neither the passphrase nor the
minted proxy PEM is ever logged (`logging.py`'s
`SensitiveValueRedactProcessor` is the defense-in-depth backstop if a future
code path gets this wrong).

## API

| Endpoint | Auth | Behavior |
| --- | --- | --- |
| `POST /v1/mint` | `Authorization: Bearer <AF Broker Identity Token>` | Body `{"unixname": str, "uid": int, "gid": int, "passphrase": str, "voms": "atlas", "valid": "192:00"}` (`voms`/`valid` optional). Mints a VOMS proxy via `voms-proxy-init` against `{HOME_ROOT}/{unixname}/.globus/{usercert,userkey}.pem`. Returns `{"pem", "dn", "voms_attributes", "expires_at", "nickname"}` (`nickname` is a best-effort VOMS-attribute lookup — see below — and is `None` when extraction fails). 400 `{"detail": "bad passphrase"}` when the key's passphrase was wrong (detected from voms-proxy-init's openssl "bad decrypt" stderr); 401 invalid/missing token; 502 on any other minting failure (generic detail — stderr is logged server-side only, never returned). |
| `GET /v1/preflight/{unixname}` | `Authorization: Bearer <AF Broker Identity Token>` (same as `/v1/mint`) | Credential-readiness checklist for the AF portal's "Grid Certificates" checklist — see below. |
| `GET /healthz` | none | Always 200. |
| `GET /readyz` | none | 200 only when `voms-proxy-init` is executable and the broker JWKS is fetchable; 503 otherwise. |

Configuration is env-driven (`src/voms_token_service/config.py`):
`BROKER_JWKS_URL`, `BROKER_ISSUER`, `EXPECTED_AUDIENCE`, `HOME_ROOT`,
`VOMS_PROXY_INIT_BIN`, `DEFAULT_VOMS`, `DEFAULT_VALID`,
`PROXY_INIT_TIMEOUT_SECONDS`, `JWKS_CACHE_TTL_SECONDS`, `LOG_LEVEL`.

**No rate limiter here, unlike condor-token-service.** condor-token-service
guards a symmetric pool-password key that could mint tokens for any identity
in the pool, so it needs its own throttle. This service instead runs the
*user's own* passphrase against the *user's own* certificate; the broker's
`CredentialCache` (`af-mcp-platform`'s `credentials/x509.py`) already
rate-limits unlock attempts per uid (`check_unlock_rate_limit`,
`record_failed_unlock`) before ever calling here. Adding a second limiter in
this service would duplicate that policy in the wrong trust domain rather
than strengthen it.

## The exact voms-proxy-init invocation

```
voms-proxy-init --rfc --voms <voms> --valid <valid> \
    --cert <home_root>/<unixname>/.globus/usercert.pem \
    --key  <home_root>/<unixname>/.globus/userkey.pem \
    --out  <private-tmpdir>/proxy.pem \
    --pwstdin
```

The passphrase is written to stdin (never argv, never logged) as a
`bytearray`, and that buffer — plus the stdin copy built at the subprocess
I/O boundary — is zeroed (`_zero_bytearray` in `minting.py`, the same
discipline as `af-mcp-platform`'s `credentials/x509.py`) immediately after
the subprocess returns, on every path: success, bad passphrase, or timeout.
The private tmpdir holding the output proxy is removed once its contents
have been read back into memory. The subprocess call itself is a
synchronous `subprocess.run(timeout=...)` offloaded to a thread via
`run_in_executor` — mirroring `x509.py`'s own local-dev minting path —
rather than `asyncio.create_subprocess_exec`, which has a
cancellation/timeout hang on at least one platform when the target binary
is a PATH-resolved shebang script (encountered while writing this service's
own test suite; a real `voms-proxy-init` is a compiled binary with no
shebang layer, but the synchronous path sidesteps the question entirely).

DN, VOMS attributes, and the expiry are parsed directly from the resulting
proxy PEM with the `cryptography` library — **not** by shelling out to a
second binary (`voms-proxy-info`). This service's design point is minting
via exactly one binary; parsing the certificate this service just wrote,
with a library already in the dependency graph, gets the same information
without a second trust boundary.

The one owner-approved exception is the `nickname` VOMS attribute
(maniaclab/af-mcp-platform#191): unlike DN/expiry, it lives only in the VOMS
attribute certificate as rendered by `voms-proxy-info --all` — not in the
PEM's ASN.1 this service already parses, and not shown by `--text` either.
`mint_proxy` therefore makes one additional, read-only, impersonated
`voms-proxy-info --file <out_path> --all` call against the file it just
minted — strictly before the PEM read-back deletes that file — and treats
any extraction failure (binary missing, non-zero exit, no matching
attribute, unparseable output) as best-effort: `nickname: None`, logged as
a warning, never a mint failure. `nickname` is the caller's CERN/Rucio
account name, which AF unixnames don't match; the broker stores it for
downstream services (e.g. rucio-mcp) that need that mapping.

## Credential preflight (`GET /v1/preflight/{unixname}`)

Minting fails in ways a user can't self-diagnose from the broker's side:
their `~/.globus` directory doesn't exist yet, the cert/key pair hasn't
been copied over, or `userkey.pem` is left group/other-readable (which
`voms-proxy-init` itself refuses to use). This endpoint answers "is this
user's Globus credential in a state where minting could possibly work?"
without ever performing a mint — intended to sit behind a broker proxy
endpoint for the AF portal's "Grid Certificates" checklist (see
[maniaclab/af-mcp-platform](https://github.com/maniaclab/af-mcp-platform)
for that follow-up). It also doubles as a mount/root-squash diagnostic: a
file can look perfectly permissioned and still be unreadable if the NFS
homes mount, or this pod's `CAP_DAC_READ_SEARCH`, doesn't behave the way
the mode bits suggest — the only way to know for certain is to actually
try to open it, which is exactly what this endpoint does.

Authenticated exactly like `/v1/mint` (same broker-issued JWT, verified
against the same broker JWKS) — a missing or invalid token is still a 401.
Once authenticated, the endpoint is always 200: a missing directory or a
bad key mode is data (a per-check `"ok": false`), not an HTTP error, so the
portal can render the checklist directly from the response body. It never
reads credential file contents, only `stat()`s and `open()`+immediately
closes them.

Example request/response:

```
GET /v1/preflight/kratsg
Authorization: Bearer <AF Broker Identity Token>
```

```json
{
  "unixname": "kratsg",
  "root": "/home/kratsg/.globus",
  "ok": false,
  "checks": [
    {"name": "globus_dir", "path": "/home/kratsg/.globus", "exists": true, "ok": true, "detail": null},
    {"name": "usercert", "path": "/home/kratsg/.globus/usercert.pem", "exists": true, "mode": "0444", "readable_by_service": true, "ok": true, "detail": null},
    {"name": "userkey", "path": "/home/kratsg/.globus/userkey.pem", "exists": true, "mode": "0644", "readable_by_service": true, "ok": false, "detail": "userkey.pem must not be group/other-accessible (found 0644); run: chmod 400 ~/.globus/userkey.pem"}
  ]
}
```

`mode`/`readable_by_service` are omitted (not `null`) on the `globus_dir`
check — they don't apply to a directory — via
`response_model_exclude_none=True`; they're always present for the
`usercert`/`userkey` checks once the file exists.

**Why `userkey.pem` enforces a mode and `usercert.pem` doesn't.** The
private key's passphrase is the one secret this service is trusted with;
`voms-proxy-init` itself already refuses a group/other-readable key, so
flagging it here (rather than letting the user discover it via an opaque
mint failure) is the entire point of a *preflight* check. The certificate
is public by design — X.509 certs are meant to be handed out — so any mode
is accepted for `usercert.pem`.

**`unixname` path safety.** Unlike `POST /v1/mint` (whose `unixname` comes
from the request body and only ever reaches `voms-proxy-init --cert/--key`,
which just fails to find a bogus path), this endpoint stats and opens files
under the resulting path directly, which makes an unsanitized `unixname` a
directly exploitable path-traversal primitive. `preflight.validate_unixname`
rejects anything that isn't a single safe path segment (must start with an
alphanumeric character or underscore) before `run_preflight` ever touches
the filesystem — a request for `/v1/preflight/%2e%2e` (percent-encoded
`..`) gets a 422, never a stat() on a path outside `home_root`.

No Helm chart changes were needed for this endpoint: it's served on the
same port (8080) behind the same auth as `/v1/mint`, so the existing
`NetworkPolicy` ingress rule (broker pods only, port 8080) and readiness
probe already cover it.

## Deployment

The Helm chart at `charts/voms-token-service/` encodes the privilege model:

- **Homes PVC, read-only.** The chart mounts an existing PVC
  (`homes.existingClaim`, typically ReadOnlyMany NFS-backed) at
  `config.homeRoot` (`/home` by default) — the *only* storage this pod
  touches, and only for reading. Unlike condor-token-service (pinned to
  specific nodes holding a hostPath secret), this service has no node
  affinity requirement by default: any node that can mount the PVC can run
  it.
- **Privilege model: `runAsUser: 0` + `CAP_DAC_READ_SEARCH`, not plain
  root.** `~<user>/.globus/{usercert,userkey}.pem` are typically mode 0600,
  owned by that user — not root, and not group-readable by anything this
  pod could plausibly hold. Running as `runAsUser: 0` with `capabilities:
  {drop: [ALL]}` (condor-token-service's own approach, for the pool
  password it owns as root) would **not** be enough here: dropping every
  capability strips `CAP_DAC_OVERRIDE`/`CAP_DAC_READ_SEARCH` too, and
  without one of those, uid 0 does not bypass file permission checks. The
  chart retains exactly `CAP_DAC_READ_SEARCH` (read-only bypass; not the
  broader read+write+execute `CAP_DAC_OVERRIDE`) alongside `runAsUser: 0` —
  the minimum privilege that can read arbitrary users' files it doesn't
  own — plus `CAP_SETUID`/`CAP_SETGID`, because the `voms-proxy-init`
  **child runs as the requesting user** (grid sslutils requires the key be
  *owned* by the process's effective uid, so a root-run child rejects every
  user's key with "key must only be readable by the user"; impersonation
  also makes NFS homes access carry the real uid). A key with group/other
  permission bits is rejected with an actionable 422 (fix: `chmod 400`),
  distinct from both bad-passphrase (400, rate-limited by the broker) and
  infra failures (502, retryable). Everything else stays locked down: read-only root filesystem
  (voms-proxy-init's private tmpdir is a `Memory`-backed `emptyDir` at
  `/tmp`, so proxy key material never touches disk even transiently), no
  privilege escalation, `RuntimeDefault` seccomp, no ServiceAccount token.
- **NetworkPolicy** — ingress only from the broker pods; egress limited to
  DNS, the broker JWKS origin, the VOMS server(s) `voms-proxy-init`
  contacts, and (when `crlRefresh.enabled`) the CRL distribution points
  `refresh_crls.sh` fetches from (all `ipBlock` rules, since these servers
  are external to the cluster and DNS names can't appear directly in a
  `NetworkPolicy`; restrict `networkPolicy.voms.cidr` and
  `networkPolicy.crl.cidr` to real server IPs in production).
- **No ConfigMap** — all configuration is env-from-values, same as
  condor-token-service.
- **CRL freshness (`crlRefresh.*`).** The baked-in IGTF CA bundle
  (`ca-policy-lcg`) is only as fresh as the last image build, but its CRLs
  (the `*.r0` files under `X509_CERT_DIR`) go stale much faster — hours to
  days, depending on the CA. A Kubernetes CronJob can't help here: it runs
  in a separate pod and has no way to write into this Deployment's pod's
  `emptyDir`, so refreshing has to happen from inside the same pod. A
  `certificates` `emptyDir` is mounted over the baked `X509_CERT_DIR` path
  in the main container; an init container (`seed-certificates`) copies the
  baked bundle into it and does a best-effort first refresh (a network blip
  here must not block pod startup — the baked `.r0` files are a valid
  fallback); and a locked-down sidecar (`crl-refresh`, no homes mount, no
  `DAC_READ_SEARCH`) re-runs `ca-policy-lcg`'s `refresh_crls.sh` every
  `crlRefresh.intervalSeconds` (default 6h) thereafter. CRLs also get a
  fresh pull on every pod restart, via the init container. Set
  `crlRefresh.enabled: false` to skip all of this and use the baked-in CRLs
  as-is for the image's lifetime.

```bash
helm lint charts/voms-token-service
helm template voms-token-service charts/voms-token-service
```

The `Containerfile` builds the runtime image: debian-slim plus the
pixi-built Python environment. `voms-proxy-init`/`-info`/`-destroy` come from
conda-forge's `voms` package (`pixi.toml`'s `service` feature) — unlike
condor-token-service's `condor_token_create` (which needs HTCondor's own apt
repo), the VOMS clients ride in the *same* pixi environment as the Python
service, so the Containerfile needs no extra package-manager step beyond
`ca-certificates` (for verifying the broker's JWKS TLS endpoint). Grid trust
is likewise baked into the same environment: `ca-policy-lcg` (the IGTF CA
bundle, whose conda activation exports `X509_CERT_DIR`), `voms-lsc` (the
`vomsdir` `.lsc` files), and the `vomses` shipped by the `voms` package
itself — no trust-material mounts are needed at deploy time. The bundle is
pinned per image (refresh it by re-releasing); CRLs, which age much faster,
are refreshed at pod start and periodically by the `crlRefresh` init/sidecar
pair (see "CRL freshness" above).

## Local development

Everything runs through [pixi](https://pixi.sh); dependencies live in
`pixi.toml` (this package's `pyproject.toml` intentionally declares no
dependencies).

```bash
pixi run serve        # dev server with reload → http://localhost:8080/docs
pixi run test         # pytest tests/ -v
pixi run lint         # ruff check + format --check
pixi run fmt          # ruff format + autofix
pixi run typecheck    # mypy --strict src
pixi run -e dev lint-all   # everything the CI lint job runs (ruff + mypy + pre-commit)
```

The default test suite never touches the network, a real VOMS server, or a
real filesystem beyond pytest's own `tmp_path`: the JWKS is served by an
in-process stub around a real generated RSA keypair
(`tests/conftest.py::stub_jwks_fetch`), and `voms-proxy-init` is a fake
executable shell script on `PATH` that writes a real, `cryptography`-signed
self-signed certificate as its output (so `minting.py`'s parsing exercises
real ASN.1, not a hand-rolled fake). `tests/test_e2e.py` is skipped unless
`VOMS_E2E=1`, and requires a real deployment, a real broker-minted token, and
a real Globus passphrase for a real AF user — it is never faked:

```bash
VOMS_E2E=1 \
  VOMS_TOKEN_SERVICE_URL=https://voms-token.af.uchicago.edu \
  AF_BROKER_IDENTITY_TOKEN=<freshly-minted broker token> \
  VOMS_E2E_UNIXNAME=<real unixname> \
  VOMS_E2E_UID=<real uid> \
  VOMS_E2E_GID=<real gid> \
  VOMS_E2E_PASSPHRASE=<real Globus key passphrase> \
  pixi run test
```
