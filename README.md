# Home Inventory AI — Backend

FastAPI + SQLAlchemy 2 (async, psycopg 3) + PostgreSQL 17 + Alembic. Python 3.14.

## Setup

```bash
python3.14 -m venv venv
./venv/bin/pip install -r requirements-dev.txt
cp .env.example .env          # fill in real values; also create .env.test for the test DB
```

Databases: `home_inventory` (dev) and `home_inventory_test` (tests). Two roles:

| Role | Used by | Privileges |
|---|---|---|
| `home_inventory_migrator` | Alembic (`MIGRATION_DATABASE_URL`) | owns schema objects |
| `home_inventory_app` | the API (`DATABASE_URL`) | SELECT/INSERT/UPDATE/DELETE only |

## Commands

```bash
./venv/bin/alembic upgrade head                                   # migrate dev DB
./venv/bin/alembic revision --autogenerate -m "describe change"   # then REVIEW the file
./venv/bin/uvicorn app.main:create_app --factory --reload --no-server-header

./venv/bin/pytest                    # full suite (uses .env.test; refuses non-*_test DBs)
./venv/bin/pytest --cov              # with coverage
./venv/bin/ruff check app tests alembic && ./venv/bin/ruff format --check app tests alembic
./venv/bin/mypy
```

Endpoints so far: `GET /health` (liveness, no DB), `GET /health/ready` (DB check, 503 when down).

## Security notes

- **Secrets** come only from the environment (`.env` locally, a secret manager in production).
  `.env*` files are git-ignored and `chmod 600`. Settings fail fast on weak/placeholder JWT
  secrets, unsafe algorithms, non-PostgreSQL URLs, and — in production — debug, non-https CORS,
  or missing/wildcard `ALLOWED_HOSTS`.
- **Errors** use one envelope `{"error": {"code", "message"}}`; no stack traces, exception text or
  echoed input reach clients. Validation errors list field locations only.
- **Logs** pass through a redaction filter (passwords, tokens, JWTs, `Authorization`, cookies,
  DB credentials) — including uvicorn access logs and tracebacks.
- **Local PostgreSQL** (Homebrew) uses `trust` authentication in `pg_hba.conf`, so role passwords
  are not enforced locally. Production must use `scram-sha-256`.

### Production expectations

- TLS everywhere: HTTPS at the edge (HSTS is sent in production) and `sslmode=verify-full` to the DB.
- Encryption at rest for the database volume and backups (managed-provider default or LUKS/KMS).
- `ENVIRONMENT=production` disables `/docs`, `/redoc`, `/openapi.json`.
- Run migrations with the migrator role in the deploy pipeline; the API only gets the app role.

## Sign in with Google

> Placeholders only: no real Google Cloud project, client or domain exists yet.

Authorization Code flow with the code exchanged **server-side**, plus PKCE and a nonce:

```
Client                         API                                   Google
  │ POST /api/v1/auth/google/start ─▶│ store attempt (hashes of state,
  │                                   │ attempt_token, nonce; PKCE verifier;
  │ ◀── {authorization_url,           │ expires in 10 min)
  │      attempt_token, expires_in}   │
  │ open authorization_url ───────────────────────────────────────────▶│ user consents
  │ ◀──────────────── redirect to GOOGLE_REDIRECT_URI?code=…&state=… ───│
  │ POST /api/v1/auth/google/callback │
  │   {code, state, attempt_token} ──▶│ consume attempt (single use) ─────▶│ POST /token
  │                                   │   code + PKCE verifier + secret    │ (server-side)
  │                                   │ ◀──────────────────────── id_token │
  │                                   │ verify id_token (JWKS), resolve
  │ ◀── standard AuthResponse ────────│ (google, sub) → user, start session
```

- **Why POST for both endpoints.** `start` creates server state and returns a secret, so it must
  not be cacheable, prefetchable or triggerable by a cross-site link. `callback` takes the code in
  a JSON body so it never appears in URLs or access logs.
- **State.** 256-bit random, stored only as a SHA-256 digest, valid 10 minutes, deleted when first
  presented (even if the sign-in then fails), so replays always fail. Attempts live in PostgreSQL,
  so single use holds across workers.
- **Binding.** `attempt_token` stays inside the client that called `start` and never passes
  through the browser redirect. A stolen `code` + `state` (for example from an intercepted
  redirect) cannot complete the sign-in without it. Comparison is constant-time.
- **PKCE and nonce.** The server keeps the PKCE verifier and sends it with the code, so a code
  only works for the attempt it was issued to. The nonce is bound to the ID token.
- **ID token checks.** RS256 only, with Google's key selected by `kid` from the JWKS endpoint
  (cached 1 hour; an unknown `kid` refetches at most once a minute). Also checked: `iss`
  (`https://accounts.google.com` or `accounts.google.com`), `aud` equal to the client ID, `azp`
  (if present), `exp`/`iat` with 60 seconds of tolerance, `nonce`, and a well-formed `sub`.
- **Identity key.** `user_identities(provider="google", subject=<sub>)`. Google's `sub` never
  changes; email addresses can. No password hash is ever stored on a Google identity.
- **Email.** Stored on the identity (normalized) only if Google marks it verified
  (`email_verified: true`); otherwise it is dropped and the sign-in still works on `sub`.
- **No implicit linking.** A new Google account whose verified email already belongs to any
  account gets `409 account_link_required` (sign in with that account and link explicitly — a
  future step). Accounts are never merged by email, and a password account is never signed in
  through Google. An existing `(google, sub)` always signs in its own user.
- **Errors.** Bad, expired or replayed state, a rejected code or ID token, or an inactive account
  → `401 oauth_failed`. Timeouts, Google 5xx/429 or malformed responses →
  `503 provider_unavailable`. Not configured → `404`. Codes, tokens, state, the client secret and
  provider response bodies are never returned or logged.
- **Rate limits.** `oauth_start_per_ip` and `oauth_callback_per_ip`, 10/minute each. The limiter
  is in-memory per process, like the other auth limits, so production needs the shared (Redis)
  backend behind the same `RateLimiter` protocol.

**Google configuration (placeholders):** create an OAuth client of type *Web application*,
register the exact redirect URI, and request scopes `openid email`.

```bash
GOOGLE_CLIENT_ID=<client-id>.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=<from the secret manager>      # SecretStr; never logged or committed
GOOGLE_REDIRECT_URI=https://app.example.com/oauth/google/callback
```

All three variables are required together. The redirect URI must be an absolute `https` URL
(`http://localhost` is allowed outside production). The redirect target is a page or a universal
link / App Link that passes `code` and `state` to the app, which then calls `/callback`. In
production the API itself is HTTPS-only (see below).

## Production deployment

> Target model only: no production domain, certificate or cloud infrastructure exists yet.
> `api.example.com` is a placeholder (ARCHITECTURE.md D5).

```
Client (iOS / Android / browser)
  │  HTTPS (TLS 1.2+, 1.3 preferred)
  ▼
Reverse proxy / load balancer      ← terminates TLS; owns the certificate and its renewal
  │  plain HTTP on a private network (re-encrypt if that network is untrusted)
  │  sets X-Forwarded-Proto / X-Forwarded-For (overwriting any client-sent values)
  ▼
uvicorn --proxy-headers --forwarded-allow-ips=<LB address/range>
  ▼
FastAPI (TrustedHost → HTTPS-only → CORS → routes)
  ▼
PostgreSQL (sslmode=verify-full, app role only)
```

**HTTPS termination and certificates.** TLS ends at the load balancer, which holds the
certificate (renewed with the same key so mobile SPKI pins stay valid — see ARCHITECTURE.md §5).
The app never handles certificates.

**How the app decides a request is HTTPS.** Only from the ASGI scheme. uvicorn rewrites that
scheme from `X-Forwarded-Proto` (and the client IP from `X-Forwarded-For`) **only when the TCP
peer is listed in `--forwarded-allow-ips`**. The app itself never reads `X-Forwarded-*` or
`Forwarded`. Anyone can send those headers, so trusting them from arbitrary peers would let a
client claim HTTPS over plain HTTP, or fake its IP to dodge per-IP rate limits. Rules:

- set `--forwarded-allow-ips` to the load balancer's address/range, never `*`;
- the load balancer must overwrite (not append to) client-supplied `X-Forwarded-*` headers;
- the app port must be reachable only from the load balancer.

In production, plain-HTTP requests get `400 {"error": {"code": "https_required", ...}}` and are
**not redirected**, so there are no redirect loops. If every request returns `https_required`,
the proxy is not trusted (check `--forwarded-allow-ips`) or is not sending `X-Forwarded-Proto: https`.
HTTP→HTTPS redirects for browsers, if wanted, belong at the load balancer.

**ALLOWED_HOSTS.** JSON list of host names the API answers to. In production it is required,
must not contain `*` or `*.domain` patterns, and entries must be bare lowercase hostnames
(no scheme, port or path); invalid values stop the app at startup. Other hosts get
`400 invalid_host`. Only the `Host` header is checked (ports ignored; `X-Forwarded-Host` ignored).

**Health/readiness exceptions.** Exactly `/health` and `/health/ready` are exempt from both the
HTTPS and Host checks so load-balancer/orchestrator probes can call an instance directly
(`http://10.0.0.5:8000/health`). They return only `ok`/`unavailable`, never configuration.
Keep them off the public listener if possible.

**CORS.** Native mobile apps need none. Browser origins go in `CORS_ORIGINS`; production
requires `https://` origins and rejects `*`; credentials are never allowed.

**Production environment requirements:** `ENVIRONMENT=production`, `DEBUG` off, strong
`JWT_SECRET`, `ALLOWED_HOSTS`, HTTPS-only `CORS_ORIGINS`, secrets from a secret manager. Docs
(`/docs`, `/redoc`, `/openapi.json`) are disabled and HSTS is sent.

Example (placeholders only):

```bash
ENVIRONMENT=production
ALLOWED_HOSTS=["api.example.com"]
CORS_ORIGINS=[]
# DATABASE_URL / JWT_SECRET etc. injected from the secret manager

uvicorn app.main:create_app --factory --host 0.0.0.0 --port 8000 \
  --proxy-headers --forwarded-allow-ips=10.0.0.0/24 --no-server-header
```

**Local development.** `ENVIRONMENT=local` (or `test`) serves plain HTTP; HTTPS is not enforced
and the Host header is only checked if `ALLOWED_HOSTS` is set (e.g. `["localhost","127.0.0.1"]`).
Leave it empty to reach the dev server from a phone by LAN IP.
