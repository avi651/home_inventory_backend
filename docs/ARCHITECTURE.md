# Home Inventory AI — Locked Architecture

Status: **locked v2** (adds mandatory Push Notifications and TLS / certificate pinning,
and the Phase 2 authentication decisions below).

## 0. Locked decisions

| # | Decision | Choice |
|---|---|---|
| D1 | Sign-in method linking | **`user_identities` table** — one user can link email, Google and Apple. Never auto-link by matching email; linking is an explicit action by an already-authenticated user. |
| D2 | Registration enumeration | Generic `409` ("Unable to register with these details") + strict rate limiting. No email verification in Phase 2; when added later, register switches to an always-`202` flow. |
| D3 | Refresh-token reuse | **Strict** — any reuse revokes the entire session. Clients must refresh single-flight. |
| D4 | Register auto-login | Registration returns the access + refresh token pair. |
| D5 | Production API hostname | `api.example.com` — configurable placeholder (`ALLOWED_HOSTS`, docs, mobile build configs). |
| D6 | Push notifications | Architecture approved (sections 1–5); delivery implemented in Phase 5. |
| D7 | TLS / pinning | Architecture approved; HTTPS-only + TrustedHost in Phase 2; pinning implemented in mobile apps. |

**Consequence of D1 for Phase 1:** the provider-specific columns on `users` (`email`,
`password_hash`, `auth_provider`, `provider_subject`) and their CHECK constraints move to
`user_identities`. This is done in Phase 2 with a **new** Alembic migration (the applied Phase 1
migration is not edited), and the Phase 1 User-constraint tests move with the columns.

---

## 1. System architecture

```
 iOS (SwiftUI)                    Android (Flutter)
 URLSession + SPKI pinning        Dart HTTP client + SPKI pinning
 Keychain token storage           flutter_secure_storage
        │  HTTPS only (TLS 1.2+, 1.3 preferred)  │
        └──────────────────┬─────────────────────┘
                           ▼
            Load balancer / reverse proxy
            - terminates TLS (auto-renewed cert, stable key)
            - forwards X-Forwarded-Proto to trusted app only
                           ▼  private network (re-encrypt if untrusted)
 ┌──────────────────────── FastAPI (uvicorn --proxy-headers) ───────────────────────┐
 │ Middleware: SecurityHeaders · HTTPS-only (prod) · TrustedHost (prod) · CORS      │
 │ API (/api/v1)        → thin route handlers, Pydantic schemas, DI only            │
 │ Services             → business rules (Auth, Session, Device, Notification, …)   │
 │ Repositories         → SQLAlchemy, every user-owned query scoped by user_id      │
 │ Core                 → config, database, logging redaction, passwords, tokens,   │
 │                        rate limiting, clock                                       │
 └───────────────┬───────────────────────────────────────────────┬──────────────────┘
                 ▼                                               ▼
        PostgreSQL 17 (app role: DML only;               Notification worker (separate process)
        migrator role: DDL via Alembic)                  reads outbox → PushProviderRegistry
                                                           ├── APNsProvider → api.push.apple.com
                                                           ├── FCMProvider  → fcm.googleapis.com
                                                           └── FakeProvider (tests / local)
```

### Layer rules (unchanged from Phase 1)

- Routes: parse input, call one service, map result. No business logic, no SQL, no provider calls.
- Services: business rules, authorization decisions, transactions.
- Repositories: data access only; methods for user-owned data **require** `user_id`.
- External integrations (APNs, FCM, later Google/Apple identity) sit behind `Protocol`s and are
  injected; the API layer never imports a concrete provider.

### Notification architecture

```
Business event (warranty reminder, …)
  → NotificationService.notify_user(user_id, Notification)       [same DB transaction as event]
      → notifications            (one row per logical notification, UNIQUE dedupe_key)
      → notification_deliveries  (one row per active device, status = pending)   ← transactional outbox
  → NotificationDispatcher (worker, outside request path)
      → PushProviderRegistry[device.provider].send(PushTarget, PushMessage) → DeliveryResult
      → sent | retry (backoff, honour Retry-After, max attempts) | invalid_token → deactivate device
```

- `PushProvider` is a `Protocol`: `provider` name + `async send(target, message) -> DeliveryResult`.
- Providers are constructed from settings at startup and injected. If a provider is not configured,
  it is absent from the registry and deliveries for it are marked `skipped` — the API still starts.
- Warranty reminders (Phase 6) only call `NotificationService.notify_user(...)`; they never touch
  providers, devices, or tokens directly.

---

## 2. Folder structure (target; phase that introduces each item in brackets)

```
app/
├── main.py                               [1]
├── core/
│   ├── config.py                         [1; +ALLOWED_HOSTS 2; +push settings 5]
│   ├── database.py  logging.py           [1]
│   ├── security.py                       [1; +HTTPS-only middleware 2]
│   ├── passwords.py  tokens.py           [2]
│   ├── rate_limit.py  clock.py           [2]
├── models/
│   ├── base.py  user.py                  [1]
│   ├── user_identity.py                  [2]
│   ├── auth_session.py  refresh_token.py [2]
│   ├── home.py  room.py                  [3]
│   ├── item.py  warranty.py  receipt.py  [4]
│   └── device_token.py  notification.py  notification_delivery.py   [5]
├── schemas/            auth.py user.py [2] · home/room [3] · item/warranty/receipt [4] · device.py [5]
├── repositories/       user/session/refresh_token [2] · home/room [3] · item/… [4]
│                       device_token/notification [5]
├── services/
│   ├── health_service.py                 [1]
│   ├── auth_service.py  session_service.py  identity_providers.py   [2]
│   ├── home/room/item/warranty/receipt services                    [3–4]
│   ├── device_service.py  notification_service.py                  [5]
│   └── reminder_service.py                                         [6]
├── notifications/                        [5]
│   ├── providers/
│   │   ├── base.py        # PushProvider Protocol, PushTarget, PushMessage, DeliveryResult
│   │   ├── apns.py        # HTTP/2, token-based auth (.p8 / ES256), sandbox vs production
│   │   ├── fcm.py         # HTTP v1 API, service account / workload identity
│   │   └── fake.py        # tests + local console delivery
│   ├── registry.py        # provider name → provider, built from settings
│   └── dispatcher.py      # outbox processing, retries, invalid-token handling
├── workers/
│   ├── notification_worker.py            [5]
│   └── reminder_scheduler.py             [6]
├── api/
│   ├── dependencies.py                   [1; +CurrentUser, rate limits 2]
│   └── routes/
│       ├── health.py                     [1]
│       ├── auth.py  users.py  sessions.py [2]
│       ├── homes.py rooms.py             [3]
│       ├── items.py warranties.py receipts.py search.py [4]
│       └── devices.py                    [5]
└── exceptions/  handlers.py [1] · errors.py [2]
docs/
├── ARCHITECTURE.md                       (this file)
├── mobile-token-storage.md               [2]
├── tls-and-certificate-pinning.md        [2]
└── push-notifications.md                 [5, operational runbook]
```

---

## 3. Database tables

| Table | Phase | Purpose |
|---|---|---|
| `users` | 1 ✅ → reshaped in 2 | the person/account; credentials move to `user_identities` (D1) |
| `user_identities` | 2 | how a user signs in: email/password, Google, Apple (many per user) |
| `auth_sessions` | 2 | one login/device session; revocation is immediate (checked per request) |
| `refresh_tokens` | 2 | SHA-256 hash only; rotation chain per session; reuse detection |
| `homes`, `rooms` | 3 | user-owned hierarchy |
| `items`, `warranties`, `receipts` | 4 | inventory, warranty dates, uploaded documents |
| `device_tokens` | 5 | push targets per user/device |
| `notifications` | 5 | logical notification, dedupe |
| `notification_deliveries` | 5 | per-device delivery status / audit (outbox) |
| `notification_preferences` | 6 | per-user opt-in per notification type |
| `documents`, `embeddings`, `conversations`, `messages`, `ai_tool_calls` | 7+ | AI / RAG |

### `users` (after Phase 2 migration)

| Column | Type / rule |
|---|---|
| `id` | UUIDv7 PK |
| `is_guest` | bool; true ⇔ created via guest sign-in and no identity linked yet |
| `is_active` | bool, default true |
| `created_at`, `updated_at` | |

A guest is a user with `is_guest = true` and zero identities. Upgrading a guest = linking an
email (or Google/Apple) identity and clearing `is_guest`, keeping the same `user_id` and data.

### `user_identities` (Phase 2)

| Column | Type / rule |
|---|---|
| `id` | UUIDv7 PK |
| `user_id` | FK users ON DELETE CASCADE, indexed |
| `provider` | enum `email` / `google` / `apple` |
| `subject` | email provider: the normalized (lowercase) email; Google/Apple: the ID token `sub` |
| `email` | lowercase; required for `email`, optional (informational) for Google/Apple |
| `email_verified` | bool; from the provider for Google/Apple; false for email until verification exists |
| `password_hash` | Argon2id; required for `email`, must be NULL otherwise |
| `last_used_at`, `created_at`, `updated_at` | |

Constraints: `UNIQUE(provider, subject)` (one account per email login / per Google or Apple
subject); `UNIQUE(user_id, provider)` (one identity of each kind per user); CHECK per provider
(email ⇒ `subject = email`, hash NOT NULL; google/apple ⇒ subject non-empty, hash NULL);
CHECK lowercase email/format. Unlinking the last identity of a non-guest user is refused.

Sign-in with Google/Apple whose email matches another account's email identity does **not**
link automatically; it returns a conflict asking the user to sign in and link explicitly.

### `auth_sessions` (Phase 2)

| Column | Type / rule |
|---|---|
| `id` | UUIDv7 PK — carried as `sid` in access tokens |
| `user_id` | FK users ON DELETE CASCADE, indexed |
| `expires_at` | absolute session cap (90 days) |
| `revoked_at`, `revoked_reason` | both NULL or both set; reason ∈ `logout`, `logout_all`, `reuse_detected`, `user_revoked` |
| `created_at`, `updated_at` | |

### `refresh_tokens` (Phase 2)

| Column | Type / rule |
|---|---|
| `id` | UUIDv7 PK |
| `session_id` | FK auth_sessions ON DELETE CASCADE, indexed |
| `token_hash` | CHAR(64) hex SHA-256, UNIQUE, CHECK length = 64 |
| `expires_at` | idle expiry (REFRESH_TOKEN_EXPIRE_DAYS) |
| `used_at` | set on rotation; presenting a used token = reuse |
| `created_at`, `updated_at` | |

### `device_tokens` (Phase 5)

| Column | Type / rule |
|---|---|
| `id` | UUIDv7 PK (the `{device_id}` in the API path) |
| `user_id` | FK users ON DELETE CASCADE |
| `session_id` | FK auth_sessions ON DELETE SET NULL — logout deactivates this device's token |
| `device_id` | app-generated installation UUID kept in Keychain/Keystore; **never** IMEI / ANDROID_ID / hardware IDs |
| `platform` | enum `ios` / `android` (operating system) |
| `provider` | enum `apns` / `fcm` (delivery channel; separate because Flutter-on-iOS uses FCM) |
| `apns_environment` | `sandbox` / `production`; required when provider = apns, NULL otherwise (CHECK) |
| `token` | TEXT, length 1–4096; never logged, never returned |
| `token_fingerprint` | first 12 hex of SHA-256(token); the only token form in logs/responses |
| `app_version`, `locale` | optional, bounded length |
| `is_active` | default true |
| `deactivated_at`, `deactivation_reason` | both NULL or both set; reason ∈ `user_removed`, `logout`, `invalid_token`, `reassigned` |
| `last_registered_at`, `created_at`, `updated_at` | |

Constraints: `UNIQUE(provider, token)`; `UNIQUE(user_id, device_id)`; partial index on
`(user_id) WHERE is_active`.

### `notifications` (Phase 5)

`id`, `user_id` (FK CASCADE), `type` (enum, e.g. `warranty_expiring`), `template_key`,
`data` (JSONB — IDs only, no PII), `dedupe_key` (UNIQUE, e.g. `warranty:{id}:30d`), timestamps.

### `notification_deliveries` (Phase 5)

`id`, `notification_id` (FK CASCADE), `device_token_id` (FK CASCADE),
`status` ∈ `pending`, `sent`, `retrying`, `failed`, `invalid_token`, `skipped`,
`attempts`, `next_attempt_at`, `provider_message_id`, `last_error_code` (provider code only),
`sent_at`, timestamps. Index on `(status, next_attempt_at)` for the dispatcher.
No token and no message body are stored here.

---

## 4. APIs

All under `/api/v1` except health. "Bearer" = valid access token for an active session.

| Method & path | Auth | Phase | Result |
|---|---|---|---|
| `GET /health`, `GET /health/ready` | none | 1 ✅ | liveness / readiness |
| `POST /auth/register` | none | 2 | 201 user + token pair |
| `POST /auth/login` | none | 2 | 200 token pair |
| `POST /auth/refresh` | refresh token (body) | 2 | 200 rotated pair |
| `POST /auth/logout` | refresh token (body) | 2 | 204 (idempotent) |
| `POST /auth/logout-all` | Bearer | 2 | 204 |
| `POST /auth/guest` | none | 2 | 201 guest + token pair |
| `GET /users/me` | Bearer | 2 | own profile, no hash |
| `GET /auth/sessions` | Bearer | 2 | own sessions |
| `DELETE /auth/sessions/{session_id}` | Bearer | 2 | 204 own / 404 otherwise |
| `GET/POST /homes`, `GET/POST /rooms` | Bearer | 3 | owner-scoped |
| `/items…`, `/warranties…`, `/receipts…`, `GET /search` | Bearer | 4 | owner-scoped |
| `POST /devices` | Bearer | 5 | 201 new / 200 updated (upsert by own `device_id`) |
| `PATCH /devices/{device_id}` | Bearer | 5 | 200 — token refresh, locale, app_version |
| `DELETE /devices/{device_id}` | Bearer | 5 | 204 own (soft deactivate) / 404 otherwise |

Device responses: `{id, device_id, platform, provider, token_fingerprint, is_active, created_at,
updated_at}` — never `token`, never `user_id` of anyone else.

---

## 5. Security considerations

### Authentication & sessions (Phase 2)
Credentials live on `user_identities`, never on `users`; Argon2id; NIST-style password policy with length cap before hashing; JWT access tokens
(HS256 only, `iss`/`aud`/`exp`/`nbf`/`iat`/`typ`/`sid`/`jti` required); opaque refresh tokens hashed
at rest, rotated, reuse ⇒ session revoked; session checked on every request so logout is immediate;
uniform 401s; login enumeration protection with dummy hash; per-IP + per-account rate limits.

### Authorization / IDOR-BOLA (all phases)
Owner-scoped repository queries (`WHERE id = :id AND user_id = :me`); 404 (not 403) for others'
resources; request schemas `extra="forbid"` so client-supplied `user_id` is rejected; every
user-owned endpoint gets an explicit cross-user test.

### Push notifications (Phase 5)
- Device API requires Bearer auth; owner-scoped; rate limited per user.
- Full tokens never logged (fingerprint only), never returned, never in errors; the existing log
  redaction already masks `*token=` / `"*token":` patterns as a backstop.
- Token registered by another user (shared/resold phone) → old row deactivated as `reassigned`;
  response is identical so ownership of a token cannot be probed.
- Logout / session revocation deactivates that session's device tokens (single revocation path in
  `SessionService`, built in Phase 2) so a logged-out phone stops receiving the user's alerts.
- Invalid/expired tokens (APNs `410 Unregistered`, `400 BadDeviceToken`; FCM `UNREGISTERED`,
  `NOT_FOUND`, token `INVALID_ARGUMENT`) deactivate the device; 429/5xx retried with backoff.
- Lock-screen payloads are generic; payload data contains IDs only; app fetches details after auth.
- Credentials only from env / secret manager as `SecretStr`: `APNS_TEAM_ID`, `APNS_KEY_ID`,
  `APNS_PRIVATE_KEY`, `APNS_BUNDLE_ID`, `FCM_PROJECT_ID`, `FCM_CREDENTIALS_JSON` (or workload
  identity). Production validation: an enabled provider must be fully configured.
  `.gitignore` blocks `*.p8`, `*.pem`, `*.key`, `*service-account*.json`.
- Backend → APNs/FCM uses standard TLS validation; never pin Apple/Google endpoints.

### Transport (Phase 2)
- Production: plain-HTTP requests rejected (400 `https_required`), not redirected — a redirect
  happens after the token was already sent in cleartext. Health endpoints exempt for internal probes.
- `TrustedHostMiddleware` with `ALLOWED_HOSTS` (required, no `*`, in production).
- HSTS in production (Phase 1 ✅).
- uvicorn `--proxy-headers --forwarded-allow-ips=<LB range>` only; never trust `X-Forwarded-*`
  from arbitrary clients.
- Clients: iOS ATS on; Android `cleartextTrafficPermitted="false"`.

### Mobile certificate pinning (documented Phase 2, implemented in the mobile apps)
- **No backend pinning endpoint.** Pinning is client-side configuration.
- Production hostname: **`api.example.com` (placeholder until confirmed)** — one value shared by
  `ALLOWED_HOSTS`, docs and mobile build configs.
- Pin **SPKI SHA-256 (public key)**, never the certificate. Renew certificates with the same key
  (e.g. ACME `--reuse-key`) so renewals do not change the pin.
- Ship **≥ 2 pins**: current key + offline pre-generated **backup key**; optionally the issuing CA
  intermediate as an additional pin.
- Pins carry an **expiry**; after it, clients fall back to normal system trust so an old,
  never-updated install degrades safely instead of bricking.
- Pinning is **in addition to** normal chain + hostname validation.
- Rotation runbook: ship backup pin in an app release → wait for adoption → switch server key →
  generate next backup → ship. Emergency key compromise: switch to backup key immediately.
- iOS: `NSPinnedDomains` (ATS) or `URLSessionDelegate` SPKI check after default trust evaluation.
- Flutter/Android: pin in the Dart HTTP layer (Dart's `HttpClient` ignores Android
  `network_security_config` pin-sets); SPKI hashes, multiple pins, expiry.
- Dev/staging: separate hostnames; no pins or staging-only pins selected by build flavor;
  production pins never compiled into debug builds.

---

## 6. Roadmap

| Phase | Scope | Push / TLS items in this phase |
|---|---|---|
| 1 ✅ | Foundation: config, DB, Alembic, users, health, headers, redaction | HSTS (prod) |
| 2 | Auth & authorization (`user_identities` reshaping, sessions, tokens, rate limiting, guest, provider-sign-in protocol) | single session-revocation path; HTTPS-only + TrustedHost middleware; `.gitignore` credential patterns; docs: mobile token storage, TLS & pinning, this architecture |
| 3 | Homes & rooms | — |
| 4 | Items, warranties, receipts (secure uploads), search | — |
| 5 | **Push notifications**: `device_tokens`, device API, NotificationService, provider Protocol, APNs + FCM providers, outbox, dispatcher worker, delivery audit, invalid-token handling | push settings + validation; push runbook |
| 6 | Warranty reminder scheduler + notification preferences → `NotificationService` | — |
| 7+ | Google/Apple sign-in verification (JWKS), AI recognition, embeddings/pgvector/RAG, agents, MCP | — |
