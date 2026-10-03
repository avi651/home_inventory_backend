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
  secrets, unsafe algorithms, non-PostgreSQL URLs, and — in production — debug or non-https CORS.
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
