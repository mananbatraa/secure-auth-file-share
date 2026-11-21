# Secure Auth & File Share

[![CI](https://github.com/mananbatraa/secure-auth-file-share/actions/workflows/ci.yml/badge.svg)](https://github.com/mananbatraa/secure-auth-file-share/actions/workflows/ci.yml)

A FastAPI backend with production-style authentication and file sharing:

- **JWT access tokens** (short-lived) plus **opaque refresh tokens with rotation and reuse detection**. Replaying a rotated refresh token revokes the whole session family.
- **Instant revocation**: "log out everywhere", password changes, role changes and deactivation invalidate outstanding access tokens immediately, without a token blocklist.
- **OAuth login** with GitHub and Google (authorization code + `state` + PKCE), linking accounts by *verified* email only.
- **RBAC** (`admin`, `member`, `guest`) mapped to explicit permissions.
- **Rate-limited login**: Redis sliding-window limits per account and per IP, run atomically in one Lua script.
- **File sharing on S3/MinIO**: uploads are hashed and size-capped, downloads go through **short-lived presigned URLs**, per-file **viewer/editor grants** (optionally expiring), and anonymous **share links** with an expiry and an optional download cap that holds under concurrency.
- **Direct-to-S3 uploads** for large files: a presigned POST pinned to the key, exact size, content type and SHA-256, followed by a confirm step that re-verifies the stored object and deletes anything that doesn't match.
- **Append-only audit log** of every security-relevant event (logins with failure reason, throttling, token reuse, admin changes, grants, share-link use), enforced by a Postgres trigger and queryable by admins.
- **Background cleanup worker** that removes expired upload intents (and the objects they left in S3), expired refresh tokens, grants and dead share links in small `SKIP LOCKED` batches.
- Postgres via async SQLAlchemy 2, **Alembic** migrations, Docker Compose stack, CI on GitHub Actions, **198 tests at 98% coverage**, `ruff` + strict `mypy`.

## Architecture

```mermaid
flowchart LR
    C[Client / SPA] -->|Bearer JWT| API[FastAPI app]
    C -->|presigned GET / POST| S3[(S3 / MinIO)]
    B[Anyone with a link] -->|GET /s/token| API
    API -->|307 to presigned URL| B
    API --> PG[(Postgres<br/>users, refresh_tokens, files,<br/>grants, links, upload_intents,<br/>audit_events)]
    API --> R[(Redis<br/>rate limits, OAuth state)]
    API -->|upload / delete| S3
    API -->|code exchange| OP[GitHub / Google OAuth]
    W[cleanup worker] -->|batched deletes| PG
    W -->|orphaned objects| S3
```

File bytes never stream back through the API. The API authorizes the request, then hands the client a presigned URL that is valid for seconds or minutes. Large uploads can skip the API too (see below).

```
app/
  core/       config (env vars), security (Argon2id, JWT), RBAC, domain errors
  models/     SQLAlchemy models: User, OAuthAccount, RefreshToken, StoredFile, FilePermission,
              ShareLink, UploadIntent, AuditEvent
  services/   auth (rotation), oauth, files (permissions, links, direct uploads), storage (S3),
              rate_limit (Lua), audit, cleanup (expiry sweeps)
  api/        routes + dependencies (current user, permission checks)
  resources.py  process-wide pools/clients, built in the app lifespan
  cleanup.py    `python -m app.cleanup` worker entry point
alembic/      migrations
tests/        unit + API tests (real Postgres, fakeredis/real Redis, moto S3 server)
```

### Refresh-token rotation and reuse detection

```mermaid
sequenceDiagram
    participant U as Legit client
    participant A as Attacker
    participant S as API
    U->>S: POST /auth/refresh (RT1)
    S-->>U: AT2 + RT2  (RT1 marked used, same family)
    A->>S: POST /auth/refresh (stolen RT1)
    S->>S: RT1 already used, so revoke the whole family
    S-->>A: 401 refresh_token_reused
    U->>S: POST /auth/refresh (RT2)
    S-->>U: 401 (family revoked, user must log in again)
```

The token row is read with `SELECT … FOR UPDATE`, so two simultaneous refreshes with the same token serialize: exactly one wins, and the other is treated as a replay.

### Direct-to-S3 uploads

```mermaid
sequenceDiagram
    participant C as Client
    participant S as API
    participant O as S3 / MinIO
    C->>S: POST /files/uploads {filename, content_type, size_bytes, sha256?}
    S->>S: insert upload_intent (owner, key, declared size/type/hash, expiry)
    S-->>C: presigned POST (policy: this key, exact size, this type, checksum)
    C->>O: POST file bytes (never touch the API)
    C->>S: POST /files/uploads/{id}/complete
    S->>O: HEAD object (size, type, stored SHA-256)
    alt everything matches
        S->>S: intent becomes a file row (same id), audit file.uploaded
        S-->>C: 201 file
    else mismatch / expired
        S->>O: DELETE object
        S-->>C: 422 / 410, audit file.upload_rejected
    end
```

S3 enforces the POST policy, but the confirm step does not rely on it: it compares the stored object with what was declared, using S3's stored full-object SHA-256 when there is one and otherwise streaming the object to hash it. Intents are single-use, owner-scoped (another user gets `404`) and expire with the policy.

### Audit log

Every security-relevant action writes an `audit_events` row with the actor, target, outcome, client IP, user agent and request ID. Success events are staged in the same transaction as the action, so an action and its audit row commit or roll back together; failures (bad password, throttled login, rejected share link) are written on their own because the action itself never commits. A trigger rejects `UPDATE` and `DELETE` on the table, and `actor_id` has no foreign key, so the trail survives user deletion.

```bash
# Failed logins in the last hour, newest first; follow next_before_id to page
curl -s "$API/admin/audit?action=auth.login&outcome=failure&since=2026-11-20T10:00:00Z" \
  -H "authorization: Bearer $ADMIN_AT"
```

### Background cleanup

`python -m app.cleanup` sweeps expired data; Compose runs it as the `cleanup` service (every `CLEANUP_INTERVAL_SECONDS`, default one hour). Use `--once` for cron or a Kubernetes CronJob (it exits non-zero if the sweep fails) and `--dry-run` to only count.

| What | Removed when |
|------|--------------|
| Upload intents + their S3 object | expired more than `CLEANUP_UPLOAD_GRACE_SECONDS` ago (default 1 h, always longer than the 5-minute completion grace) |
| Refresh tokens | expired more than `CLEANUP_RETENTION_SECONDS` ago (default 7 days) |
| File grants | past `expires_at` (they already grant nothing) |
| Share links | expired or revoked more than `CLEANUP_RETENTION_SECONDS` ago |

Each sweep deletes in batches of `CLEANUP_BATCH_SIZE`, one short transaction per batch, selecting rows with `FOR UPDATE SKIP LOCKED`. Several workers can run at once, and a row that a request holds (an upload being confirmed right now) is skipped and picked up next time instead of blocking either side. Intent rows are deleted before their objects: once the row is gone nothing can complete the upload, so the object delete can't race a completion, and a failed object delete only leaves an unreferenced object. A sweep that removed anything writes one `maintenance.cleanup` audit event with the counts.

## Running it

### Docker Compose (everything)

```bash
docker compose up --build
# API + Swagger UI: http://localhost:8000/docs
# MinIO console:    http://localhost:9001  (minioadmin / minioadmin)
```

The `migrate` service runs `alembic upgrade head` before the API starts. To enable OAuth, export `GITHUB_CLIENT_ID`/`GITHUB_CLIENT_SECRET` (callback `http://localhost:8000/auth/oauth/github/callback`) and/or the Google equivalents before `up`.

### Quick tour with curl

```bash
API=http://localhost:8000
curl -s -XPOST $API/auth/register -H 'content-type: application/json' \
  -d '{"email":"alice@example.com","password":"correct-horse-battery-staple"}'
TOKENS=$(curl -s -XPOST $API/auth/login -H 'content-type: application/json' \
  -d '{"email":"alice@example.com","password":"correct-horse-battery-staple"}')
AT=$(echo $TOKENS | jq -r .access_token)

FILE=$(curl -s -XPOST $API/files -H "authorization: Bearer $AT" -F upload=@README.md)
ID=$(echo $FILE | jq -r .id)

curl -s "$API/files/$ID/download?ttl=120" -H "authorization: Bearer $AT"     # presigned URL
curl -s -XPOST $API/files/$ID/links -H "authorization: Bearer $AT" \
  -H 'content-type: application/json' -d '{"expires_in_seconds":3600,"max_downloads":3}'
```

### Local development

```bash
uv sync
docker compose up -d postgres redis minio
cp .env.example .env            # set JWT_SECRET
uv run alembic upgrade head
uv run uvicorn app.main:app_factory --factory --reload
```

### Tests and checks

```bash
docker compose up -d postgres redis
createdb -h localhost -U postgres fileshare_test   # once
uv run pytest --cov=app        # 180 tests
uv run ruff check . && uv run ruff format --check . && uv run mypy
```

The test suite runs migrations from scratch, then exercises the API against real Postgres, a moto S3 server on a local port (so presigned URLs are really fetched over HTTP), and fakeredis. A real Redis is used too when `TEST_REDIS_URL` is reachable. Override `TEST_DATABASE_URL` if your Postgres differs.

## API

| Method | Path | Who | Notes |
|---|---|---|---|
| POST | `/auth/register` | anyone | password ≥ 12 chars, not containing the email name |
| POST | `/auth/login` | anyone | rate limited per account and per IP; `429` + `Retry-After` |
| POST | `/auth/refresh` | refresh token | rotates; replay → `401 refresh_token_reused` |
| POST | `/auth/logout` | refresh token | revokes that session (token family) |
| POST | `/auth/logout-all` | user | revokes all sessions and live access tokens |
| POST | `/auth/change-password` | user | also logs out everywhere |
| GET | `/auth/oauth/{github,google}/authorize` | anyone | 302 to provider |
| GET | `/auth/oauth/{provider}/callback` | provider | returns a token pair |
| GET | `/users/me` | user | |
| GET/PATCH | `/admin/users[/{id}]` | admin | change role / deactivate (takes effect immediately) |
| POST/GET | `/files` | member+ / user | multipart upload (`upload` field); list `?scope=owned\|shared\|all` |
| POST | `/files/uploads` | member+ | start a direct-to-S3 upload; returns presigned POST `url` + `fields` |
| POST | `/files/uploads/{id}/complete` | uploader | verify the object and create the file |
| GET/PATCH/DELETE | `/files/{id}` | viewer / editor / owner | |
| GET | `/files/{id}/download?ttl=` | viewer | presigned URL, TTL clamped to server max |
| POST/GET/DELETE | `/files/{id}/permissions[/{user_id}]` | owner | grant `viewer`/`editor`, optional expiry |
| POST/GET/DELETE | `/files/{id}/links[/{link_id}]` | owner | anonymous links, expiry + download cap |
| GET | `/s/{token}` | anyone | `307` to a 60 s presigned URL; `410` if expired, revoked or used up |
| GET | `/admin/audit` | admin | filter by `action` (exact or `prefix.`), `outcome`, `actor_id`, `target_type`/`target_id`, `since`/`until`; keyset paging via `before_id` |
| GET | `/healthz`, `/readyz` | anyone | readiness checks Postgres, Redis and S3 |

Errors share one shape: `{"error": {"code": "permission_denied", "message": "..."}}`.

## Design decisions

- **Opaque refresh tokens, stored hashed.** Refresh tokens are 256-bit random strings. Only their SHA-256 is stored, so a database leak doesn't hand out sessions. They are opaque rather than JWTs because they must be revocable and single-use anyway, which needs a database row.
- **`token_version` instead of an access-token blocklist.** Each user row carries a counter that is embedded in every access token. The API already loads the user on each request, so comparing the counter costs nothing extra, and bumping it kills every outstanding access token at once.
- **Concurrent refresh counts as reuse.** Two refreshes with the same token are indistinguishable from a replay, so the family is revoked. Real clients should serialize refreshes. A short grace window would be friendlier but weakens theft detection; this project chooses strictness.
- **Login throttling fails closed.** If Redis is down, logins return `503` rather than allowing unlimited guessing (`RATE_LIMIT_FAIL_OPEN=true` flips this). Every attempt counts against the account bucket, and a successful login clears it.
- **`X-Forwarded-For` is ignored by default.** Otherwise an attacker could rotate a spoofed header to get a fresh IP bucket on each try. Set `TRUST_PROXY_HEADERS=true` only behind a proxy you control.
- **404, not 403, for files you can't see.** This doesn't confirm that a file ID exists. Users who can see a file but lack the level for an action get `403`.
- **Downloads are always `Content-Disposition: attachment`.** An uploaded HTML or SVG file can't render as a page, so it can't run script. Storage keys are server-generated (`files/{owner}/{uuid}`), and user filenames are only display metadata.
- **Atomic download caps.** Redeeming a share link is a single conditional `UPDATE … WHERE download_count < max_downloads RETURNING`. Twelve concurrent hits on a 3-download link give exactly three redirects (there is a test for this).
- **Argon2id** password hashing. Unknown emails still run a dummy verification, so response time doesn't reveal which accounts exist.
- **PKCE on OAuth** even for confidential clients, plus single-use `state` stored in Redis (`GETDEL`) and bound to the provider. Accounts are linked by email only when the provider says that email is verified; otherwise an attacker could take over an existing account.
- **Verify uploads after the fact.** A presigned POST policy is only as good as the storage backend that enforces it (moto, for one, ignores it). The confirm step checks size, content type and checksum against the stored object, so a client can't swap in different bytes, even against a lax backend.
- **Audit ids are a Postgres identity, not UUIDs.** `created_at` is the transaction start time, so events inside one transaction tie; a monotonically increasing id gives a total order and a cheap keyset cursor. Retention would be done by a privileged role (or by partitioning by month and dropping old partitions), never by the app's own credentials.
- **Cleanup keeps dead rows for a while.** Expired refresh tokens stay for the retention period, so for a week a replayed old token is still reported as reuse in the audit log instead of looking like garbage, and owners still see recently expired links. Deleting a rotated token never breaks its successor (`replaced_by_id` is `ON DELETE SET NULL`).
- **Pinned JWT algorithm and audience/issuer checks.** `alg=none` and algorithm substitution are rejected (there are tests for both).

## Configuration

All settings are environment variables (see [`.env.example`](.env.example) and `app/core/config.py`). Startup refuses a missing or short `JWT_SECRET` when `ENVIRONMENT=production`, and Swagger UI is disabled there.

## License

MIT
