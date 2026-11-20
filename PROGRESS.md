# Progress

Handoff notes between build runs. Slot: Nov 20-21 2026 (four runs; the Nov 20 morning run was lost waiting for the repo, so work started ~11:30 AM Phoenix).

## Done (Nov 20, first working run)

- FastAPI app factory, env-driven settings, structured logging, security headers, request IDs, uniform error shape.
- Auth: Argon2id passwords with policy, JWT access tokens (pinned alg, iss/aud), opaque hashed refresh tokens with rotation, family revocation on reuse (row lock makes concurrent refresh deterministic), logout, logout-all, change-password, `token_version` for instant access-token invalidation.
- Login throttling: Redis Lua sliding window (Redis TIME clock), per-account and per-IP, fail-closed by default.
- OAuth: GitHub + Google, state + PKCE in Redis (single use, provider-bound), link by verified email only.
- RBAC: admin / member / guest permission matrix; admin user listing, role change, deactivation.
- Files: upload with size cap + SHA-256 + filename/content-type sanitising, presigned downloads (TTL clamped, always attachment), viewer/editor grants with expiry, anonymous share links (expiry, revocation, atomic download cap, per-IP throttle).
- Alembic initial migration (reversible, drift test), Dockerfile (non-root, healthcheck), docker-compose (API, migrate, Postgres, Redis, MinIO), GitHub Actions CI (ruff, strict mypy, tests with Postgres + Redis services, coverage, Docker build).
- README with Mermaid architecture and rotation diagrams, design decisions, API table.

## Done (Nov 20, evening run)

- First CI run on main was green (lint, tests, Docker build).
- **Audit log**: `audit_events` table (migration 0002) with an append-only trigger (UPDATE/DELETE raise), identity id for total ordering, no FK on actor so rows outlive users. `AuditLog` service stages success events in the action's own transaction and writes failures separately (`record_now`, which never turns a 4xx into a 500). Covers register, login success/failure (with reason), throttled logins, refresh-token reuse, logout, logout-all, password change, OAuth login, admin user changes (with a from/to diff), and the whole file lifecycle including anonymous share-link redemption and rejection. `GET /admin/audit` (new `audit:read` permission, admin only) with filters and keyset pagination.
- **Direct-to-S3 uploads** (migration 0003, `upload_intents`): `POST /files/uploads` returns a presigned POST pinned to key, exact size, content type and optional SHA-256; `POST /files/uploads/{id}/complete` re-verifies the stored object (S3 stored checksum, else streamed hash), deletes mismatches, and turns the intent into a file with the same id. Single-use, owner-scoped, expiring.
- Fixed a test leak: the lifespan test now truncates the rows it creates.
- README: new feature bullets, upload sequence diagram, audit section, API table rows, two new design decisions. `.env.example` has the new settings.

## Test status

- 180 passed, 0 failed (`uv run pytest`), 98% line+branch coverage.
- `ruff check`, `ruff format --check`, `mypy --strict` (app + tests) all clean.
- Docker image not built in the sandbox (package downloads are blocked there); CI builds it.

## Next steps (ideas for the remaining runs)

1. Check CI is green for this run's push.
2. Background cleanup (e.g. `python -m app.cleanup`, run by a compose service or cron): delete expired upload intents and their S3 objects, expired refresh tokens, grants and links.
3. Optional refresh token in an HttpOnly, SameSite=strict cookie for browser clients (with CSRF protection on `/auth/refresh`).
4. Email verification for password sign-ups (token table + endpoint; mock mailer in tests).
5. A k6 or Locust script for login throttling and share-link redemption under load, with results in the README.
6. Final run (Nov 21, 10:40 PM): polish pass and report ALL TESTS PASSING / TESTS FAILING.

## Local test setup used in the sandbox

Postgres 16 binaries at /usr/lib/postgresql/16/bin (initdb into /var/tmp/pgdata, trust auth), `redis-server` on 6379, `createdb fileshare_test`. Tests start a moto S3 server themselves.
