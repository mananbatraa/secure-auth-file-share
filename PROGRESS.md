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

## Test status

- 140 passed, 0 failed (`uv run pytest`), 98% line+branch coverage.
- `ruff check`, `ruff format --check`, `mypy --strict` (app + tests) all clean.
- Docker image not built in the sandbox (package downloads are blocked there); CI builds it.

## Next steps (ideas for the remaining runs)

1. Confirm the first CI run is green (look at Actions on the repo); fix anything that differs from local.
2. Direct-to-S3 uploads via presigned POST (with a size condition), then a `confirm` endpoint, so large files skip the API.
3. Audit log table (logins, reuse detections, shares, downloads) + `GET /admin/audit`.
4. Optional refresh token in an HttpOnly, SameSite=strict cookie for browser clients.
5. Email verification for password sign-ups (token table + endpoint; mock mailer in tests).
6. Background cleanup job for expired refresh tokens, grants and links.
7. A k6 or Locust script for login throttling and share-link redemption under load, with results in the README.
8. Final run (Nov 21, 10:40 PM): polish pass and report ALL TESTS PASSING / TESTS FAILING.

## Local test setup used in the sandbox

Postgres 16 binaries at /usr/lib/postgresql/16/bin (initdb into /var/tmp/pgdata, trust auth), `redis-server` on 6379, `createdb fileshare_test`. Tests start a moto S3 server themselves.
