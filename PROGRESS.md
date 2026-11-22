# Progress

Handoff notes between build runs. Slot: Nov 20-21 2026 (runs at 10:40 AM, 4:40 PM, 10:40 PM Phoenix; the Nov 20 morning run was lost waiting for the repo, so work started ~11:30 AM Phoenix).

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

## Done (Nov 20, late run)

- CI was green for the evening run's push.
- **Cleanup worker** (`python -m app.cleanup`, `--once`, `--dry-run`, compose `cleanup` service): removes expired upload intents and their S3 objects (after a 1 h grace, longer than the 5-minute completion grace), refresh tokens and dead share links after a 7-day retention, and expired grants. Batches with `FOR UPDATE SKIP LOCKED`, rows before objects, one `maintenance.cleanup` audit event per productive sweep. Migration 0004 indexes `expires_at`.
- **Email verification**: `users.email_verified_at` (migration 0005, backfills OAuth-linked accounts). Stateless JWT link token (own audience, 24 h, bound to a fingerprint of the address). `POST /auth/verify-email`, `POST /auth/verify-email/resend` (capped 3/h per account). Unverified users get `403 email_not_verified` on uploads, grants and share links (`REQUIRE_VERIFIED_EMAIL`). Mailer abstraction: SMTP, or a logging mailer that redacts bodies in production; Mailpit in compose. Registration never fails on a mail outage.
- **Pre-account-takeover defense**: OAuth linking to an unverified password account removes the password and revokes its sessions and access tokens (audited).
- Test fixture `make_user` now marks users verified by default (`verified=False` for the new tests); audit tests count the new `auth.email_verification_sent` event.
- README: features, diagram, verification and cleanup sections, API rows, design decisions.

## Done (Nov 21, morning run)

- CI was green for the late run's push.
- **Password reset** (`POST /auth/password-reset/request`, `/confirm`; `app/services/password_reset.py`): always `202` with an identical body, mail sent as a background task after the response, throttled per IP and per hashed address (known or not). Token: 30-minute JWT, own audience, bound to user, address fingerprint and an HMAC of the current password hash, so it is single-use with no table, a newer reset kills older links, and change-password kills pending links. Confirm takes a row lock (concurrent confirms: exactly one wins), revokes all sessions/access tokens, verifies the address, works for OAuth-only accounts. Audited (`auth.password_reset_requested`, `auth.password_reset`, with failure reasons).
- **Browser sessions** (`app/api/session_cookies.py`): `X-Token-Delivery: cookie` on login puts the refresh token in an HttpOnly, Secure, SameSite=Strict cookie on `/auth` (body gets `refresh_token: null` plus `csrf_token`). `/auth/refresh` and `/auth/logout` fall back to the cookie and then require `X-CSRF-Token` = HMAC(key, refresh token) (signed double submit); body tokens win and need no CSRF. Logout clears cookies. CORS now allows credentials and the new headers; settings refuse `CORS_ORIGINS=["*"]` and `COOKIE_SECURE=false` in production.
- README: feature bullets, password reset and browser session sections (with a sequence diagram), API rows, two design decisions. `.env.example` has the new settings.

## Done (Nov 21, afternoon run)

- CI was green for the morning run's push.
- **TOTP two-factor auth** (`app/core/totp.py`, `app/services/mfa.py`, `app/api/routes/mfa.py`, migration 0006: `users.totp_secret/totp_enabled_at/totp_last_step`, `mfa_recovery_codes`). RFC 6238 on `hmac`, tested against the RFC 4226/6238 vectors, ±1 step drift.
  - Enrolment: `POST /auth/mfa/totp/setup` (needs password unless OAuth-only, and a verified email) then `/totp/enable` with a code, which returns 10 recovery codes. `GET /auth/mfa` for status.
  - Sign-in: login and the OAuth callback return `{mfa_required, mfa_token}` when 2FA is on; `POST /auth/mfa/verify` with a TOTP or recovery code returns tokens (cookie delivery supported). Challenge token: 5-minute JWT, own audience, single use (Redis `SET NX` on jti), bound to `token_version`.
  - Replay safety: last accepted step stored under a row lock (5 concurrent verifies with one code: exactly one wins); recovery codes consumed by one conditional UPDATE; codes stored as per-user HMACs.
  - Per-account throttle on every code check (`MFA_MAX_ATTEMPTS`/`MFA_WINDOW_SECONDS`), fails closed on Redis outage.
  - Seeds AES-256-GCM encrypted with the user id as AAD (`MFA_ENCRYPTION_KEY`, else derived from `JWT_SECRET` via HKDF).
  - `POST /auth/mfa/disable` (password + code), `POST /auth/mfa/recovery-codes` (regenerate, needs TOTP), `POST /admin/users/{id}/mfa/reset` (also ends sessions). OAuth pre-account-takeover path also clears any factor.
  - Audit actions `auth.mfa_setup_started/enabled/disabled/challenge_issued/failed/recovery_codes_regenerated`, `admin.mfa_reset`; logins record `{mfa: totp|recovery_code}`.
- `UserOut` now has `mfa_enabled`. `AuthService.login` was split into `authenticate` + `complete_login`.
- README: feature bullet, 2FA section with a sequence diagram, API rows, two design decisions; `.env.example` has the MFA settings.

## Done (Nov 21, final run: polish)

- CI was green for the afternoon run's push.
- **k6 load test** (`loadtest/k6/security-under-load.js`, `loadtest/run.sh`, `loadtest/README.md`), also a new `loadtest` CI job. Thresholds make k6 fail on drift:
  - 200 concurrent redemptions of a 25-download share link: exactly 25 redirects, 175 `410`.
  - 150 concurrent wrong-password logins on one account from 150 addresses: exactly 5 reach the password check, 145 `429` with `Retry-After`.
  - 40 signed-in users for 30 s: ~310 req/s, refresh p95 ~115 ms, `/users/me` p95 ~60 ms, no errors. The runner also fails if the API logged a `500`.
  - Checked that a wrong expectation (`LOGIN_MAX_PER_EMAIL=4`) makes k6 exit 99.
- README: load test section with results, layout block lists `loadtest/` and the newer services, stale test counts fixed (334, 99%).

## Test status (final)

- **ALL TESTS PASSING**: 334 passed, 0 failed (`uv run pytest`), 99% line+branch coverage.
- `ruff check`, `ruff format --check`, `mypy --strict` (app + tests) all clean.
- k6 load test passes all thresholds (3 runs locally).
- Docker image not built in the sandbox (package downloads are blocked there); CI builds it.

## Slot finished

This slot ended Nov 21 (Phoenix). Scheduled runs move on to the next project; nothing more is planned here. Ideas if Manan comes back to it:

1. OAuth callback: hand off to a frontend with a one-time code (cookie delivery and the 2FA challenge via redirect instead of JSON).
2. WebAuthn/passkeys as a phishing-resistant second factor.
3. A small React frontend or a deployed demo.

## Local test setup used in the sandbox

Postgres 16 binaries at /usr/lib/postgresql/16/bin (initdb into /var/tmp/pgdata, trust auth), `redis-server` on 6379, `createdb fileshare_test`. Tests start a moto S3 server themselves.
