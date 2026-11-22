# Load test: security limits under concurrency

[`k6/security-under-load.js`](k6/security-under-load.js) checks that the limits which matter for security still hold when requests race, and measures the normal signed-in path:

| Scenario | Load | Must hold |
|---|---|---|
| `share_link_race` | 200 redemptions of one share link capped at 25 downloads, 100 VUs, each from a different address | exactly 25 presigned redirects (`307`), every other request `410` |
| `brute_force` | 150 wrong-password logins on one account, 50 VUs, each from a different address | exactly 5 reach the password check (`401`), the other 145 get `429` with `Retry-After` |
| `sessions` | 40 signed-in users for 30 s, each loop: 1 refresh-token rotation + 4 `GET /users/me` | no failed requests; p95 refresh < 250 ms, p95 `/users/me` < 100 ms |

Each guarantee is a k6 threshold, so any drift (one extra download, one extra password guess) makes k6 exit non-zero. CI runs it on every push (`loadtest` job).

## Run it

Needs `uv`, Docker, and a Postgres and Redis you can throw away:

```bash
docker compose up -d postgres redis
createdb -h localhost -U postgres fileshare_load   # once
DATABASE_URL=postgresql+asyncpg://postgres:postgres@localhost:5432/fileshare_load \
REDIS_URL=redis://localhost:6379/5 \
loadtest/run.sh
```

[`run.sh`](run.sh) migrates the database, starts a moto S3 server and the API with 2 uvicorn workers, runs k6 from the `grafana/k6` image, and also fails if the API logged any `500`. The API runs with `TRUST_PROXY_HEADERS=true` so each simulated client can bring its own `X-Forwarded-For` (otherwise the per-IP limits would throttle the test itself), and `REQUIRE_VERIFIED_EMAIL=false` so setup can upload without reading email. Don't use either setting like this in production unless a proxy you control sets the header.

## Results

Run on a 4-vCPU cloud sandbox, API with 2 workers, Postgres 16 and Redis 7 on the same machine, k6 on the same machine too (so the numbers are conservative):

```
share link (cap 25, 200 concurrent): 25 redirected, 175 refused, 0 unexpected
brute force (limit 5, 150 concurrent): 5 reached the password check, 145 throttled, 0 unexpected
sessions (40 VUs, 30 s): refresh p50 85.9 ms / p95 114.7 ms; /users/me p50 44.0 ms / p95 59.8 ms; 312 req/s overall
```

Three runs gave the same counts every time; p95 refresh latency ranged from 115 to 148 ms across them. A refresh is a database transaction (lock the token row, insert its successor, mark the old one used) plus a JWT signature, so it costs about twice an authenticated read. Logins aren't in the throughput numbers on purpose: Argon2id is meant to be slow, and its cost is a tuning choice rather than a property of the API.
