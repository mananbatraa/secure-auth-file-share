// Load test: do the security limits still hold when many requests race?
//
// Three scenarios run one after another against a live API:
//   share_link_race  200 concurrent redemptions of a link capped at MAX_DOWNLOADS.
//                    Exactly MAX_DOWNLOADS must get a presigned redirect (307).
//   brute_force      150 concurrent wrong-password logins on one account.
//                    Exactly LOGIN_MAX_PER_EMAIL may reach the password check (401);
//                    the rest must be throttled (429) with a Retry-After header.
//   sessions         Signed-in users refreshing tokens and calling /users/me, to
//                    measure latency and throughput of the normal path.
//
// The API must run with TRUST_PROXY_HEADERS=true so each simulated client can send
// its own X-Forwarded-For (otherwise the per-IP limits throttle the whole test), and
// REQUIRE_VERIFIED_EMAIL=false so setup can upload without reading email.
// See loadtest/README.md for the exact commands.
import http from 'k6/http';
import { check, fail } from 'k6';
import { Counter, Trend } from 'k6/metrics';
import exec from 'k6/execution';

const BASE = __ENV.BASE_URL || 'http://localhost:8000';
const MAX_DOWNLOADS = Number(__ENV.MAX_DOWNLOADS || 25);
const LOGIN_MAX_PER_EMAIL = Number(__ENV.LOGIN_MAX_PER_EMAIL || 5);
const SESSION_USERS = Number(__ENV.SESSION_USERS || 40);
const PASSWORD = 'load-test-Passw0rd!';
const RUN = `${Date.now()}`;

const shareOk = new Counter('share_link_redirects');
const shareRefused = new Counter('share_link_refused');
const shareUnexpected = new Counter('share_link_unexpected');
const bruteChecked = new Counter('brute_force_password_checked');
const bruteThrottled = new Counter('brute_force_throttled');
const bruteUnexpected = new Counter('brute_force_unexpected');
const refreshLatency = new Trend('session_refresh_ms', true);
const meLatency = new Trend('session_me_ms', true);

export const options = {
  scenarios: {
    share_link_race: {
      executor: 'shared-iterations',
      exec: 'redeemShareLink',
      vus: 100,
      iterations: 200,
      maxDuration: '60s',
    },
    brute_force: {
      executor: 'shared-iterations',
      exec: 'bruteForce',
      vus: 50,
      iterations: 150,
      startTime: '15s',
      maxDuration: '60s',
    },
    sessions: {
      executor: 'constant-vus',
      exec: 'session',
      vus: SESSION_USERS,
      duration: '30s',
      startTime: '35s',
    },
  },
  thresholds: {
    // The guarantees under test. Any drift fails the run (k6 exits non-zero).
    share_link_redirects: [`count==${MAX_DOWNLOADS}`],
    share_link_unexpected: ['count==0'],
    brute_force_password_checked: [`count==${LOGIN_MAX_PER_EMAIL}`],
    brute_force_unexpected: ['count==0'],
    'http_req_failed{scenario:sessions}': ['rate==0'],
    session_refresh_ms: ['p(95)<250'],
    session_me_ms: ['p(95)<100'],
  },
};

const json = { headers: { 'Content-Type': 'application/json' } };

// A distinct, stable fake client address per id, so per-IP limits apply per simulated client.
function ip(n) {
  return `10.${(n >> 16) & 255}.${(n >> 8) & 255}.${n & 255}`;
}

function withIp(n, headers = {}) {
  return { headers: { 'Content-Type': 'application/json', 'X-Forwarded-For': ip(n), ...headers } };
}

function register(email, n) {
  const res = http.post(`${BASE}/auth/register`, JSON.stringify({ email, password: PASSWORD }), withIp(n));
  if (res.status !== 201) fail(`register ${email}: ${res.status} ${res.body}`);
}

function login(email, n) {
  const res = http.post(`${BASE}/auth/login`, JSON.stringify({ email, password: PASSWORD }), withIp(n));
  if (res.status !== 200) fail(`login ${email}: ${res.status} ${res.body}`);
  return res.json();
}

export function setup() {
  // Owner uploads a file and creates a capped share link.
  const owner = `owner-${RUN}@example.com`;
  register(owner, 1);
  const tokens = login(owner, 1);
  const upload = http.post(
    `${BASE}/files`,
    { upload: http.file('hello from k6\n'.repeat(64), 'report.txt', 'text/plain') },
    { headers: { Authorization: `Bearer ${tokens.access_token}`, 'X-Forwarded-For': ip(1) } },
  );
  if (upload.status !== 201) fail(`upload: ${upload.status} ${upload.body}`);
  const link = http.post(
    `${BASE}/files/${upload.json('id')}/links`,
    JSON.stringify({ expires_in_seconds: 3600, max_downloads: MAX_DOWNLOADS }),
    { headers: { ...json.headers, Authorization: `Bearer ${tokens.access_token}`, 'X-Forwarded-For': ip(1) } },
  );
  if (link.status !== 201) fail(`share link: ${link.status} ${link.body}`);

  // Brute-force victim.
  const victim = `victim-${RUN}@example.com`;
  register(victim, 2);

  // One account per session VU, each from its own address.
  const sessions = [];
  for (let i = 0; i < SESSION_USERS; i++) {
    const email = `user-${i}-${RUN}@example.com`;
    register(email, 100 + i);
    sessions.push({ email, n: 100 + i });
  }
  return { linkToken: link.json('token'), victim, sessions };
}

export function redeemShareLink(data) {
  // Every redemption comes from a different address, so the per-IP throttle stays out of
  // the way and only the download cap decides.
  const n = 10_000 + exec.scenario.iterationInTest;
  const res = http.get(`${BASE}/s/${data.linkToken}`, { redirects: 0, headers: { 'X-Forwarded-For': ip(n) } });
  if (res.status === 307) {
    shareOk.add(1);
    check(res, { 'redirect is presigned': (r) => (r.headers.Location || '').includes('Signature') });
  } else if (res.status === 410) {
    shareRefused.add(1);
  } else {
    shareUnexpected.add(1);
  }
}

export function bruteForce(data) {
  // Different source addresses: only the per-account bucket can stop this.
  const n = 50_000 + exec.scenario.iterationInTest;
  const res = http.post(
    `${BASE}/auth/login`,
    JSON.stringify({ email: data.victim, password: 'wrong-password-guess' }),
    withIp(n),
  );
  if (res.status === 401) {
    bruteChecked.add(1);
  } else if (res.status === 429) {
    bruteThrottled.add(1);
    check(res, { 'throttled response has Retry-After': (r) => Number(r.headers['Retry-After']) > 0 });
  } else {
    bruteUnexpected.add(1);
  }
}

const vuState = {};

export function session(data) {
  const vu = exec.vu.idInTest;
  const me = data.sessions[(vu - 1) % data.sessions.length];
  if (!vuState.refresh) {
    const tokens = login(me.email, me.n);
    vuState.access = tokens.access_token;
    vuState.refresh = tokens.refresh_token;
  }
  const r = http.post(`${BASE}/auth/refresh`, JSON.stringify({ refresh_token: vuState.refresh }), withIp(me.n));
  refreshLatency.add(r.timings.duration);
  if (!check(r, { 'refresh 200': (x) => x.status === 200 })) return;
  vuState.access = r.json('access_token');
  vuState.refresh = r.json('refresh_token');

  for (let i = 0; i < 4; i++) {
    const res = http.get(`${BASE}/users/me`, withIp(me.n, { Authorization: `Bearer ${vuState.access}` }));
    meLatency.add(res.timings.duration);
    check(res, { 'me 200': (x) => x.status === 200 });
  }
}

export function handleSummary(data) {
  const v = (name, stat = 'count') => (data.metrics[name] ? data.metrics[name].values[stat] : 0);
  const lines = [
    '',
    `share link (cap ${MAX_DOWNLOADS}, 200 concurrent): ${v('share_link_redirects')} redirected, ${v('share_link_refused')} refused, ${v('share_link_unexpected')} unexpected`,
    `brute force (limit ${LOGIN_MAX_PER_EMAIL}, 150 concurrent): ${v('brute_force_password_checked')} reached the password check, ${v('brute_force_throttled')} throttled, ${v('brute_force_unexpected')} unexpected`,
    `sessions (${SESSION_USERS} VUs, 30 s): refresh p50 ${v('session_refresh_ms', 'med').toFixed(1)} ms / p95 ${v('session_refresh_ms', 'p(95)').toFixed(1)} ms; /users/me p50 ${v('session_me_ms', 'med').toFixed(1)} ms / p95 ${v('session_me_ms', 'p(95)').toFixed(1)} ms; ${(v('http_reqs', 'rate')).toFixed(0)} req/s overall`,
    '',
  ];
  return { stdout: lines.join('\n') };
}
