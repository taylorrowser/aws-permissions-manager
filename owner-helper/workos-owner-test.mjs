#!/usr/bin/env node
/** Owner-run, dependency-free AuthKit smoke test. See README.md before --run.
 * No filesystem writes, external packages, token logging, telemetry, or API key.
 * Only --help is allowed by default; --run deliberately starts one new device flow.
 */
import https from 'node:https';
import { createPublicKey, verify } from 'node:crypto';
import { pathToFileURL } from 'node:url';
import { performance } from 'node:perf_hooks';

export const CONFIG = Object.freeze({
  appId: 'app_01M4F8908SNZGNK94B9194PTQ2',
  clientId: 'client_01M4F8908R45SEPPWV0KN3Q7NW',
  environmentId: 'environment_01M0WAF6WHJSEW95T4PTT5D2Y1',
  issuer: 'https://api.workos.com/user_management/client_01M0WAF72P892WH9FCE0VFRGWC',
  jwksPath: '/sso/jwks/client_01M0WAF72P892WH9FCE0VFRGWC',
  verificationUri: 'https://rousing-school-60.authkit.app/device',
  ownerUserId: 'user_01M0WD1S3ZX1R7KG75D2Z8SHTZ',
  maxTokenSeconds: 300,
  configuredMaxSessionSeconds: 3600,
});
const AUTH_PATH = '/user_management/authenticate';
const DEVICE_PATH = '/user_management/authorize/device';
const MAX_BYTES = 1_048_576;
const MAX_AUTH_SECONDS = 600;
const MAX_RETRY_MS = 24_000; // Stay inside WorkOS's documented 30-second refresh replay grace.
const TRANSIENT_STATUSES = new Set([408, 429, 500, 502, 503, 504]);
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
export class SafeError extends Error {}
const fail = message => { throw new SafeError(message); };
const isObject = value => value && typeof value === 'object' && !Array.isArray(value);
const isId = (value, prefix) => typeof value === 'string' && new RegExp(`^${prefix}_[A-Z0-9]{26}$`).test(value);
const isToken = value => typeof value === 'string' && value.length > 0 && value.length <= 100_000;
const iso = seconds => {
  const date = new Date(seconds * 1000);
  return Number.isFinite(date.getTime()) ? date.toISOString() : 'an invalid timestamp (review required)';
};

// Keep the compatibility floor separate from Node's security-support lifecycle.
// All required APIs are built into Node 18; no package or fetch polyfill is used.
export function validateNodeVersion(version = process.versions.node) {
  const match = typeof version === 'string' && /^(\d+)\.\d+\.\d+$/.exec(version);
  if (!match || Number(match[1]) < 18) {
    fail('This helper requires Node.js 18 or newer. Use a supported Node.js 22 or 24 LTS release when possible.');
  }
  return Number(match[1]);
}

// This transport pins the host, validates TLS, has a total deadline, never follows
// redirects, and does not consult HTTP(S)_PROXY. Raw bodies/errors never get printed.
export function request(path, form = null, timeoutMs = 8_000) {
  const allowed = path === AUTH_PATH || path === DEVICE_PATH || path === CONFIG.jwksPath ||
    /^\/user_management\/sessions\/logout\?session_id=session_[A-Z0-9]{26}$/.test(path);
  if (!allowed) return Promise.reject(new SafeError('Refused an unexpected API path.'));
  return new Promise((resolve, reject) => {
    let finished = false;
    let chunks = [];
    let size = 0;
    let encoded = form ? new URLSearchParams(form).toString() : null;
    const finish = (error, result) => {
      if (finished) return;
      finished = true;
      clearTimeout(timer);
      for (const chunk of chunks) chunk.fill(0);
      chunks = [];
      encoded = null;
      error ? reject(error) : resolve(result);
    };
    const req = https.request({
      hostname: 'api.workos.com', port: 443, path,
      method: form ? 'POST' : 'GET', agent: false, rejectUnauthorized: true,
      headers: { Accept: 'application/json', 'User-Agent': 'owner-authkit-smoke-test/1',
        ...(form ? { 'Content-Type': 'application/x-www-form-urlencoded',
          'Content-Length': Buffer.byteLength(encoded) } : {}) },
    }, res => {
      res.on('data', chunk => {
        size += chunk.length;
        if (size > MAX_BYTES) {
          req.destroy();
          finish(new SafeError('API response exceeded the safe size limit.'));
        } else chunks.push(chunk);
      });
      res.on('end', () => {
        let data = {};
        const body = Buffer.concat(chunks);
        try { data = JSON.parse(body.toString('utf8')); } catch { /* Status is enough for logout. */ }
        body.fill(0);
        finish(null, { status: res.statusCode, data: isObject(data) ? data : {} });
      });
      res.on('error', () => finish(new SafeError('Network response was interrupted.')));
    });
    const timer = setTimeout(() => {
      req.destroy();
      finish(new SafeError('Network request timed out.'));
    }, Math.max(1, timeoutMs));
    req.on('error', () => finish(new SafeError('Network request failed.')));
    req.end(encoded ?? undefined);
  });
}

export function parseJwt(token) {
  if (!isToken(token)) fail('No access token was returned.');
  const parts = token.split('.');
  if (parts.length !== 3 || parts.some(p => !/^[A-Za-z0-9_-]+$/.test(p))) fail('Invalid JWT format.');
  try {
    const header = JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8'));
    const claims = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
    if (!isObject(header) || !isObject(claims)) fail('Invalid JWT structure.');
    return { parts, header, claims };
  } catch { fail('Invalid JWT structure.'); }
}

export function verifyToken(token, jwks) {
  const { parts, header, claims } = parseJwt(token);
  if (header.alg !== 'RS256' || typeof header.kid !== 'string' || header.crit !== undefined ||
      header.jku !== undefined || header.jwk !== undefined || header.x5u !== undefined) {
    fail('Unsupported JWT signing header.');
  }
  if (!Array.isArray(jwks?.keys)) fail('No public signing keys were returned.');
  const matches = jwks.keys.filter(k => k.kid === header.kid && k.kty === 'RSA' &&
    (!k.alg || k.alg === 'RS256') && (!k.use || k.use === 'sig') &&
    (!k.key_ops || (Array.isArray(k.key_ops) && k.key_ops.includes('verify'))) && !k.d);
  if (matches.length !== 1) fail('The JWT signing key was not uniquely identified.');
  let valid = false;
  try {
    const key = createPublicKey({ key: matches[0], format: 'jwk' });
    if (key.asymmetricKeyDetails?.modulusLength < 2048) fail('Signing key was too small.');
    valid = verify('RSA-SHA256', Buffer.from(`${parts[0]}.${parts[1]}`), key, Buffer.from(parts[2], 'base64url'));
  } catch { fail('Unable to validate the JWT signature.'); }
  if (!valid) fail('The JWT signature was invalid.');
  if (claims.iss !== CONFIG.issuer) fail('The signed JWT issuer did not match this environment.');
  if (claims.client_id !== CONFIG.clientId) fail('The signed JWT belongs to a different application.');
  if (!isId(claims.sid, 'session') || !isId(claims.sub, 'user')) fail('Missing or invalid signed session identity.');
  if (claims.aud !== undefined && claims.aud !== CONFIG.clientId &&
      !(Array.isArray(claims.aud) && claims.aud.includes(CONFIG.clientId))) fail('Unexpected JWT audience.');
  return claims;
}

export function validateTiming(claims, nowSeconds = Math.floor(Date.now() / 1000)) {
  if (!Number.isSafeInteger(claims.exp) || !Number.isSafeInteger(claims.iat) ||
      claims.exp <= claims.iat || claims.exp - claims.iat > CONFIG.maxTokenSeconds) {
    fail('Access-token lifetime exceeded 300 seconds or was invalid.');
  }
  if (claims.iat > nowSeconds + 30 || claims.exp <= nowSeconds ||
      (claims.nbf !== undefined && (!Number.isSafeInteger(claims.nbf) || claims.nbf > nowSeconds + 30))) {
    fail('Access-token timestamps were not currently valid; check the local clock.');
  }
}

export function validateDevice(data) {
  if (!isToken(data.device_code) || !/^[A-Z0-9]{4}-[A-Z0-9]{4}$/.test(data.user_code ?? '') ||
      data.verification_uri !== CONFIG.verificationUri ||
      !Number.isFinite(data.expires_in) || data.expires_in <= 0 || data.expires_in > MAX_AUTH_SECONDS ||
      !Number.isFinite(data.interval ?? 5) || (data.interval ?? 5) < 1 || (data.interval ?? 5) > 60) {
    fail('Unexpected device authorization response; no browser was opened.');
  }
  // Ignore verification_uri_complete rather than opening an unverified response URL.
  return { deviceCode: data.device_code, userCode: data.user_code,
    expiresIn: data.expires_in, interval: Math.max(5, data.interval ?? 5) };
}

export async function pollDevice(device, { transport = request, delay = sleep, now = () => performance.now(),
  cancelled = () => false } = {}) {
  const deadline = now() + device.expiresIn * 1000;
  let interval = device.interval * 1000;
  while (now() < deadline) {
    if (cancelled()) fail('Test cancelled before token receipt.');
    await delay(Math.min(interval, deadline - now()));
    if (cancelled()) fail('Test cancelled before token receipt.');
    if (now() >= deadline) break;
    let result;
    try {
      result = await transport(AUTH_PATH, { grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
        client_id: CONFIG.clientId, device_code: device.deviceCode }, Math.min(8_000, deadline - now()));
    } catch {
      // A lost success response could have created a session. Never start a second flow automatically.
      fail('Token-exchange response was lost. Stop and check this application for a new session.');
    }
    if (result.status === 200) return result.data;
    if (result.data.error === 'authorization_pending') continue;
    if (result.data.error === 'slow_down' || result.status === 429) { interval += 5_000; continue; }
    if (result.data.error === 'access_denied') fail('Device approval was denied.');
    if (result.data.error === 'expired_token') fail('Device approval expired. No new flow was started.');
    fail(`Token exchange stopped (HTTP ${Number(result.status) || 0}); no response body was logged.`);
  }
  fail('Device approval timed out. No new flow was started.');
}

export async function refresh(refreshToken, { transport = request, delay = sleep, now = () => performance.now() } = {}) {
  const deadline = now() + MAX_RETRY_MS;
  let pause = 1_000;
  let uncertain = false;
  while (now() < deadline) {
    let result;
    try {
      result = await transport(AUTH_PATH, { grant_type: 'refresh_token',
        client_id: CONFIG.clientId, refresh_token: refreshToken }, Math.min(6_000, deadline - now()));
    } catch {
      result = { status: 408, data: {} };
    }
    if (!TRANSIENT_STATUSES.has(result.status)) return { ...result, uncertain };
    uncertain = true;
    if (now() + pause >= deadline) break;
    await delay(pause);
    pause = Math.min(pause * 2, 4_000);
  }
  fail('Refresh was inconclusive after bounded network retries.');
}

export function adoptTokens(data, state, jwks) {
  if (!isToken(data.access_token)) fail('No access token was returned; session lookup may be needed.');
  const hasRefreshToken = isToken(data.refresh_token);
  // Preserve a verified session identity even if the response is incomplete.
  if (hasRefreshToken) state.refreshToken = data.refresh_token;
  const claims = verifyToken(data.access_token, jwks);
  if (state.sessionId && (state.sessionId !== claims.sid || state.userId !== claims.sub)) {
    fail('Refresh changed the signed session identity; exact-session cleanup needs review.');
  }
  state.sessionId = claims.sid;
  state.userId = claims.sub;
  state.refreshCurrent = hasRefreshToken;
  if (Number.isSafeInteger(claims.exp)) state.latestAccessExpiry = Math.max(state.latestAccessExpiry ?? 0, claims.exp);
  if (claims.sub !== CONFIG.ownerUserId) fail('The signed token belongs to a different account; cleaning up this test session.');
  validateTiming(claims);
  if (!hasRefreshToken) fail('No refresh token was returned; cleaning up the verified test session.');
  return claims;
}

export async function cleanUp(state, jwks, dependencies = {}) {
  const transport = dependencies.transport ?? request;
  const delay = dependencies.delay ?? sleep;
  if (!state.sessionId) return { ended: false, outcome: 'No verified session ID available for cleanup.' };
  // A logout redirect or HTTP 200 alone is never treated as successful revocation.
  try {
    await transport(`/user_management/sessions/logout?session_id=${state.sessionId}`);
  } catch { /* Refresh rejection below is still the useful observation. */ }
  if (!state.refreshToken) return { ended: false, outcome: 'No refresh token available to verify session end.' };
  await delay(1_000);
  const knownCurrent = state.refreshCurrent === true;
  state.refreshCurrent = false;
  try {
    const result = await refresh(state.refreshToken, dependencies);
    if (result.status === 400 && result.data.error === 'invalid_grant' && knownCurrent && !result.uncertain) {
      return { ended: true, outcome: 'Session-end check passed: latest refresh token rejected (invalid_grant).' };
    }
    if (result.status === 200) {
      adoptTokens(result.data, state, jwks);
      // Do not lose a rotated token or claim cleanup passed. One more logout is cleanup only.
      try { await transport(`/user_management/sessions/logout?session_id=${state.sessionId}`); } catch {}
      return { ended: false, outcome: 'Refresh remained usable after logout. Exact-session cleanup is required.' };
    }
    return { ended: false, outcome: 'Session end was not confirmed; exact-session cleanup is required.' };
  } catch {
    return { ended: false, outcome: 'Session-end check was inconclusive; exact-session cleanup is required.' };
  }
}

export async function runOwnerTest() {
  if (!process.stdin.isTTY || !process.stdout.isTTY) fail('Run this yourself in a private, interactive terminal.');
  if (process.env.NODE_OPTIONS || process.env.NODE_DEBUG || process.env.NODE_DEBUG_NATIVE ||
      process.env.SSLKEYLOGFILE || process.env.NODE_V8_COVERAGE || process.env.NODE_COMPILE_CACHE ||
      process.env.NODE_REDIRECT_WARNINGS || process.env.NODE_TLS_REJECT_UNAUTHORIZED === '0' ||
      process.execArgv.length > 0) {
    fail('Run without Node debugging, profiling, preloads, tracing, or TLS key logging.');
  }
  const nodeMajor = validateNodeVersion();
  const state = { refreshToken: null, sessionId: null, userId: null, latestAccessExpiry: 0 };
  let cancelled = false;
  let received = false;
  let passed = false;
  let jwks;
  const stop = () => { cancelled = true; };
  process.on('SIGINT', stop);
  process.on('SIGTERM', stop);
  if (nodeMajor < 22) {
    console.log('Warning: Node.js 18–21 are end-of-life. Prefer Node.js 22 or 24 LTS for security updates.');
  }
  console.log('AWS Permissions CLI: one device sign-in, one refresh, then session-specific logout.');
  console.log('No API key is needed. Tokens stay in process memory and are never displayed.');
  console.log('Keep this terminal open until cleanup finishes. Ctrl+C requests cleanup.');
  console.log(`Test started: ${new Date().toISOString()}`);
  console.log(`Application: ${CONFIG.appId}`);
  try {
    const keys = await request(CONFIG.jwksPath);
    if (keys.status !== 200 || !Array.isArray(keys.data.keys)) fail('Could not load the pinned public signing keys.');
    jwks = keys.data;
    if (cancelled) fail('Test cancelled before device authorization.');
    const response = await request(DEVICE_PATH, { client_id: CONFIG.clientId });
    if (response.status !== 200) fail(`Device authorization failed (HTTP ${Number(response.status) || 0}).`);
    const device = validateDevice(response.data);
    // The returned device secret is never displayed, persisted, or transferred elsewhere.
    delete response.data.device_code;
    console.log(`Open this address in your own browser: ${CONFIG.verificationUri}`);
    console.log(`Enter this user code and confirm it matches: ${device.userCode}`);
    console.log('Use the owner account. This code belongs only to this terminal run.');
    let tokens;
    try { tokens = await pollDevice(device, { cancelled: () => cancelled }); }
    finally { device.deviceCode = null; }
    received = true;
    const first = adoptTokens(tokens, state, jwks);
    tokens = null;
    console.log(`Device exchange passed. Signed token lifetime: ${first.exp - first.iat} seconds.`);
    console.log(`Test session ID: ${state.sessionId}`);
    if (cancelled) fail('Test cancelled; proceeding to cleanup.');
    await sleep(1_100);
    if (cancelled) fail('Test cancelled; proceeding to cleanup.');
    state.refreshCurrent = false;
    const renewed = await refresh(state.refreshToken);
    if (renewed.status !== 200) fail(`Refresh did not succeed (HTTP ${Number(renewed.status) || 0}).`);
    const next = adoptTokens(renewed.data, state, jwks);
    renewed.data = {};
    if (cancelled) fail('Test cancelled; proceeding to cleanup.');
    console.log(`Refresh passed. Signed token lifetime: ${next.exp - next.iat} seconds.`);
    passed = true;
  } catch (error) {
    console.log(error instanceof SafeError ? error.message : 'Test stopped due to an unexpected error; raw details were withheld.');
  } finally {
    if (received) {
      console.log('Checking session-specific logout now...');
      const cleanup = await cleanUp(state, jwks);
      console.log(cleanup.outcome);
      if (state.sessionId) console.log(`Cleanup session ID: ${state.sessionId}`);
      if (!cleanup.ended) {
        if (state.sessionId) {
          console.log(`Ask for revokeUserSession on this exact test session in ${CONFIG.environmentId}.`);
        } else {
          console.log('Ask for a new-session lookup using the printed application and test start time.');
        }
        console.log('Do not revoke all user sessions or create an API key.');
        passed = false;
      }
      if (state.latestAccessExpiry) {
        console.log(`Latest observed access-token expiry: ${iso(state.latestAccessExpiry)}.`);
        console.log('Issued JWTs may stay valid until expiry; lost responses may contain newer JWTs.');
        console.log('A rejected refresh does not prove immediate revocation of those JWTs.');
      }
    } else {
      console.log('No tokens were received. If exchange was interrupted, check for a session before retrying.');
    }
    state.refreshToken = null;
    process.removeListener('SIGINT', stop);
    process.removeListener('SIGTERM', stop);
  }
  console.log('App configuration checked separately: 300-second tokens; 3,600-second maximum session.');
  console.log('This short test does not empirically wait out the one-hour session limit.');
  console.log(passed ? 'RESULT: exchange, refresh, and session-end check passed.' : 'RESULT: incomplete; review the safe status lines above.');
  return passed ? 0 : 2;
}

const HELP = `Owner-run WorkOS smoke test (no credentials are embedded).
Compatibility: Node.js 18 or newer. Node.js 22 or 24 LTS is recommended; 18–21 are end-of-life.
Usage:
  node workos-owner-test.mjs --help  # No network activity
  node workos-owner-test.mjs --run   # One new live device flow, only when you are ready
Read README.md first. Do not run under an assistant tool, terminal recorder, or debugger.
No files are written and no tokens are printed. Live verification has not been run by the preparer.`;
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  if (process.argv.length === 3 && process.argv[2] === '--run') {
    runOwnerTest().then(code => { process.exitCode = code; }).catch(error => {
      console.error(error instanceof SafeError ? error.message : 'Stopped; raw error details withheld.');
      process.exitCode = 2;
    });
  } else {
    console.log(HELP);
    if (process.argv.length > 3 || (process.argv[2] && process.argv[2] !== '--help')) process.exitCode = 2;
  }
}
