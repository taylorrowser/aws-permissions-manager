import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, sign } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { CONFIG, SafeError, parseJwt, verifyToken, validateTiming, validateDevice,
  pollDevice, refresh, adoptTokens, cleanUp, request, validateNodeVersion } from './workos-owner-test.mjs';

// All cryptographic material below is generated locally for offline tests only.
// No production keys, device codes, access tokens, or refresh tokens are loaded.
const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
const jwk = { ...publicKey.export({ format: 'jwk' }), kid: 'offline-test', alg: 'RS256', use: 'sig' };
const jwks = { keys: [jwk] };
const now = Math.floor(Date.now() / 1000);
const sessionId = 'session_00000000000000000000000000';
const base = { iss: CONFIG.issuer, client_id: CONFIG.clientId, sub: CONFIG.ownerUserId,
  sid: sessionId, iat: now, exp: now + 300 };
function token(changes = {}, headerChanges = {}) {
  const a = Buffer.from(JSON.stringify({ alg: 'RS256', kid: 'offline-test', ...headerChanges })).toString('base64url');
  const b = Buffer.from(JSON.stringify({ ...base, ...changes })).toString('base64url');
  return `${a}.${b}.${sign('RSA-SHA256', Buffer.from(`${a}.${b}`), privateKey).toString('base64url')}`;
}
const tokens = (changes = {}) => ({ access_token: token(changes), refresh_token: 'offline-fixture-new-refresh' });
const makeState = () => ({ sessionId, userId: CONFIG.ownerUserId, refreshToken: 'offline-fixture-refresh', refreshCurrent: true, latestAccessExpiry: 0 });
function fakeClock() {
  let time = 0;
  const waits = [];
  return { now: () => time, delay: async ms => { waits.push(ms); time += ms; }, waits };
}
const device = { deviceCode: 'offline-fixture-device', userCode: 'ABCD-EFGH', expiresIn: 300, interval: 5 };
const deviceResponse = { device_code: device.deviceCode, user_code: device.userCode,
  verification_uri: CONFIG.verificationUri, expires_in: 300, interval: 5 };
const rejectsSafe = fn => assert.throws(fn, SafeError);

// Default import, help and these tests issue no live requests.
test('runtime compatibility accepts Node 18 and newer without dropping security checks', () => {
  for (const version of ['18.0.0', '18.20.8', '20.0.0', '20.20.2', '22.0.0', '22.23.3', '24.19.0']) {
    assert.equal(validateNodeVersion(version), Number(version.split('.')[0]));
  }
  assert.equal(validateNodeVersion(), Number(process.versions.node.split('.')[0]));
});
test('unsupported and malformed runtime versions are rejected', () => {
  for (const version of ['14.21.3', '16.20.2', '17.9.1', '', '18', '18.x.0', null]) {
    rejectsSafe(() => validateNodeVersion(version));
  }
});
const helperPath = fileURLToPath(new URL('./workos-owner-test.mjs', import.meta.url));
test('help and default invocation work without starting authentication', () => {
  for (const args of [[], ['--help']]) {
    const result = spawnSync(process.execPath, [helperPath, ...args], { encoding: 'utf8', timeout: 5000 });
    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /Compatibility: Node\.js 18 or newer/);
    assert.match(result.stdout, /18–21 are end-of-life/);
    assert.doesNotMatch(result.stdout, /Test started:|Enter this user code/);
  }
});
test('unknown arguments fail without starting authentication', () => {
  const result = spawnSync(process.execPath, [helperPath, '--unknown'], { encoding: 'utf8', timeout: 5000 });
  assert.equal(result.status, 2);
  assert.doesNotMatch(result.stdout, /Test started:|Enter this user code/);
});
test('live invocation from a noninteractive process is refused before network activity', () => {
  const result = spawnSync(process.execPath, [helperPath, '--run'], { encoding: 'utf8', timeout: 5000 });
  assert.equal(result.status, 2);
  assert.match(result.stderr, /private, interactive terminal/);
  assert.doesNotMatch(result.stdout, /Test started:|Enter this user code/);
});
test('valid offline-signed token verifies and has exactly 300-second lifetime', () => {
  const claims = verifyToken(token(), jwks);
  assert.deepEqual(claims, base);
  validateTiming(claims, now);
});
test('unsigned JWT, bad algorithm and key URL headers are refused', () => {
  rejectsSafe(() => parseJwt('not-a-jwt'));
  for (const header of [{ alg: 'none' }, { alg: 'HS256' }, { jku: 'https://evil.example/key' },
    { jwk }, { x5u: 'https://evil.example' }, { crit: [] }]) {
    rejectsSafe(() => verifyToken(token({}, header), jwks));
  }
});
test('altered signature, duplicate kid and unknown kid are refused', () => {
  const t = token();
  const parts = t.split('.');
  const sig = Buffer.from(parts[2], 'base64url'); sig[0] ^= 1;
  rejectsSafe(() => verifyToken(`${parts[0]}.${parts[1]}.${sig.toString('base64url')}`, jwks));
  rejectsSafe(() => verifyToken(t, { keys: [jwk, jwk] }));
  rejectsSafe(() => verifyToken(token({}, { kid: 'missing' }), jwks));
});
test('wrong issuer, client, audience and malformed identity are refused', () => {
  for (const change of [{ iss: 'https://evil.example' }, { client_id: 'client_wrong' },
    { sid: 'session_bad\nlog' }, { sub: null }, { aud: 'another-app' }]) {
    rejectsSafe(() => verifyToken(token(change), jwks));
  }
  verifyToken(token({ aud: [CONFIG.clientId] }), jwks);
});
test('expired, oversized lifetime and future/invalid timestamps are refused', () => {
  for (const changes of [{ exp: now }, { exp: now + 301 }, { iat: now + 31, exp: now + 300 },
    { nbf: now + 31 }, { iat: '0' }, { exp: Infinity }]) {
    rejectsSafe(() => validateTiming({ ...base, ...changes }, now));
  }
});
test('wrong-account token is refused but exact app session remains available for cleanup', () => {
  const state = {};
  rejectsSafe(() => adoptTokens(tokens({ sub: 'user_00000000000000000000000000' }), state, jwks));
  assert.equal(state.sessionId, sessionId);
  assert.equal(state.refreshToken, 'offline-fixture-new-refresh');
});
test('overlong token is refused but exact app session remains available for cleanup', () => {
  const state = {};
  rejectsSafe(() => adoptTokens(tokens({ exp: now + 301 }), state, jwks));
  assert.equal(state.sessionId, sessionId);
});
test('refresh session-identity change is rejected', () => {
  const state = makeState();
  rejectsSafe(() => adoptTokens(tokens({ sid: 'session_00000000000000000000000001' }), state, jwks));
  assert.equal(state.sessionId, sessionId);
});
test('device URL and user-code validation excludes arbitrary hosts and terminal control chars', () => {
  assert.deepEqual(validateDevice(deviceResponse), device);
  for (const change of [{ verification_uri: 'http://evil.example/device' },
    { user_code: 'ABCD-\u001b[1m' }, { expires_in: 99999 }, { interval: -1 }, { device_code: '' }]) {
    rejectsSafe(() => validateDevice({ ...deviceResponse, ...change }));
  }
});
test('device polling waits first, respects slow_down by 5 seconds and sends no client secret', async () => {
  const clock = fakeClock(); let i = 0;
  const sequence = [{ status: 400, data: { error: 'authorization_pending' } },
    { status: 400, data: { error: 'slow_down' } }, { status: 200, data: tokens() }];
  const output = await pollDevice(device, { ...clock, transport: async (path, body) => {
    assert.equal(path, '/user_management/authenticate');
    assert.deepEqual(Object.keys(body).sort(), ['client_id', 'device_code', 'grant_type']);
    return sequence[i++];
  } });
  assert.equal(output.refresh_token, 'offline-fixture-new-refresh');
  assert.deepEqual(clock.waits, [5000, 5000, 10000]);
});
test('denied, expired and lost device responses stop without starting a replacement flow', async () => {
  for (const error of ['access_denied', 'expired_token', 'unexpected']) {
    let calls = 0;
    await assert.rejects(pollDevice(device, { ...fakeClock(), transport: async () => {
      calls++; return { status: 400, data: { error, error_description: 'DO_NOT_PRINT_THIS' } };
    } }), e => e instanceof SafeError && !e.message.includes('DO_NOT_PRINT_THIS'));
    assert.equal(calls, 1);
  }
  await assert.rejects(pollDevice(device, { ...fakeClock(), transport: async () => { throw new Error('secret'); } }),
    e => e instanceof SafeError && !e.message.includes('secret'));
});
test('device timeout and cancellation make no unnecessary token request', async () => {
  let calls = 0;
  const transport = async () => { calls++; return { status: 400, data: { error: 'authorization_pending' } }; };
  await assert.rejects(pollDevice({ ...device, expiresIn: 5 }, { ...fakeClock(), transport }), SafeError);
  assert.equal(calls, 0);
  await assert.rejects(pollDevice(device, { ...fakeClock(), transport, cancelled: () => true }), SafeError);
  assert.equal(calls, 0);
});
test('refresh retries transient errors with same token, then returns success', async () => {
  let calls = 0;
  const clock = fakeClock();
  const answer = await refresh('offline-refresh', { ...clock, transport: async (path, form) => {
    assert.equal(form.refresh_token, 'offline-refresh');
    assert.deepEqual(Object.keys(form).sort(), ['client_id', 'grant_type', 'refresh_token']);
    calls++; return calls < 3 ? { status: 503, data: {} } : { status: 200, data: tokens() };
  } });
  assert.equal(answer.status, 200);
  assert.deepEqual(clock.waits, [1000, 2000]);
});
test('refresh invalid_grant is terminal and network retries stay within grace budget', async () => {
  let calls = 0;
  const answer = await refresh('offline-refresh', { ...fakeClock(), transport: async () => {
    calls++; return { status: 400, data: { error: 'invalid_grant' } };
  } });
  assert.equal(calls, 1); assert.equal(answer.status, 400);
  const clock = fakeClock();
  await assert.rejects(refresh('offline-refresh', { ...clock, transport: async () => { throw new Error('secret'); } }), SafeError);
  assert.ok(clock.now() < 24_000);
});
test('logout redirect is followed by latest refresh verification and never treated as proof alone', async () => {
  const paths = [];
  const result = await cleanUp(makeState(), jwks, { ...fakeClock(), transport: async (path, form) => {
    paths.push(path);
    if (!form) return { status: 302, data: {} };
    assert.equal(form.refresh_token, 'offline-fixture-refresh');
    return { status: 400, data: { error: 'invalid_grant' } };
  } });
  assert.equal(result.ended, true);
  assert.equal(paths.length, 2);
  assert.ok(paths[0].endsWith(sessionId));
});
test('successful refresh after logout is incomplete and keeps newest token for final logout', async () => {
  let logoutCalls = 0;
  const state = makeState();
  const result = await cleanUp(state, jwks, { ...fakeClock(), transport: async (path, form) => {
    if (!form) { logoutCalls++; return { status: 302, data: {} }; }
    return { status: 200, data: tokens() };
  } });
  assert.equal(result.ended, false);
  assert.equal(state.refreshToken, 'offline-fixture-new-refresh');
  assert.equal(logoutCalls, 2);
});
test('logout failure, generic HTTP errors and network uncertainty never report cleanup complete', async () => {
  for (const status of [200, 400, 401, 403, 404]) {
    const result = await cleanUp(makeState(), jwks, { ...fakeClock(), transport: async () => ({ status, data: {} }) });
    assert.equal(result.ended, false);
  }
  const result = await cleanUp(makeState(), jwks, { ...fakeClock(), transport: async () => { throw new Error('secret'); } });
  assert.equal(result.ended, false);
});
test('missing verified session ID does not send a cleanup request', async () => {
  const result = await cleanUp({}, jwks, { transport: async () => assert.fail('must not call') });
  assert.equal(result.ended, false);
});
test('transport refuses unexpected endpoints before any network call', async () => {
  await assert.rejects(request('https://evil.example'), SafeError);
  await assert.rejects(request('/user_management/sessions/logout?session_id=bad'), SafeError);
});

test('a possibly stale refresh cannot prove logout even if rejected', async () => {
  const state = makeState(); state.refreshCurrent = false;
  const result = await cleanUp(state, jwks, { ...fakeClock(), transport: async (path, form) =>
    form ? ({ status: 400, data: { error: 'invalid_grant' } }) : ({ status: 302, data: {} }) });
  assert.equal(result.ended, false);
});
test('ambiguous cleanup refresh followed by invalid_grant still requires fallback', async () => {
  let refreshCalls = 0;
  const result = await cleanUp(makeState(), jwks, { ...fakeClock(), transport: async (path, form) => {
    if (!form) return { status: 302, data: {} };
    if (++refreshCalls === 1) throw new Error('lost response');
    return { status: 400, data: { error: 'invalid_grant' } };
  } });
  assert.equal(result.ended, false);
});

test('incomplete token response preserves signed session ID for cleanup', () => {
  const state = {};
  rejectsSafe(() => adoptTokens({ access_token: token() }, state, jwks));
  assert.equal(state.sessionId, sessionId);
  assert.equal(state.refreshCurrent, false);
});
