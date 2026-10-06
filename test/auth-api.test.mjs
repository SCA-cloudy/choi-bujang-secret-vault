import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createAuthHandlers } from '../src/auth-api.mjs';

function fakeResponse() {
  return {
    statusCode: null, body: null, headers: {},
    setHeader(name, value) { this.headers[name] = value; },
    status(code) { this.statusCode = code; return this; },
    json(body) { this.body = body; return this; },
  };
}

const env = { SUPABASE_URL: 'https://example-project.supabase.co', SUPABASE_PUBLISHABLE_KEY: 'test-public-key' };
const upstreamSession = {
  access_token: 'access-1', refresh_token: 'refresh-1', expires_at: 1900000000,
  token_type: 'bearer', user: { id: 'u1', email: 'a@example.test', phone: '', app_metadata: { x: 1 } },
};

// 보낸 요청을 기록하고 정해 둔 답을 돌려주는 가짜 fetch.
function fakeFetch(status, data) {
  const calls = [];
  const impl = async (url, init) => {
    calls.push({ url: String(url), init });
    return new Response(JSON.stringify(data), { status, headers: { 'content-type': 'application/json' } });
  };
  return { impl, calls };
}

test('login: 서버가 키를 붙여 Supabase에 보내고 화면이 쓸 값만 돌려준다', async () => {
  const upstream = fakeFetch(200, upstreamSession);
  const { login } = createAuthHandlers({ env, fetchImpl: upstream.impl });
  const response = fakeResponse();
  await login({ method: 'POST', body: { email: ' a@example.test ', password: 'pw' } }, response);
  assert.equal(response.statusCode, 200);
  assert.deepEqual(response.body, {
    accessToken: 'access-1', refreshToken: 'refresh-1', expiresAt: 1900000000, email: 'a@example.test',
  });
  assert.equal(response.headers['Cache-Control'], 'no-store');
  assert.equal(upstream.calls.length, 1);
  assert.equal(upstream.calls[0].url, 'https://example-project.supabase.co/auth/v1/token?grant_type=password');
  assert.equal(upstream.calls[0].init.headers.apikey, 'test-public-key');
  assert.deepEqual(JSON.parse(upstream.calls[0].init.body), { email: 'a@example.test', password: 'pw' });
  assert.ok(!JSON.stringify(response.body).includes('app_metadata'));
});

test('login: POST만 받고, 잘못된 입력은 Supabase에 보내지 않는다', async () => {
  const upstream = fakeFetch(200, upstreamSession);
  const { login } = createAuthHandlers({ env, fetchImpl: upstream.impl });
  const get = fakeResponse();
  await login({ method: 'GET' }, get);
  assert.equal(get.statusCode, 405);
  for (const body of [undefined, {}, { email: 'a@b.c' }, { email: '', password: 'x' }, { email: 5, password: 'x' },
    { email: 'a@b.c', password: 'x'.repeat(201) }, 'not json', [1]]) {
    const response = fakeResponse();
    await login({ method: 'POST', body }, response);
    assert.equal(response.statusCode, 400);
    assert.equal(response.body.error, 'INVALID_LOGIN');
  }
  assert.equal(upstream.calls.length, 0);
});

test('login: 틀린 비밀번호·미인증·시도 과다·서버 오류를 구분하고 토큰을 내보내지 않는다', async () => {
  const cases = [
    [400, { error_code: 'invalid_credentials', msg: 'Invalid login credentials' }, 401, 'INVALID_CREDENTIALS'],
    [400, { error_code: 'email_not_confirmed' }, 401, 'EMAIL_NOT_CONFIRMED'],
    [429, { error_code: 'over_request_rate_limit' }, 429, 'TOO_MANY_ATTEMPTS'],
    [500, { msg: 'boom' }, 502, 'AUTH_UNAVAILABLE'],
    [200, { unexpected: true }, 502, 'AUTH_UNAVAILABLE'],
  ];
  for (const [status, data, expectedStatus, expectedError] of cases) {
    const { login } = createAuthHandlers({ env, fetchImpl: fakeFetch(status, data).impl });
    const response = fakeResponse();
    await login({ method: 'POST', body: { email: 'a@example.test', password: 'pw' } }, response);
    assert.equal(response.statusCode, expectedStatus);
    assert.deepEqual(response.body, { error: expectedError });
  }
});

test('login: 설정이 없거나 연결이 안 되면 502이고 비밀번호를 응답에 담지 않는다', async () => {
  const noKey = createAuthHandlers({ env: { SUPABASE_URL: env.SUPABASE_URL }, fetchImpl: fakeFetch(200, upstreamSession).impl });
  const response = fakeResponse();
  await noKey.login({ method: 'POST', body: { email: 'a@example.test', password: 'secret-pw' } }, response);
  assert.equal(response.statusCode, 502);
  const broken = createAuthHandlers({ env, fetchImpl: async () => { throw new Error('network secret-pw'); } });
  const failed = fakeResponse();
  await broken.login({ method: 'POST', body: { email: 'a@example.test', password: 'secret-pw' } }, failed);
  assert.equal(failed.statusCode, 502);
  assert.ok(!JSON.stringify(failed.body).includes('secret-pw'));
});

test('refresh: 새 출입증을 받고, 끝난 세션은 401로 알린다', async () => {
  const upstream = fakeFetch(200, upstreamSession);
  const handlers = createAuthHandlers({ env, fetchImpl: upstream.impl });
  const ok = fakeResponse();
  await handlers.refresh({ method: 'POST', body: { refreshToken: 'refresh-0' } }, ok);
  assert.equal(ok.statusCode, 200);
  assert.equal(ok.body.accessToken, 'access-1');
  assert.equal(upstream.calls[0].url, 'https://example-project.supabase.co/auth/v1/token?grant_type=refresh_token');
  assert.deepEqual(JSON.parse(upstream.calls[0].init.body), { refresh_token: 'refresh-0' });

  const bad = fakeResponse();
  await handlers.refresh({ method: 'POST', body: {} }, bad);
  assert.equal(bad.statusCode, 400);

  const expired = createAuthHandlers({ env, fetchImpl: fakeFetch(400, { error_code: 'refresh_token_not_found' }).impl });
  const gone = fakeResponse();
  await expired.refresh({ method: 'POST', body: { refreshToken: 'old' } }, gone);
  assert.equal(gone.statusCode, 401);
  assert.deepEqual(gone.body, { error: 'SESSION_EXPIRED' });
});

test('logout: 출입증이 있어야 하고, 이 기기 세션만 끝낸다', async () => {
  const upstream = fakeFetch(204, null);
  const handlers = createAuthHandlers({ env, fetchImpl: async (url, init) => {
    upstream.calls.push({ url: String(url), init });
    return new Response(null, { status: 204 });
  } });
  const none = fakeResponse();
  await handlers.logout({ method: 'POST', headers: {} }, none);
  assert.equal(none.statusCode, 401);
  assert.equal(upstream.calls.length, 0);

  const ok = fakeResponse();
  await handlers.logout({ method: 'POST', headers: { authorization: 'Bearer access-1' } }, ok);
  assert.equal(ok.statusCode, 200);
  assert.deepEqual(ok.body, { ok: true });
  assert.equal(upstream.calls[0].url, 'https://example-project.supabase.co/auth/v1/logout?scope=local');
  assert.equal(upstream.calls[0].init.headers.Authorization, 'Bearer access-1');
  assert.equal(upstream.calls[0].init.headers.apikey, 'test-public-key');

  const stale = createAuthHandlers({ env, fetchImpl: fakeFetch(401, { error_code: 'bad_jwt' }).impl });
  const already = fakeResponse();
  await stale.logout({ method: 'POST', headers: { authorization: 'Bearer old' } }, already);
  assert.equal(already.statusCode, 200);
});
