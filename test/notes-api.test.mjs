import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createNotesHandler } from '../api/notes.js';

function fakeResponse() {
  return {
    statusCode: null, body: null, headers: {},
    setHeader(name, value) { this.headers[name] = value; },
    status(code) { this.statusCode = code; return this; },
    json(body) { this.body = body; return this; },
  };
}

const NOTES = [{ title: 'a', content: 'b' }];
const A_LOGIN = Object.freeze({ kind: 'student', userId: '11111111-1111-4111-8111-111111111111' });

function build(verify, read = async () => NOTES) {
  const calls = { read: 0, auth: [] };
  const handler = createNotesHandler({
    verifyAuthorization: async authorization => { calls.auth.push(authorization); return verify(authorization); },
    readNotes: async () => { calls.read += 1; return read(); },
  });
  return { handler, calls };
}

test('로그인 없는 요청은 401과 JSON 오류로 거부하고 자료를 읽지 않는다', async () => {
  const { handler, calls } = build(() => null);
  const response = fakeResponse();
  await handler({ method: 'GET', headers: {} }, response);
  assert.equal(response.statusCode, 401);
  assert.deepEqual(response.body, { error: 'LOGIN_REQUIRED' });
  assert.equal(calls.read, 0);
  assert.equal(response.headers['Cache-Control'], 'no-store');
});

test('검사에 실패한 토큰(위조·만료·다른 서비스용)도 401이다', async () => {
  const { handler, calls } = build(() => null);
  const response = fakeResponse();
  await handler({ method: 'GET', headers: { authorization: 'Bearer aaa.bbb.ccc' } }, response);
  assert.equal(response.statusCode, 401);
  assert.equal(calls.read, 0);
  assert.deepEqual(calls.auth, ['Bearer aaa.bbb.ccc']);
});

test('검사 도중 예외가 나도 열어 주지 않고 401이다', async () => {
  const { handler, calls } = build(() => { throw new Error('boom'); });
  const response = fakeResponse();
  await handler({ method: 'GET', headers: { authorization: 'Bearer aaa.bbb.ccc' } }, response);
  assert.equal(response.statusCode, 401);
  assert.equal(calls.read, 0);
});

test('브라우저가 보낸 userId·role 값은 믿지 않는다', async () => {
  const { handler, calls } = build(() => null);
  const response = fakeResponse();
  await handler({
    method: 'GET',
    headers: { 'x-user-id': A_LOGIN.userId, 'x-role': 'admin' },
    query: { userId: A_LOGIN.userId, role: 'admin' },
  }, response);
  assert.equal(response.statusCode, 401);
  assert.equal(calls.read, 0);
});

test('정상 로그인은 200과 메모 배열을 받는다', async () => {
  const { handler, calls } = build(() => A_LOGIN);
  const response = fakeResponse();
  await handler({ method: 'GET', headers: { authorization: 'Bearer aaa.bbb.ccc' } }, response);
  assert.equal(response.statusCode, 200);
  assert.deepEqual(response.body, { notes: NOTES });
  assert.equal(calls.read, 1);
});

test('GET이 아닌 요청은 로그인 검사 전에 405이다', async () => {
  const { handler, calls } = build(() => A_LOGIN);
  const response = fakeResponse();
  await handler({ method: 'POST', headers: { authorization: 'Bearer aaa.bbb.ccc' } }, response);
  assert.equal(response.statusCode, 405);
  assert.equal(calls.read, 0);
  assert.equal(calls.auth.length, 0);
});

test('자료 읽기에 실패하면 500이고 오류 내용을 응답에 담지 않는다', async () => {
  const { handler } = build(() => A_LOGIN, async () => { throw new Error('read_failed:SECRET-DETAIL'); });
  const response = fakeResponse();
  const original = console.error;
  console.error = () => {};
  try {
    await handler({ method: 'GET', headers: { authorization: 'Bearer aaa.bbb.ccc' } }, response);
  } finally {
    console.error = original;
  }
  assert.equal(response.statusCode, 500);
  assert.deepEqual(response.body, { error: 'NOTES_UNAVAILABLE' });
  assert.ok(!JSON.stringify(response.body).includes('SECRET-DETAIL'));
});
