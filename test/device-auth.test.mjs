// 11단계 제작 2: 기기 승인과 요청 서명 시험. 브라우저와 같은 WebCrypto(ECDSA P-256, 꺼낼 수 없는 키)로 실제 서명한다.
import assert from 'node:assert/strict';
import { createHash, webcrypto } from 'node:crypto';
import { test } from 'node:test';
import { canonicalRequest, deviceIdOf } from '../src/device-auth.mjs';
import { createDeviceHandlers } from '../src/device-api.mjs';
import { createNotesHandlers } from '../src/notes-api.mjs';
import { createRestoreHandler } from '../src/notes-restore.mjs';

const { subtle } = webcrypto;
const A = '11111111-1111-4111-8111-111111111111';
const B = '22222222-2222-4222-8222-222222222222';
const NOTE = '33333333-3333-4333-8333-333333333333';
const OTHER = '44444444-4444-4444-8444-444444444444';
const TOKENS = { 'Bearer a.a.a': { kind: 'student', userId: A }, 'Bearer b.b.b': { kind: 'student', userId: B } };
const NOW = 1_800_000_000_000;

async function makeDevice() {
  const pair = await subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign', 'verify']);
  const { kty, crv, x, y } = await subtle.exportKey('jwk', pair.publicKey);
  const publicKey = { kty, crv, x, y };
  return { privateKey: pair.privateKey, publicKey, deviceId: deviceIdOf(publicKey) };
}
const sha = text => createHash('sha256').update(text, 'utf8').digest('hex');
async function sign(device, { method, path, body = '', time = NOW }) {
  const message = canonicalRequest({ method, path, timestamp: time, bodySha256: sha(body) });
  const signature = await subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, device.privateKey, new TextEncoder().encode(message));
  return { 'x-device-id': device.deviceId, 'x-device-time': String(time), 'x-device-signature': Buffer.from(signature).toString('base64url') };
}

function memoryStore() {
  const rows = new Map([[NOTE, { id: NOTE, owner_id: B, title: 'B 메모', content: 'B 내용' }]]);
  const devices = new Map();
  return {
    rows, devices,
    async list(ownerId) { return [...rows.values()].filter(row => row.owner_id === ownerId); },
    async get(id, ownerId) { const row = rows.get(id); return row?.owner_id === ownerId ? row : null; },
    async peek(id) { const row = rows.get(id); return row ? { id, owner_id: row.owner_id } : null; },
    async create({ id, ownerId, title, content }) { if (rows.has(id)) return { conflict: true }; rows.set(id, { id, owner_id: ownerId, title, content }); return {}; },
    async update(id, ownerId, fields) { const row = rows.get(id); if (row?.owner_id !== ownerId) return null; Object.assign(row, fields); return row; },
    async remove(id, ownerId) { const row = rows.get(id); if (row?.owner_id !== ownerId) return null; rows.delete(id); return { id }; },
    async saveBackup() { return {}; },
    async getBackup() { return null; },
    async getDevice(id) { return devices.get(id) ?? null; },
    async addDevice({ deviceId, ownerId, publicKey, label }) { devices.set(deviceId, { device_id: deviceId, owner_id: ownerId, public_key: publicKey, label, status: 'pending' }); return {}; },
  };
}

function build() {
  const store = memoryStore();
  const verifyAuthorization = async header => TOKENS[header] ?? null;
  const now = () => NOW;
  return {
    store,
    device: createDeviceHandlers({ verifyAuthorization, store, now }),
    notes: createNotesHandlers({ verifyAuthorization, store, now }), // 기본 기기 확인(실제 서명 확인)을 그대로 쓴다
    restore: createRestoreHandler({ verifyAuthorization, store, now }),
  };
}

// Vercel처럼 본문은 이미 JSON으로 풀린 객체로 들어온다고 가정한다.
async function call(fn, { method = 'GET', url, token = 'Bearer b.b.b', headers = {}, body, query } = {}) {
  const response = {
    statusCode: null, body: null, headers: {},
    setHeader(name, value) { this.headers[name] = value; }, status(code) { this.statusCode = code; return this; }, json(value) { this.body = value; return this; },
  };
  const lines = [];
  const quiet = console.error; console.error = (...args) => lines.push(args.join(' '));
  try {
    await fn({ method, url, headers: { ...(token ? { authorization: token } : {}), ...headers }, body, query }, response);
  } finally { console.error = quiet; }
  response.logs = lines.join('\n');
  return response;
}

async function requestApproval(ctx, device, token = 'Bearer b.b.b') {
  const body = { publicKey: device.publicKey, label: '시험 기기' };
  return call(ctx.device.requestApproval, { method: 'POST', url: '/api/device/request', token, body,
    headers: await sign(device, { method: 'POST', path: '/api/device/request', body: JSON.stringify(body) }) });
}
const approve = (ctx, device) => { ctx.store.devices.get(device.deviceId).status = 'approved'; }; // SQL Editor에서 학생이 하는 승인

test('승인 요청: 로그인과 키 소유 서명이 있어야 "승인 대기"로만 등록되고, 그것만으로는 권한이 생기지 않는다', async () => {
  const ctx = build();
  const device = await makeDevice();
  assert.equal((await call(ctx.device.requestApproval, { method: 'POST', url: '/api/device/request', token: null, body: { publicKey: device.publicKey } })).statusCode, 401);
  const unsigned = await call(ctx.device.requestApproval, { method: 'POST', url: '/api/device/request', body: { publicKey: device.publicKey } });
  assert.deepEqual([unsigned.statusCode, unsigned.body], [403, { error: 'DEVICE_SIGNATURE_REQUIRED' }]);
  const withPrivate = await call(ctx.device.requestApproval, { method: 'POST', url: '/api/device/request', body: { publicKey: { ...device.publicKey, d: 'x'.repeat(43) } } });
  assert.equal(withPrivate.statusCode, 400); // 개인키를 보내면 거부
  const other = await makeDevice(); // 남의 키로 서명한 요청은 키 소유 증명이 안 된다
  const forged = await call(ctx.device.requestApproval, { method: 'POST', url: '/api/device/request', body: { publicKey: device.publicKey },
    headers: { ...(await sign(other, { method: 'POST', path: '/api/device/request', body: JSON.stringify({ publicKey: device.publicKey }) })), 'x-device-id': device.deviceId } });
  assert.equal(forged.statusCode, 403);
  assert.equal(ctx.store.devices.size, 0);

  const first = await requestApproval(ctx, device);
  assert.deepEqual([first.statusCode, first.body], [201, { deviceId: device.deviceId, status: 'pending' }]);
  assert.equal(ctx.store.devices.get(device.deviceId).status, 'pending');
  assert.equal((await requestApproval(ctx, device)).statusCode, 200); // 다시 요청해도 같은 대기 상태
  assert.equal((await requestApproval(ctx, device, 'Bearer a.a.a')).statusCode, 409); // 남이 같은 기기를 자기 것으로 등록할 수 없다

  // 승인 대기 기기로는 자료를 볼 수 없다
  const list = await call(ctx.notes.collection, { url: '/api/notes', headers: await sign(device, { method: 'GET', path: '/api/notes' }) });
  assert.deepEqual([list.statusCode, list.body], [403, { error: 'DEVICE_NOT_APPROVED' }]);
});

test('상태 확인: 서명한 요청으로 승인 대기·승인 상태만 알려 주고, 서명 없으면 403', async () => {
  const ctx = build();
  const device = await makeDevice();
  await requestApproval(ctx, device);
  const pending = await call(ctx.device.status, { url: '/api/device/status', headers: await sign(device, { method: 'GET', path: '/api/device/status' }) });
  assert.deepEqual([pending.statusCode, pending.body], [200, { deviceId: device.deviceId, status: 'pending' }]);
  approve(ctx, device);
  const approved = await call(ctx.device.status, { url: '/api/device/status', headers: await sign(device, { method: 'GET', path: '/api/device/status' }) });
  assert.equal(approved.body.status, 'approved');
  assert.equal((await call(ctx.device.status, { url: '/api/device/status' })).statusCode, 403);
  assert.equal((await call(ctx.device.status, { url: '/api/device/status', token: null })).statusCode, 401);
});

test('승인된 기기의 서명한 요청만 자료실이 열리고, 기존 메모 기능(목록·추가·수정·삭제·복구 경로)은 그대로 동작한다', async () => {
  const ctx = build();
  const device = await makeDevice();
  await requestApproval(ctx, device);
  approve(ctx, device);
  const list = await call(ctx.notes.collection, { url: '/api/notes', headers: await sign(device, { method: 'GET', path: '/api/notes' }) });
  assert.equal(list.statusCode, 200);
  assert.deepEqual(list.body.map(note => note.id), [NOTE]);
  const created = { id: OTHER, title: '새 메모', body: '새 내용' };
  const add = await call(ctx.notes.collection, { method: 'POST', url: '/api/notes', body: created,
    headers: await sign(device, { method: 'POST', path: '/api/notes', body: JSON.stringify(created) }) });
  assert.equal(add.statusCode, 201);
  const edit = { title: '고친 제목', body: '고친 내용' };
  const put = await call(ctx.notes.item, { method: 'PUT', url: `/api/notes/${NOTE}`, query: { id: NOTE }, body: edit,
    headers: await sign(device, { method: 'PUT', path: `/api/notes/${NOTE}`, body: JSON.stringify(edit) }) });
  assert.equal(put.statusCode, 200);
  const del = await call(ctx.notes.item, { method: 'DELETE', url: `/api/notes/${OTHER}`, query: { id: OTHER },
    headers: await sign(device, { method: 'DELETE', path: `/api/notes/${OTHER}` }) });
  assert.equal(del.statusCode, 200);
  const restore = await call(ctx.restore, { method: 'POST', url: '/api/restore', body: { id: NOTE },
    headers: await sign(device, { method: 'POST', path: '/api/restore', body: JSON.stringify({ id: NOTE }) }) });
  assert.equal(restore.statusCode, 404); // 기기 확인은 통과했고, 이 시험 저장소에는 사본이 없어서 복구 경로가 404로 멈춤
});

test('괴물 1: 서명 없이 보낸 보호 요청은 메모·복구 모두 403이고 자료를 주지 않는다', async () => {
  const ctx = build();
  for (const [fn, options] of [
    [ctx.notes.collection, { url: '/api/notes' }],
    [ctx.notes.item, { url: `/api/notes/${NOTE}`, query: { id: NOTE } }],
    [ctx.notes.item, { method: 'DELETE', url: `/api/notes/${NOTE}`, query: { id: NOTE } }],
    [ctx.restore, { method: 'POST', url: '/api/restore', body: { id: NOTE } }],
  ]) {
    const result = await call(fn, options);
    assert.deepEqual([result.statusCode, result.body], [403, { error: 'DEVICE_SIGNATURE_REQUIRED' }]);
  }
  assert.ok(ctx.store.rows.has(NOTE)); // 지워지지 않음
});

test('괴물 2: 서명한 뒤 요청 경로를 바꾸면(다른 메모 번호, 쿼리로 다른 id 끼워 넣기) 403', async () => {
  const ctx = build();
  const device = await makeDevice();
  await requestApproval(ctx, device);
  approve(ctx, device);
  const signedFor = await sign(device, { method: 'DELETE', path: `/api/notes/${OTHER}` });
  const moved = await call(ctx.notes.item, { method: 'DELETE', url: `/api/notes/${NOTE}`, query: { id: NOTE }, headers: signedFor });
  assert.deepEqual([moved.statusCode, moved.body], [403, { error: 'DEVICE_SIGNATURE_INVALID' }]);
  const listSigned = await sign(device, { method: 'GET', path: '/api/notes' });
  const toItem = await call(ctx.notes.item, { url: `/api/notes/${NOTE}`, query: { id: NOTE }, headers: listSigned });
  assert.equal(toItem.statusCode, 403);
  const signedNote = await sign(device, { method: 'DELETE', path: `/api/notes/${OTHER}` });
  const smuggled = await call(ctx.notes.item, { method: 'DELETE', url: `/api/notes/${OTHER}?id=${NOTE}`, query: { id: NOTE }, headers: signedNote });
  assert.equal(smuggled.statusCode, 403);
  const methodChanged = await call(ctx.notes.item, { method: 'DELETE', url: `/api/notes/${NOTE}`, query: { id: NOTE }, headers: await sign(device, { method: 'GET', path: `/api/notes/${NOTE}` }) });
  assert.equal(methodChanged.statusCode, 403);
  assert.ok(ctx.store.rows.has(NOTE));
});

test('괴물 3: 서명한 뒤 수정 본문을 바꾸면 403이고 메모가 바뀌지 않는다', async () => {
  const ctx = build();
  const device = await makeDevice();
  await requestApproval(ctx, device);
  approve(ctx, device);
  const signedBody = { title: '원래 고치려던 제목', body: '원래 내용' };
  const headers = await sign(device, { method: 'PUT', path: `/api/notes/${NOTE}`, body: JSON.stringify(signedBody) });
  const tampered = await call(ctx.notes.item, { method: 'PUT', url: `/api/notes/${NOTE}`, query: { id: NOTE }, headers, body: { title: '바뀐 제목', body: '공격자가 바꾼 내용' } });
  assert.deepEqual([tampered.statusCode, tampered.body], [403, { error: 'DEVICE_SIGNATURE_INVALID' }]);
  assert.equal(ctx.store.rows.get(NOTE).content, 'B 내용');
  const addSigned = { id: OTHER, title: 't', body: 'b' };
  const addTampered = await call(ctx.notes.collection, { method: 'POST', url: '/api/notes', body: { ...addSigned, body: 'changed' },
    headers: await sign(device, { method: 'POST', path: '/api/notes', body: JSON.stringify(addSigned) }) });
  assert.equal(addTampered.statusCode, 403);
  assert.ok(!ctx.store.rows.has(OTHER));
});

test('그 밖의 거부: 오래된 서명, 남의 기기, 취소된 기기, 모양이 틀린 헤더는 403이고 서버 기록에 기기 정보가 남지 않는다', async () => {
  const ctx = build();
  const device = await makeDevice();
  await requestApproval(ctx, device);
  approve(ctx, device);
  const old = await call(ctx.notes.collection, { url: '/api/notes', headers: await sign(device, { method: 'GET', path: '/api/notes', time: NOW - 3 * 60 * 1000 }) });
  assert.equal(old.statusCode, 403);
  const asA = await call(ctx.notes.collection, { url: '/api/notes', token: 'Bearer a.a.a', headers: await sign(device, { method: 'GET', path: '/api/notes' }) });
  assert.deepEqual([asA.statusCode, asA.body], [403, { error: 'DEVICE_NOT_REGISTERED' }]);
  const bad = await call(ctx.notes.collection, { url: '/api/notes', headers: { 'x-device-id': 'zz', 'x-device-time': '1', 'x-device-signature': 'x' } });
  assert.equal(bad.statusCode, 403);
  ctx.store.devices.get(device.deviceId).status = 'revoked';
  const revoked = await call(ctx.notes.collection, { url: '/api/notes', headers: await sign(device, { method: 'GET', path: '/api/notes' }) });
  assert.equal(revoked.statusCode, 403);
  for (const text of [old.logs, asA.logs, revoked.logs]) {
    assert.match(text, /device: 거부 사유=/);
    for (const secret of [device.deviceId, device.publicKey.x, A, B]) assert.ok(!text.includes(secret), secret);
  }
});
