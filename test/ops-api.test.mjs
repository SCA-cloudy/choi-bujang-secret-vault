// 12단계 제작 1: 탈환 작전실 요약(GET /api/ops) 시험. 실제 기기 키(WebCrypto ECDSA P-256)로 서명한다.
import assert from 'node:assert/strict';
import { createHash, webcrypto } from 'node:crypto';
import { test } from 'node:test';
import { canonicalRequest, deviceIdOf } from '../src/device-auth.mjs';
import { noteContentSha256 } from '../src/note-backup.mjs';
import { createOpsHandler, mask } from '../src/ops-api.mjs';

const { subtle } = webcrypto;
const B = '22222222-2222-4222-8222-222222222222';
const A = '11111111-1111-4111-8111-111111111111';
const NOW = Date.now();
const NOTE1 = '33333333-3333-4333-8333-333333333333';
const NOTE2 = '44444444-4444-4444-8444-444444444444';

async function makeDevice() {
  const pair = await subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign', 'verify']);
  const { kty, crv, x, y } = await subtle.exportKey('jwk', pair.publicKey);
  const publicKey = { kty, crv, x, y };
  return { privateKey: pair.privateKey, publicKey, deviceId: deviceIdOf(publicKey) };
}
const sha = text => createHash('sha256').update(text, 'utf8').digest('hex');
async function sign(device, path = '/api/ops') {
  const message = canonicalRequest({ method: 'GET', path, timestamp: NOW, bodySha256: sha('') });
  const signature = await subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, device.privateKey, new TextEncoder().encode(message));
  return { 'x-device-id': device.deviceId, 'x-device-time': String(NOW), 'x-device-signature': Buffer.from(signature).toString('base64url') };
}

function memoryStore(device, { status = 'approved', failDevices = false } = {}) {
  const devices = new Map([[device.deviceId, { device_id: device.deviceId, owner_id: B, public_key: device.publicKey, status }]]);
  devices.set('aaaaaaaaaaaaaaaa', { device_id: 'aaaaaaaaaaaaaaaa', owner_id: B, public_key: device.publicKey, status: 'pending' });
  devices.set('bbbbbbbbbbbbbbbb', { device_id: 'bbbbbbbbbbbbbbbb', owner_id: B, public_key: device.publicKey, status: 'revoked' });
  devices.set('cccccccccccccccc', { device_id: 'cccccccccccccccc', owner_id: A, public_key: device.publicKey, status: 'approved' }); // 남의 기기
  const backups = [
    { id: NOTE1, owner_id: B, title: '비밀 제목 SECRET_TITLE', content: '비밀 본문 SECRET_BODY', content_sha256: noteContentSha256('비밀 제목 SECRET_TITLE', '비밀 본문 SECRET_BODY') },
    { id: NOTE2, owner_id: B, title: '변조된 사본', content: 'TAMPERED_BODY', content_sha256: 'f'.repeat(64) },
  ];
  return {
    async getDevice(id) { return devices.get(id) ?? null; },
    async listDevices(ownerId) {
      if (failDevices) throw new Error('db_failed:x');
      return [...devices.values()].filter(row => row.owner_id === ownerId).map(({ device_id, status: st }) => ({ device_id, status: st }));
    },
    async listBackups(ownerId) { return backups.filter(row => row.owner_id === ownerId); },
  };
}

async function call(handler, { token = 'Bearer b.b.b', headers = {}, method = 'GET', url = '/api/ops' } = {}) {
  const response = {
    statusCode: null, body: null, headers: {},
    setHeader(name, value) { this.headers[name] = value; }, status(code) { this.statusCode = code; return this; }, json(value) { this.body = value; return this; },
  };
  const lines = [];
  const quiet = console.error; console.error = (...args) => lines.push(args.join(' '));
  try { await handler({ method, url, headers: { ...(token ? { authorization: token } : {}), ...headers } }, response); } finally { console.error = quiet; }
  response.logs = lines.join('\n');
  return response;
}
const build = (store, now = () => NOW) => createOpsHandler({ verifyAuthorization: async h => (h === 'Bearer b.b.b' ? { kind: 'student', userId: B } : null), store, now });

test('작전실은 로그인과 승인된 기기의 서명이 있어야 열린다', async () => {
  const device = await makeDevice();
  const handler = build(memoryStore(device));
  assert.equal((await call(handler, { token: null })).statusCode, 401);
  const unsigned = await call(handler);
  assert.deepEqual([unsigned.statusCode, unsigned.body], [403, { error: 'DEVICE_SIGNATURE_REQUIRED' }]);
  const pending = await call(build(memoryStore(device, { status: 'pending' })), { headers: await sign(device) });
  assert.deepEqual([pending.statusCode, pending.body], [403, { error: 'DEVICE_NOT_APPROVED' }]);
  const moved = await call(handler, { headers: await sign(device, '/api/notes') }); // 다른 경로용 서명
  assert.equal(moved.statusCode, 403);
  assert.equal((await call(handler, { method: 'POST', headers: await sign(device) })).statusCode, 405);
});

test('작전실 요약: 네 칸의 값과 출처, 가린 기록이 서로 맞고, 메모 제목·본문은 없다', async () => {
  const device = await makeDevice();
  const result = await call(build(memoryStore(device)), { headers: await sign(device) });
  assert.equal(result.statusCode, 200);
  const body = result.body;
  assert.equal(body.schema, 'aleph.ops.v1');
  assert.match(body.requestId, /^[0-9a-f-]{36}$/u);
  // 판정기: 지금 실행한 가상 요청 4건
  assert.equal(body.decider.source, 'live_virtual');
  assert.deepEqual(body.decider.ruleIds, ['device_registered', 'step_up_required', 'resource_zone']);
  assert.deepEqual(body.decider.probes.map(p => [p.expected, p.decision]), [['allow', 'allow'], ['deny', 'deny'], ['step_up', 'step_up'], ['deny', 'deny']]);
  // 탐지: 가상 사건은 실행, 실제 접속 사건은 미실행
  assert.equal(body.detection.source, 'live_virtual');
  assert.deepEqual(body.detection.probes.map(p => [p.count, p.action, p.reasonCode]), [[30, 'observe', null], [121, 'propose_revocation', 'burst_read']]);
  assert.equal(body.detection.liveEvents.source, 'not_run');
  // 회수 상태: 내 기기 3개만(남의 기기 제외), 개수와 가린 기록이 맞음
  assert.equal(body.revocation.source, 'live_db');
  assert.deepEqual(body.revocation.counts, { approved: 1, pending: 1, revoked: 1 });
  assert.equal(body.revocation.total, body.revocation.records.length);
  for (const status of ['approved', 'pending', 'revoked']) {
    assert.equal(body.revocation.records.filter(r => r.status === status).length, body.revocation.counts[status]);
  }
  assert.ok(body.revocation.records.every(r => /^[0-9a-f]{4}…[0-9a-f]{4}$/u.test(r.device)));
  assert.ok(body.revocation.records.some(r => r.device === mask(device.deviceId)));
  // 복구 버전: 정책 사본·복원 훈련 기록은 파일, 사본은 DB. 틀린 사본 개수와 기록이 맞음
  assert.deepEqual([body.recovery.policy.source, body.recovery.policy.version, body.recovery.policy.sha256Prefix], ['live_file', 'safe-9', '2756f683cac9']);
  assert.equal(body.recovery.drill.source, 'live_file');
  assert.ok(body.recovery.drill.runs >= 1 && body.recovery.drill.lastOk === true);
  assert.deepEqual([body.recovery.backups.source, body.recovery.backups.count, body.recovery.backups.invalid], ['live_db', 2, 1]);
  assert.equal(body.recovery.backups.records.filter(r => !r.verified).length, body.recovery.backups.invalid);
  assert.deepEqual(body.recovery.backups.records.map(r => r.note), [mask(NOTE1), mask(NOTE2)]);
  // 메모 제목·본문, 전체 번호, 사용자 번호는 응답과 서버 기록 어디에도 없다
  const text = JSON.stringify(body) + result.logs;
  for (const secret of ['SECRET_TITLE', 'SECRET_BODY', 'TAMPERED_BODY', '변조된 사본', NOTE1, NOTE2, device.deviceId, B, A]) assert.ok(!text.includes(secret), secret);
  assert.equal(result.headers['Cache-Control'], 'no-store');
});

test('DB를 읽지 못한 칸은 unavailable로 표시하고 다른 칸은 그대로 보인다', async () => {
  const device = await makeDevice();
  const result = await call(build(memoryStore(device, { failDevices: true })), { headers: await sign(device) });
  assert.equal(result.statusCode, 200);
  assert.deepEqual(result.body.revocation, { source: 'unavailable', reason: 'DEVICES_UNAVAILABLE' });
  assert.equal(result.body.recovery.backups.source, 'live_db');
  assert.match(result.logs, /DEVICES_UNAVAILABLE/u);
});
