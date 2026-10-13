import assert from 'node:assert/strict';
import { test } from 'node:test';
import { randomUUID } from 'node:crypto';
import { fixtureRequests } from '../scripts/fixture-7.mjs';
import { decide, RULE_IDS } from '../src/decider.mjs';
import { resourceIdOf } from '../src/resources.mjs';

const { normal } = fixtureRequests();
const ask = (change) => decide({ ...normal, requestId: randomUUID(), ...change });
const ID = '11111111-2222-4333-8444-555555555555';

test('자기 메모 구역: 목록 읽기·한 건 읽기·수정은 허용', async () => {
  for (const [method, route, path] of [['GET', 'GET /notes', '/notes'], ['GET', 'GET /notes/:id', `/notes/${ID}`], ['PUT', 'PUT /notes/:id', `/notes/${ID}`]]) {
    const answer = await ask({ method, route, path });
    assert.equal(answer.decision, 'allow', route);
    assert.deepEqual(answer.ruleIds, ['device_registered', 'resource_zone']);
  }
});

test('공개 주소 표기(/api/notes...)도 같은 구역으로 본다', async () => {
  assert.equal((await ask({ method: 'GET', route: 'GET /api/notes/:id', path: `/api/notes/${ID}` })).decision, 'allow');
  assert.equal((await ask({ method: 'PUT', route: 'PUT /api/notes/:id', path: `/api/notes/${ID}` })).decision, 'allow');
});

test('강사 공지 수정(일반 학생)은 거부하고, 공지 읽기도 이번 규칙은 열지 않는다', async () => {
  for (const [method, route, path] of [['PUT', 'PUT /notices/:id', `/notices/${ID}`], ['GET', 'GET /notices', '/notices'], ['GET', 'GET /notices/:id', `/notices/${ID}`]]) {
    const answer = await ask({ method, route, path });
    assert.equal(answer.decision, 'deny', route);
    assert.deepEqual(answer.ruleIds, ['resource_zone']);
  }
});

test('이번 규칙이 열지 않는 동작과 알 수 없는 경로는 모두 거부', async () => {
  const cases = [
    { method: 'POST', route: 'POST /notes', path: '/notes' },
    { method: 'DELETE', route: 'DELETE /notes/:id', path: `/notes/${ID}` },
    { method: 'GET', route: 'GET /admin', path: '/admin' },
    { method: 'GET', route: 'GET /notes/:id/export', path: `/notes/${ID}/export` },
    { method: 'GET', route: 'GET /notes/:id', path: '/notes/export' },
    { method: 'GET', route: 'GET /notes/:id', path: '/notes/Export' },
    { method: 'GET', route: 'GET /notes/:id', path: '/notes/search' },
    { method: 'GET', route: 'GET /notes/:id', path: `/notes/${ID}/extra` },
    { method: 'GET', route: 'GET /notes/:id', path: '/notes/' },
    { method: 'GET', route: 'GET /notes/:id', path: '/notes/..%2fnotices' },
    { method: 'GET', route: 'GET /notes/:id', path: `/notices/${ID}` },
    { method: 'GET', route: 'GET /notes', path: `/notes/${ID}` },
    { method: 'PUT', route: 'GET /notes/:id', path: `/notes/${ID}` },
    { method: 'get', route: 'get /notes', path: '/notes' },
    { method: 'GET', route: 'toString', path: '/notes' },
    { method: 'GET', route: '__proto__', path: '/notes' },
    { method: 'GET', route: undefined, path: '/notes' },
    { method: 'GET', route: 'GET /notes', path: undefined },
    { method: undefined, route: 'GET /notes', path: '/notes' },
  ];
  for (const item of cases) {
    const answer = await ask(item);
    assert.equal(answer.decision, 'deny', JSON.stringify(item));
    assert.deepEqual(answer.ruleIds, ['resource_zone']);
    assert.deepEqual(Object.keys(answer).sort(), ['decision', 'reasonCode', 'requestId', 'ruleIds', 'schema']);
  }
});

test('쿼리 정보와 요청에 덧붙은 role·owner 같은 이름은 구역 판단을 바꾸지 않는다', async () => {
  const base = { method: 'PUT', route: 'PUT /notices/:id', path: `/notices/${ID}` };
  for (const extra of [{ queryLength: 12 }, { querySha256: 'f'.repeat(64) }, { role: 'instructor' }, { identity: { role: 'instructor' } }, { owner: 'someone' }]) {
    assert.equal((await ask({ ...base, ...extra })).decision, 'deny', JSON.stringify(extra));
  }
  const own = { method: 'GET', route: 'GET /notes/:id', path: `/notes/${ID}` };
  assert.equal((await ask({ ...own, queryLength: 40, querySha256: 'a'.repeat(64) })).decision, 'allow');
});

test('이전 규칙은 그대로: 미등록 기기는 구역보다 먼저 거부, 복합 이상은 추가 확인', async () => {
  const unregistered = await ask({ deviceRegistered: false, method: 'GET', route: 'GET /notes', path: '/notes' });
  assert.deepEqual([unregistered.decision, unregistered.reasonCode, unregistered.ruleIds], ['deny', 'device_not_registered', ['device_registered']]);
  const { suspicious } = fixtureRequests();
  assert.equal((await decide(suspicious)).decision, 'step_up');
  assert.equal((await decide({ ...suspicious, route: 'PUT /notices/:id', method: 'PUT', path: `/notices/${ID}` })).decision, 'deny');
});

test('RULE_IDS에는 구현한 세 규칙만 있고, 판정기의 구역 표는 resources.mjs와 같은 자원 ID를 준다', async () => {
  assert.deepEqual([...RULE_IDS], ['device_registered', 'step_up_required', 'resource_zone']);
  for (const route of ['GET /notes', 'POST /notes', 'GET /notes/:id', 'PUT /notes/:id', 'DELETE /notes/:id', 'GET /notices', 'GET /notices/:id', 'PUT /notices/:id']) {
    const [method, path] = route.split(' ');
    const allowedHere = resourceIdOf(route) === 'note.own' && ['GET /notes', 'GET /notes/:id', 'PUT /notes/:id'].includes(route);
    const answer = await ask({ method, route, path: path.replace(':id', ID) });
    assert.equal(answer.decision === 'allow', allowedHere, route);
  }
});
