import assert from 'node:assert/strict';
import { test } from 'node:test';
import { RESOURCE_IDS, resourceIdOf } from '../src/resources.mjs';

test('메모 경로는 note.own, 강사 공지 경로는 notice.instructor로 서로 다른 자원 ID를 받는다', () => {
  assert.notEqual(RESOURCE_IDS.ownNote, RESOURCE_IDS.instructorNotice);
  for (const route of ['GET /notes', 'POST /notes', 'GET /notes/:id', 'PUT /notes/:id', 'DELETE /notes/:id']) {
    assert.equal(resourceIdOf(route), 'note.own');
  }
  for (const route of ['GET /notices', 'GET /notices/:id', 'PUT /notices/:id']) {
    assert.equal(resourceIdOf(route), 'notice.instructor');
  }
});

test('공개 주소 표기(/api/...)도 같은 자원 ID를 준다', () => {
  assert.equal(resourceIdOf('GET /api/notes/:id'), 'note.own');
  assert.equal(resourceIdOf('PUT /api/notices/:id'), 'notice.instructor');
});

test('표에 없는 경로·모양이 다른 값은 null이고 추측하지 않는다', () => {
  for (const bad of ['DELETE /notices/:id', 'GET /notes/abc', 'GET /notes/:id/extra', 'GET /notes?x=1',
    'get /notes', 'GET /api/api/notes', 'GET /admin', '', 'toString', '__proto__', 'constructor', null, undefined, 5, {}, []]) {
    assert.equal(resourceIdOf(bad), null, String(bad));
  }
});

test('현재 허용 경로 다섯 개는 모두 note.own이다', async () => {
  const { readFileSync } = await import('node:fs');
  const config = JSON.parse(readFileSync(new URL('../aleph.config.json', import.meta.url), 'utf8'));
  assert.equal(config.allowedRoutes.length, 5);
  for (const route of config.allowedRoutes) assert.equal(resourceIdOf(route), 'note.own', route);
});
