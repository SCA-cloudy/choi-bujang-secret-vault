import assert from 'node:assert/strict';
import { test } from 'node:test';
import { detect, readDetectionEvents } from '../src/detect.mjs';

const START = Date.UTC(2026, 9, 1, 0, 0, 0);
const reads = (count, owner = 'learner_fixture', step = 2) => Array.from({ length: count }, (_, i) => ({
  at: new Date(START + i * step * 1000).toISOString(), method: 'GET', identity: { sub: owner },
}));

test('정상 사건과 의심 사건을 계약의 세 값만으로 읽는다', () => {
  for (const events of [reads(30), reads(200)]) {
    const read = readDetectionEvents(events);
    assert.equal(read.length, events.length);
    assert.deepEqual(Object.keys(read[0]).sort(), ['atMs', 'method', 'sub']);
    assert.deepEqual(read[0], { atMs: START, method: 'GET', sub: 'learner_fixture' });
  }
});

test('사건에 덧붙은 토큰·본문·이름·헤더·기기 값은 읽지도 복사하지도 않는다', () => {
  const secret = 'SECRET-VALUE-123';
  const event = {
    ...reads(1)[0], token: secret, authorization: `Bearer ${secret}`, body: { content: secret }, name: secret,
    email: `${secret}@example.test`, deviceId: secret, headers: { cookie: secret }, sub: 'forged_top_level',
    identity: { sub: 'learner_fixture', token: secret, name: secret },
  };
  const read = readDetectionEvents([event]);
  assert.deepEqual(read, [{ atMs: START, method: 'GET', sub: 'learner_fixture' }]);
  assert.ok(!JSON.stringify(read).includes(secret));
});

test('모양이 맞지 않는 사건은 버리고 값을 채워 넣지 않는다', () => {
  const bad = [
    null, undefined, 5, 'x', [], {}, { at: '2026-10-01T00:00:00.000Z', method: 'GET' },
    { at: '2026-10-01T00:00:00.000Z', method: 'GET', identity: null },
    { at: '2026-10-01T00:00:00.000Z', method: 'GET', identity: { sub: 7 } },
    { at: '2026-10-01T00:00:00.000Z', method: 'GET', identity: { sub: '' } },
    { at: '2026-10-01T00:00:00.000Z', method: 'GET', identity: { sub: 'a b' } },
    { at: '2026-10-01T00:00:00.000Z', method: 'GET', identity: { sub: 'x'.repeat(65) } },
    { at: '2026-10-01', method: 'GET', identity: { sub: 'u' } },
    { at: '2026-13-45T99:00:00.000Z', method: 'GET', identity: { sub: 'u' } },
    { at: 1700000000000, method: 'GET', identity: { sub: 'u' } },
    { at: '2026-10-01T00:00:00.000Z', method: 'get', identity: { sub: 'u' } },
    { at: '2026-10-01T00:00:00.000Z', method: 5, identity: { sub: 'u' } },
  ];
  assert.deepEqual(readDetectionEvents(bad), []);
  assert.equal(readDetectionEvents([...bad, ...reads(3)]).length, 3);
});

test('배열이 아니면 사건 내용을 담지 않은 오류를 낸다', () => {
  for (const value of [undefined, null, 'SECRET-VALUE-123', 5, { sub: 'SECRET-VALUE-123' }]) {
    assert.throws(() => readDetectionEvents(value), error => error instanceof TypeError && error.message === 'invalid_detection_events');
    assert.throws(() => detect(value), error => error.message === 'invalid_detection_events');
  }
});

test('이번 단계에서 detect의 결과는 그대로 observe이다', () => {
  assert.deepEqual(detect(reads(30)), { action: 'observe' });
  assert.deepEqual(detect(reads(200)), { action: 'observe' });
  assert.deepEqual(detect([]), { action: 'observe' });
});
