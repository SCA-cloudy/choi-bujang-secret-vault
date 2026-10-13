import assert from 'node:assert/strict';
import { test } from 'node:test';
import { checkDetection } from '../scripts/detect-test.mjs';
import { detect } from '../src/detect.mjs';

const START = Date.UTC(2026, 9, 1, 0, 0, 0);
const at = ms => new Date(START + ms).toISOString();
const reads = (count, { owner = 'learner_fixture', stepMs = 2000, offset = 0, method = 'GET' } = {}) => Array.from({ length: count }, (_, i) => ({
  at: at(offset + i * stepMs), method, identity: { sub: owner },
}));
const PROPOSE = sub => ({ action: 'propose_revocation', reasonCode: 'burst_read', subject: sub });
const OBSERVE = { action: 'observe' };

test('카드의 연습 사례 6개가 모두 통과한다', async () => {
  const results = await checkDetection(detect);
  assert.deepEqual(results.map(item => item.passed), [true, true, true, true, true, true]);
});

test('120건은 관찰, 121건부터 회수 제안이다', () => {
  assert.deepEqual(detect(reads(120)), OBSERVE);
  assert.deepEqual(detect(reads(121)), PROPOSE('learner_fixture'));
  assert.deepEqual(detect(reads(121, { stepMs: 1 })), PROPOSE('learner_fixture'));
});

test('10분 구간 경계: 시작과 끝이 600초 차이면 한 구간이고, 601초면 아니다', () => {
  assert.deepEqual(detect(reads(121, { stepMs: 5000 })), PROPOSE('learner_fixture'));
  const spread = reads(121, { stepMs: 5008.33 }).map((event, i) => ({ ...event, at: at(Math.round(i * 5008.33)) }));
  assert.deepEqual(detect(spread), OBSERVE);
});

test('입력 순서가 뒤섞여도 시각으로 정렬해 센다', () => {
  assert.deepEqual(detect(reads(121).reverse()), PROPOSE('learner_fixture'));
});

test('GET이 아닌 사건은 세지 않는다', () => {
  assert.deepEqual(detect([...reads(100), ...reads(100, { method: 'POST' })]), OBSERVE);
  assert.deepEqual(detect(reads(200, { method: 'POST' })), OBSERVE);
  assert.deepEqual(detect([...reads(100), ...reads(21, { method: 'POST', offset: 1000 })]), OBSERVE);
});

test('다른 사용자의 사건은 합산하지 않는다', () => {
  assert.deepEqual(detect([...reads(100), ...reads(100, { owner: 'other_fixture', offset: 1000 })]), OBSERVE);
  assert.deepEqual(detect([...reads(121), ...reads(10, { owner: 'other_fixture' })]), PROPOSE('learner_fixture'));
});

test('두 사용자가 모두 넘으면 먼저 넘은 한 명만 제안한다', () => {
  assert.deepEqual(detect([...reads(130, { owner: 'late_fixture', offset: 60000 }), ...reads(130, { owner: 'early_fixture' })]), PROPOSE('early_fixture'));
});

test('지역·네트워크·기기 같은 계약 밖 값은 판단에 쓰지 않는다', () => {
  const quiet = reads(30).map(event => ({ ...event, region: 'foreign', network: 'unusual', deviceId: 'a'.repeat(16) }));
  assert.deepEqual(detect(quiet), OBSERVE);
  const burst = reads(121).map(event => ({ ...event, region: 'local', network: 'usual' }));
  assert.deepEqual(detect(burst), PROPOSE('learner_fixture'));
});

test('잘못된 사건은 세지 않고, 제안에는 세 항목만 있고 비밀값이 없다', () => {
  const secret = 'SECRET-VALUE-123';
  const broken = Array.from({ length: 300 }, () => ({ at: 'not-a-date', method: 'GET', identity: { sub: 'learner_fixture' }, token: secret }));
  assert.deepEqual(detect(broken), OBSERVE);
  const answer = detect(reads(121).map(event => ({ ...event, token: secret, body: { content: secret } })));
  assert.deepEqual(Object.keys(answer).sort(), ['action', 'reasonCode', 'subject']);
  assert.ok(!JSON.stringify(answer).includes(secret));
  assert.match(answer.reasonCode, /^[a-z][a-z_]*$/u);
});
