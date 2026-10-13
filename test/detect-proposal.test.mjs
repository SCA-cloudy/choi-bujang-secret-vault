import assert from 'node:assert/strict';
import { test } from 'node:test';
import { randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { fixtureRequests } from '../scripts/fixture-7.mjs';
import { decide, RULE_IDS } from '../src/decider.mjs';
import { detect } from '../src/detect.mjs';

const START = Date.UTC(2026, 9, 1, 0, 0, 0);
const reads = (count, owner = 'learner_fixture', extra = {}) => Array.from({ length: count }, (_, i) => ({
  at: new Date(START + i * 2000).toISOString(), method: 'GET', identity: { sub: owner }, ...extra,
}));

test('의심 사건은 대상 한 명과 이유 코드가 있는 회수 제안을 낸다', () => {
  const answer = detect(reads(150));
  assert.deepEqual(answer, { action: 'propose_revocation', reasonCode: 'burst_read', subject: 'learner_fixture' });
  assert.deepEqual(Object.keys(answer).sort(), ['action', 'reasonCode', 'subject']);
  assert.equal(typeof answer.subject, 'string');
  assert.match(answer.reasonCode, /^[a-z][a-z_]*$/u);
});

test('정상 사건은 제안을 내지 않고, 대상과 이유 항목도 없다', () => {
  for (const events of [reads(30), reads(120), []]) {
    const answer = detect(events);
    assert.deepEqual(answer, { action: 'observe' });
    assert.ok(!('subject' in answer) && !('reasonCode' in answer));
  }
});

test('대상은 엔진이 확인한 identity.sub 한 명뿐이고, 사건에 덧붙은 이름·기기·최상위 sub는 대상이 되지 않는다', () => {
  const forged = reads(150, 'learner_fixture', { sub: 'forged_top_level', deviceId: 'ffffffffffffffff', device: { id: 'x' }, userId: 'forged_user' });
  assert.deepEqual(detect(forged), { action: 'propose_revocation', reasonCode: 'burst_read', subject: 'learner_fixture' });
  const two = detect([...reads(150, 'first_fixture'), ...reads(150, 'second_fixture')]);
  assert.equal(typeof two.subject, 'string');
  assert.equal(Object.keys(two).length, 3);
});

test('탐지는 제안만 돌려주고 회수를 직접 하지 않는다: 파일·네트워크·다른 모듈에 닿지 않는다', () => {
  const source = readFileSync(new URL('../src/detect.mjs', import.meta.url), 'utf8');
  assert.ok(!/^\s*import\s/mu.test(source));
  assert.ok(!/(fetch\(|readFile|writeFile|process\.env|child_process|XMLHttpRequest)/u.test(source));
});

test('기존 접속 허용·거부 응답 형식과 규칙은 그대로이다', async () => {
  const { normal, suspicious } = fixtureRequests();
  for (const request of [normal, suspicious, { ...normal, requestId: randomUUID(), deviceRegistered: false }]) {
    const answer = await decide(request);
    assert.deepEqual(Object.keys(answer).sort(), ['decision', 'reasonCode', 'requestId', 'ruleIds', 'schema']);
    assert.ok(['allow', 'deny', 'step_up'].includes(answer.decision));
    assert.ok(answer.ruleIds.every(id => RULE_IDS.includes(id)));
  }
  assert.equal((await decide(normal)).decision, 'allow');
  assert.equal((await decide(suspicious)).decision, 'step_up');
  assert.equal((await decide({ ...normal, deviceRegistered: false })).reasonCode, 'device_not_registered');
  assert.deepEqual([...RULE_IDS], ['device_registered', 'step_up_required', 'resource_zone']);
});
