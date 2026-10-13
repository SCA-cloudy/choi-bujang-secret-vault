import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { test } from 'node:test';
import { fixtureRequests } from '../scripts/fixture-7.mjs';
import { RULE_IDS, decide } from '../src/decider.mjs';

const { normal, suspicious } = fixtureRequests();
const fixture = (signals, recentEvents = [], extra = {}) => ({
  ...normal, requestId: randomUUID(), signals: { source: 'judge_fixture', region: 'local', network: 'usual', hour: 14, ...signals },
  recentEvents, ...extra,
});
const bulk = [{ kind: 'risk_signal', ageSeconds: 60, count: 20 }];

test('rule ids keep the device and step-up rules and add resource_zone', () => {
  assert.deepEqual([...RULE_IDS], ['device_registered', 'step_up_required', 'resource_zone']);
});

test('the fixed complex event asks for a further check and the normal event is allowed', async () => {
  const unusual = await decide(suspicious);
  assert.deepEqual(unusual, { schema: 'aleph.decision.v1', requestId: suspicious.requestId, decision: 'step_up',
    reasonCode: 'step_up_required', ruleIds: ['step_up_required'] });
  const ordinary = await decide(normal);
  assert.equal(ordinary.decision, 'allow');
  assert.deepEqual(ordinary.ruleIds, ['device_registered', 'resource_zone']);
});

test('region alone never causes a further check or a block', async () => {
  for (const region of ['foreign', 'local', 'unknown', 'somewhere_new']) {
    const answer = await decide(fixture({ region }));
    assert.equal(answer.decision, 'allow', region);
  }
  // 지역이 평소(local)여도 세 신호가 겹치면 추가 확인을 요구한다. 지역은 판단 조건이 아니다.
  const answer = await decide(fixture({ region: 'local', network: 'unusual', hour: 3 }, bulk));
  assert.equal(answer.decision, 'step_up');
});

test('one or two of the three signals are not enough', async () => {
  const cases = [
    fixture({ hour: 3 }), fixture({ network: 'unusual' }), fixture({}, bulk),
    fixture({ hour: 3, network: 'unusual' }), fixture({ hour: 3 }, bulk), fixture({ network: 'unusual' }, bulk),
  ];
  for (const request of cases) assert.equal((await decide(request)).decision, 'allow');
});

test('hour boundaries and old events', async () => {
  for (const [hour, expected] of [[22, 'step_up'], [23, 'step_up'], [0, 'step_up'], [5, 'step_up'], [6, 'allow'], [21, 'allow']]) {
    assert.equal((await decide(fixture({ network: 'unusual', hour }, bulk))).decision, expected, `hour ${hour}`);
  }
  const old = [{ kind: 'risk_signal', ageSeconds: 601, count: 20 }];
  assert.equal((await decide(fixture({ network: 'unusual', hour: 3 }, old))).decision, 'allow');
  const nine = [{ kind: 'risk_signal', ageSeconds: 5, count: 9 }];
  assert.equal((await decide(fixture({ network: 'unusual', hour: 3 }, nine))).decision, 'allow');
  const split = [{ kind: 'a', ageSeconds: 5, count: 4 }, { kind: 'b', ageSeconds: 9, count: 6 }];
  assert.equal((await decide(fixture({ network: 'unusual', hour: 3 }, split))).decision, 'step_up');
});

test('missing, untrusted or malformed signals never trigger the rule and are not treated as normal data', async () => {
  const base = { network: 'unusual', hour: 3 };
  for (const request of [
    { ...fixture(base, bulk), signals: { source: 'none', region: 'unknown', network: 'unusual', hour: 3 } },
    { ...fixture(base, bulk), signals: { source: 'client_header', region: 'foreign', network: 'unusual', hour: 3 } },
    { ...fixture(base, bulk), signals: undefined },
    fixture({ hour: '3' }, bulk), fixture({ network: 'Unusual!' }, bulk),
    { ...fixture(base, bulk), headers: { 'x-network': 'unusual' } , signals: { source: 'none' } },
  ]) {
    assert.equal((await decide(request)).decision, 'allow');
  }
});

test('after the further check the same request is allowed again with both rule ids, and nothing is permanently blocked', async () => {
  const again = await decide({ ...suspicious, requestId: randomUUID(), stepUp: { verified: true, authAgeSeconds: 60 } });
  assert.deepEqual(again, { schema: 'aleph.decision.v1', requestId: again.requestId, decision: 'allow',
    reasonCode: 'approved', ruleIds: ['device_registered', 'resource_zone', 'step_up_required'] });
  const stale = await decide({ ...suspicious, requestId: randomUUID(), stepUp: { verified: true, authAgeSeconds: 901 } });
  assert.equal(stale.decision, 'step_up');
  const unverifiedForged = await decide({ ...suspicious, requestId: randomUUID(), stepUp: { verified: 'true', authAgeSeconds: 1 } });
  assert.equal(unverifiedForged.decision, 'step_up');
});

test('the earlier device rules stay in force', async () => {
  assert.equal((await decide({ ...suspicious, deviceRegistered: false })).reasonCode, 'device_not_registered');
  assert.equal((await decide({ ...suspicious, deviceRegistered: false })).decision, 'deny');
  assert.equal((await decide({ ...normal, method: 'POST' })).reasonCode, 'starter_not_ready');
  assert.equal((await decide({ ...suspicious, method: 'DELETE' })).decision, 'deny');
});

test('every response has only the five contract names', async () => {
  for (const request of [normal, suspicious, { ...normal, deviceRegistered: false }, { ...normal, method: 'PUT' }, null, {}]) {
    const answer = await decide(request);
    assert.deepEqual(Object.keys(answer).sort(), ['decision', 'reasonCode', 'requestId', 'ruleIds', 'schema']);
    assert.ok(answer.ruleIds.every(id => RULE_IDS.includes(id)));
  }
});
