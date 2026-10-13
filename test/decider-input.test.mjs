import assert from 'node:assert/strict';
import { test } from 'node:test';
import { fixtureRequests } from '../scripts/fixture-7.mjs';
import { decide, readAccessInfo } from '../src/decider.mjs';

const { normal, suspicious } = fixtureRequests();

test('engine fixture signals are read as engine_fixture with their values', () => {
  const info = readAccessInfo(suspicious);
  assert.deepEqual(info.signals, { source: 'engine_fixture', region: 'foreign', network: 'unusual', hour: 3 });
  assert.deepEqual(info.recentEvents, [{ kind: 'risk_signal', ageSeconds: 60, count: 20 }]);
  assert.deepEqual(info.stepUp, { verified: false, authAgeSeconds: null });
});

test('source none, missing or unknown sources give no values and no default normal', () => {
  const none = { source: 'none', region: 'unknown', network: 'unknown', hour: 14 };
  for (const signals of [none, undefined, null, 'x', { source: 'client_header', region: 'local', network: 'usual', hour: 14 },
    { region: 'local', network: 'usual', hour: 14 }]) {
    const info = readAccessInfo({ ...normal, signals });
    assert.deepEqual(info.signals, { source: 'none', region: null, network: null, hour: null });
  }
});

test('forged client headers and extra names never become access information', () => {
  const forged = {
    ...normal, signals: { source: 'none', region: 'unknown', network: 'unknown', hour: 0 },
    headers: { 'x-forwarded-for': '203.0.113.9', 'x-geo-region': 'local', 'x-network': 'usual' },
    geo: { region: 'local' }, region: 'local', network: 'usual', hour: 14,
  };
  assert.deepEqual(readAccessInfo(forged).signals, { source: 'none', region: null, network: null, hour: null });
  // 엔진 출처라도 요청 바깥의 헤더 값이 빈 칸을 채우지 않는다.
  const partial = { ...forged, signals: { source: 'judge_fixture' }, headers: { 'x-geo-region': 'local' } };
  assert.deepEqual(readAccessInfo(partial).signals, { source: 'engine_fixture', region: null, network: null, hour: null });
});

test('malformed values become unknown instead of normal', () => {
  const bad = { ...normal, signals: { source: 'judge_fixture', region: 'Local!', network: 7, hour: '14' } };
  assert.deepEqual(readAccessInfo(bad).signals, { source: 'engine_fixture', region: null, network: null, hour: null });
  for (const hour of [24, -1, 1.5, NaN, null]) {
    assert.equal(readAccessInfo({ ...normal, signals: { ...normal.signals, hour } }).signals.hour, null);
  }
  assert.equal(readAccessInfo({ ...normal, signals: { ...normal.signals, region: 'unknown' } }).signals.region, null);
});

test('step-up proof counts only when verified with an age of 0 to 900 seconds', () => {
  const ok = readAccessInfo({ ...normal, stepUp: { verified: true, authAgeSeconds: 60 } }).stepUp;
  assert.deepEqual(ok, { verified: true, authAgeSeconds: 60 });
  for (const stepUp of [{ verified: true, authAgeSeconds: null }, { verified: true, authAgeSeconds: 901 },
    { verified: true, authAgeSeconds: -1 }, { verified: 'true', authAgeSeconds: 60 }, undefined, 7]) {
    assert.deepEqual(readAccessInfo({ ...normal, stepUp }).stepUp, { verified: false, authAgeSeconds: null });
  }
});

test('recent events keep at most 12 well-formed items', () => {
  const good = { kind: 'risk_signal', ageSeconds: 5, count: 2 };
  const many = Array.from({ length: 20 }, () => good);
  assert.equal(readAccessInfo({ ...normal, recentEvents: many }).recentEvents.length, 12);
  const mixed = [good, { kind: 'Risk', ageSeconds: 5, count: 2 }, { kind: 'risk_signal', ageSeconds: -1, count: 2 },
    { kind: 'risk_signal', ageSeconds: 5, count: 0 }, null, 'x'];
  assert.deepEqual(readAccessInfo({ ...normal, recentEvents: mixed }).recentEvents, [good]);
  assert.deepEqual(readAccessInfo({ ...normal, recentEvents: 'x' }).recentEvents, []);
});

test('missing or broken requests give empty access information and the device decision is unchanged', async () => {
  for (const request of [undefined, null, 'x', {}]) {
    assert.deepEqual(readAccessInfo(request), {
      signals: { source: 'none', region: null, network: null, hour: null },
      stepUp: { verified: false, authAgeSeconds: null }, recentEvents: [],
    });
  }
  assert.equal((await decide(normal)).decision, 'allow');
  assert.equal((await decide({ ...normal, deviceRegistered: false })).reasonCode, 'device_not_registered');
});
