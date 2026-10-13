import assert from 'node:assert/strict';
import { mkdtemp, readFile, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { DEFAULT_SNAPSHOT, run } from '../scripts/policy-diff.mjs';
import { diffPolicy, policyDigest, verifySnapshot } from '../src/policy-diff.mjs';

const load = async () => JSON.parse(await readFile(DEFAULT_SNAPSHOT, 'utf8'));
const tempFile = async (value) => {
  const file = join(await mkdtemp(join(tmpdir(), 'policy-')), 'safe-policy.json');
  await writeFile(file, typeof value === 'string' ? value : JSON.stringify(value));
  return file;
};
const resign = (snapshot) => ({ ...snapshot, sha256: policyDigest(snapshot.policy) });

test('커밋된 사본은 검증을 통과하고 현재 정책과 같다', async () => {
  const snapshot = await load();
  assert.deepEqual(verifySnapshot(snapshot), { ok: true });
  const result = await run({});
  assert.equal(result.code, 0);
  assert.match(result.lines.join('\n'), /복원할 정책 버전: safe-9/);
  assert.match(result.lines.join('\n'), /변경 범위: 없음/);
});

test('사본 파일이 없으면 중단한다', async () => {
  const result = await run({ file: join(tmpdir(), 'no-such-policy-file.json') });
  assert.equal(result.code, 1);
  assert.match(result.lines[0], /^중단:/);
  assert.ok(!result.lines.join('\n').includes('변경 범위'));
});

test('JSON이 아니거나 내용이 바뀐 사본은 검증에서 중단한다', async () => {
  assert.equal((await run({ file: await tempFile('not json') })).code, 1);
  const snapshot = await load();
  const edited = { ...snapshot, policy: { ...snapshot.policy, decisions: { ...snapshot.policy.decisions, 'GET /notes': 'allow' } } };
  const result = await run({ file: await tempFile(edited) });
  assert.equal(result.code, 1);
  assert.match(result.lines[0], /digest_mismatch/);
});

test('모양이 다른 사본(알 수 없는 항목, 잘못된 버전·결정·커밋)은 거부한다', async () => {
  const snapshot = await load();
  const reason = (value) => verifySnapshot(value).reason;
  assert.equal(reason({ ...snapshot, extra: 1 }), 'snapshot_keys_invalid');
  assert.equal(reason({ ...snapshot, version: 'latest' }), 'version_invalid');
  assert.equal(reason({ ...snapshot, schema: 'other' }), 'schema_mismatch');
  assert.equal(reason({ ...snapshot, source: { ...snapshot.source, commit: 'abc' } }), 'source_invalid');
  assert.equal(reason(resign({ ...snapshot, policy: { ...snapshot.policy, decisions: { 'GET /notes': 'maybe' } } })), 'policy_invalid');
  assert.equal(reason(null), 'snapshot_not_object');
});

test('바깥에서 적어 둔 지문과 다르면 지문을 다시 계산해 둔 사본도 거부한다', async () => {
  const snapshot = await load();
  const forged = resign({ ...snapshot, policy: { ...snapshot.policy, ruleIds: ['device_registered'] } });
  assert.deepEqual(verifySnapshot(forged), { ok: true }); // 지문만으로는 위조를 못 막는다: 바깥 지문(pin)이 필요하다
  assert.equal(verifySnapshot(forged, { expectedSha256: snapshot.sha256 }).reason, 'pin_mismatch');
  const result = await run({ file: await tempFile(forged), expectSha256: snapshot.sha256 });
  assert.equal(result.code, 1);
  assert.match(result.lines[0], /pin_mismatch/);
  assert.equal((await run({ expectSha256: snapshot.sha256 })).code, 0);
});

test('현재 정책이 달라지면 변경 범위가 실행 전에 항목별로 보인다', async () => {
  const snapshot = await load();
  const current = structuredClone(snapshot.policy);
  current.ruleIds = current.ruleIds.filter(id => id !== 'resource_zone');
  current.allowedRoutes.push('POST /api/restore');
  current.decisions['GET /notes'] = 'allow';
  current.decisions['PUT /notices/:id'] = 'allow';
  const diff = diffPolicy(snapshot.policy, current);
  assert.equal(diff.same, false);
  const find = (area, item) => diff.changes.find(change => change.area === area && change.item === item);
  assert.equal(find('ruleIds', 'resource_zone').kind, 'restore_add');
  assert.equal(find('allowedRoutes', 'POST /api/restore').kind, 'restore_remove');
  assert.deepEqual([find('decisions', 'GET /notes').safe, find('decisions', 'GET /notes').current], ['deny', 'allow']);
  const result = await run({ current });
  assert.equal(result.code, 0);
  assert.match(result.lines.join('\n'), /변경 범위: 4건 \(ruleIds, allowedRoutes, decisions\)/);
  assert.match(result.lines.join('\n'), /\[decisions\] PUT \/notices\/:id: 값이 바뀜 \(사본 deny \/ 현재 allow\)/);
});

test('차이를 보는 동안 사본 파일은 바뀌지 않고, 사본에는 비밀로 볼 만한 값이 없다', async () => {
  const before = await readFile(DEFAULT_SNAPSHOT, 'utf8');
  await run({});
  assert.equal(await readFile(DEFAULT_SNAPSHOT, 'utf8'), before);
  assert.ok(!/token|secret|password|apikey|authorization|owner|content|@/iu.test(before));
});
