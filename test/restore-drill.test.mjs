import assert from 'node:assert/strict';
import { mkdtemp, readFile, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { DEFAULT_SNAPSHOT } from '../scripts/policy-diff.mjs';
import { runDrill } from '../scripts/restore-drill.mjs';

const tempRecord = async () => join(await mkdtemp(join(tmpdir(), 'drill-record-')), 'restore-drill.json');

test('복원 훈련은 정책·메모 사본에서 실제로 복원해 보고 모든 항목이 통과한다', async () => {
  const entry = await runDrill({ write: false });
  assert.equal(entry.ok, true, JSON.stringify(entry.checks.filter(check => !check.ok)));
  const names = entry.checks.map(check => check.name);
  for (const name of ['policy_snapshot_reread', 'policy_preview_before_apply', 'policy_restored_and_reread', 'real_policy_untouched',
    'note_backup_reread_verified', 'note_preview_before_restore', 'note_tampered_restored_and_reread', 'note_corrupt_backup_stops']) {
    assert.ok(names.includes(name), name);
  }
  assert.equal(entry.snapshot.version, 'safe-9');
});

test('사본이 변조되었으면 훈련은 실패로 기록하고 복원을 시도하지 않는다', async () => {
  const bad = JSON.parse(await readFile(DEFAULT_SNAPSHOT, 'utf8'));
  bad.policy.decisions['GET /notes'] = 'allow';
  const file = join(await mkdtemp(join(tmpdir(), 'drill-bad-')), 'bad.json');
  await writeFile(file, JSON.stringify(bad));
  const entry = await runDrill({ snapshotFile: file, write: false });
  assert.equal(entry.ok, false);
  assert.equal(entry.checks[0].name, 'policy_snapshot_verified');
  assert.equal(entry.checks[0].ok, false);
  assert.ok(!entry.checks.some(check => check.name === 'policy_restored_and_reread')); // 검증 실패 뒤에는 복원하지 않음
});

test('훈련 기록은 끝에 덧붙이기만 하고 이전 기록을 지우지 않으며, 메모 내용은 담지 않는다', async () => {
  const recordFile = await tempRecord();
  let tick = 0;
  const now = () => new Date(Date.UTC(2026, 9, 14, 0, 0, tick++));
  await runDrill({ recordFile, now });
  await runDrill({ recordFile, now });
  const text = await readFile(recordFile, 'utf8');
  const record = JSON.parse(text);
  assert.equal(record.schema, 'aleph.restore-drill.v1');
  assert.equal(record.runs.length, 2);
  assert.deepEqual(record.runs.map(run => run.at), ['2026-10-14T00:00:00.000Z', '2026-10-14T00:00:01.000Z']);
  for (const secret of ['훈련용 가상 내용', '변조된 내용', 'Bearer']) assert.ok(!text.includes(secret), secret);
});
