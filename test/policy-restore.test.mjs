import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { cp, mkdir, mkdtemp, readFile, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { test } from 'node:test';
import { fixtureRequests } from '../scripts/fixture-7.mjs';
import { DEFAULT_SNAPSHOT, REPO_ROOT, currentPolicyOf } from '../scripts/policy-diff.mjs';
import { run } from '../scripts/policy-restore.mjs';
import { mergeRoutes, planRestore, setAllowedRoutes } from '../src/policy-restore.mjs';

const ID = '11111111-2222-4333-8444-555555555555';
const pristine = (_commit, file) => readFile(resolve(REPO_ROOT, file), 'utf8'); // git 없이 시험하려고 현재 정상 파일을 사본 커밋 내용으로 씁니다
const FILES = ['src/decider.mjs', 'src/resources.mjs', 'aleph.config.json'];

async function makeRoot() {
  const base = await mkdtemp(join(tmpdir(), 'restore-'));
  await mkdir(join(base, 'src'));
  for (const file of FILES) await cp(resolve(REPO_ROOT, file), join(base, file));
  return base;
}
const read = (base, file) => readFile(join(base, file), 'utf8');
const snapshotPin = async () => JSON.parse(await readFile(DEFAULT_SNAPSHOT, 'utf8')).sha256.slice(0, 12);
const ask = async (base, change) => {
  const { decide } = await import(`${pathToFileURL(join(base, 'src', 'decider.mjs')).href}?q=${randomUUID()}`);
  return (await decide({ ...fixtureRequests().normal, requestId: randomUUID(), ...change })).decision;
};
// 침해 흉내: 남의 자료를 지우는 DELETE 를 허용하고, 미등록 기기도 통과시키고, 허용 경로를 늘립니다. 설정의 다른 값도 바꿔 둡니다.
async function tamper(base) {
  let decider = await read(base, 'src/decider.mjs');
  decider = decider.replace("['GET /notes/:id', 'PUT /notes/:id']", "['GET /notes/:id', 'PUT /notes/:id', 'DELETE /notes/:id']")
    .replace('request?.deviceRegistered !== true', 'false');
  await writeFile(join(base, 'src/decider.mjs'), decider);
  const config = JSON.parse(await read(base, 'aleph.config.json'));
  config.allowedRoutes.push('GET /api/notes/export');
  config.step = 99; config.restoreRoute = 'POST /api/other';
  await writeFile(join(base, 'aleph.config.json'), `${JSON.stringify(config, null, 2)}\n`);
}

test('설정 파일을 JSON으로 다시 써도 allowedRoutes 밖의 모양은 그대로다', async () => {
  const text = await readFile(resolve(REPO_ROOT, 'aleph.config.json'), 'utf8');
  const same = JSON.parse(text).allowedRoutes;
  assert.equal(setAllowedRoutes(text, same), text);
  assert.deepEqual(mergeRoutes(['B', 'X', 'A'], ['A', 'B', 'C']), ['B', 'A', 'C']);
  const crlf = text.replace(/\n/gu, '\r\n');
  assert.equal(setAllowedRoutes(crlf, same), crlf);
});

test('정상 상태에서는 바꿀 것이 없고 apply 해도 파일·감사 기록이 그대로다', async () => {
  const base = await makeRoot();
  const before = await Promise.all(FILES.map(file => read(base, file)));
  const result = await run({ base, apply: true, confirm: await snapshotPin(), readSource: pristine });
  assert.equal(result.code, 0);
  assert.match(result.lines.join('\n'), /복원할 것이 없습니다/);
  assert.deepEqual(await Promise.all(FILES.map(file => read(base, file))), before);
  await assert.rejects(readFile(join(base, 'policy/restore-audit.log')));
});

test('미리보기는 바뀔 항목을 보여 주고 파일을 고치지 않는다', async () => {
  const base = await makeRoot();
  await tamper(base);
  const before = await Promise.all(FILES.map(file => read(base, file)));
  const result = await run({ base, readSource: pristine });
  const text = result.lines.join('\n');
  assert.equal(result.code, 0);
  assert.match(text, /복원할 정책 버전: safe-9/);
  assert.match(text, /\[decisions\] DELETE \/notes\/:id: 값이 바뀜 \(사본 deny \/ 현재 allow\)/);
  assert.match(text, /\[decisions\] device:unregistered: 값이 바뀜/);
  assert.match(text, /\[allowedRoutes\] GET \/api\/notes\/export: 없어짐/);
  assert.match(text, /src\/decider\.mjs 전체를/);
  assert.match(text, /aleph\.config\.json 의 allowedRoutes 항목 하나만/);
  assert.match(text, /미리보기입니다. 아무것도 고치지 않았습니다/);
  assert.match(text, /--apply --confirm [0-9a-f]{12}/);
  assert.deepEqual(await Promise.all(FILES.map(file => read(base, file))), before);
  await assert.rejects(readFile(join(base, 'policy/restore-audit.log')));
});

test('확인 값이 없거나 틀리면 실행하지 않는다', async () => {
  const base = await makeRoot();
  await tamper(base);
  const before = await read(base, 'src/decider.mjs');
  for (const confirm of [undefined, '', '000000000000']) {
    const result = await run({ base, apply: true, confirm, readSource: pristine });
    assert.equal(result.code, 1);
    assert.match(result.lines.at(-1), /--confirm 값이/);
  }
  assert.equal(await read(base, 'src/decider.mjs'), before);
});

test('복원하면 남의 자료 요청은 다시 거부되고 내 메모 정상 요청은 유지되며, 다른 설정 값과 감사 이력은 보존된다', async () => {
  const base = await makeRoot();
  await tamper(base);
  // 침해된 상태: 삭제와 미등록 기기가 열려 있다
  assert.equal(await ask(base, { method: 'DELETE', route: 'DELETE /notes/:id', path: `/notes/${ID}` }), 'allow');
  assert.equal(await ask(base, { deviceRegistered: false }), 'allow');
  await mkdir(join(base, 'policy'));
  await writeFile(join(base, 'policy/restore-audit.log'), '{"old":"audit line"}\n');

  const result = await run({ base, apply: true, confirm: await snapshotPin(), readSource: pristine, now: () => new Date('2026-10-13T08:00:00Z') });
  assert.equal(result.code, 0, result.lines.join('\n'));
  assert.match(result.lines.join('\n'), /복원 완료/);

  assert.equal(await ask(base, { method: 'DELETE', route: 'DELETE /notes/:id', path: `/notes/${ID}` }), 'deny');
  assert.equal(await ask(base, { method: 'GET', route: 'GET /notes', path: '/notes' }), 'deny');
  assert.equal(await ask(base, { deviceRegistered: false }), 'deny');
  assert.equal(await ask(base, { method: 'GET', route: 'GET /notes/:id', path: `/notes/${ID}` }), 'allow');
  assert.equal(await ask(base, { method: 'PUT', route: 'PUT /notes/:id', path: `/notes/${ID}` }), 'allow');
  assert.equal(await read(base, 'src/decider.mjs'), await read(REPO_ROOT, 'src/decider.mjs'));

  const config = JSON.parse(await read(base, 'aleph.config.json'));
  assert.equal(config.step, 99);                       // 정책 밖의 값은 그대로
  assert.equal(config.restoreRoute, 'POST /api/other');
  assert.deepEqual(config.allowedRoutes, JSON.parse(await read(REPO_ROOT, 'aleph.config.json')).allowedRoutes);
  assert.equal((await currentPolicyOf(base)).allowedRoutes.length, 5);

  const audit = (await read(base, 'policy/restore-audit.log')).trimEnd().split('\n');
  assert.equal(audit[0], '{"old":"audit line"}');       // 기존 감사 기록은 그대로
  assert.equal(audit.length, 2);
  const entry = JSON.parse(audit[1]);
  assert.deepEqual(Object.keys(entry).sort(), ['at', 'changes', 'event', 'files', 'sha256', 'version']);
  assert.deepEqual(entry.files, ['src/decider.mjs', 'src/resources.mjs', 'aleph.config.json#allowedRoutes']);
});

test('복원 뒤 검증이 실패하면 바꾼 파일을 모두 원래대로 돌려놓는다', async () => {
  const base = await makeRoot();
  await tamper(base);
  const tampered = await Promise.all(FILES.map(file => read(base, file)));
  const wrongSource = async (_commit, file) => (file === 'src/decider.mjs'
    ? (await read(REPO_ROOT, file)).replace("'PUT /notes/:id']);", "'PUT /notes/:id', 'DELETE /notes/:id']);")
    : read(REPO_ROOT, file));
  const result = await run({ base, apply: true, confirm: await snapshotPin(), readSource: wrongSource });
  assert.equal(result.code, 1);
  assert.match(result.lines.at(-1), /원래대로 돌려놓았습니다/);
  assert.deepEqual(await Promise.all(FILES.map(file => read(base, file))), tampered);
  await assert.rejects(readFile(join(base, 'policy/restore-audit.log')));
});

test('사본이 없거나 검증에 실패하면 중단하고 아무것도 쓰지 않는다', async () => {
  const base = await makeRoot();
  await tamper(base);
  const tampered = await Promise.all(FILES.map(file => read(base, file)));
  const missing = await run({ base, file: join(base, 'none.json'), apply: true, confirm: 'x', readSource: pristine });
  assert.equal(missing.code, 1);
  assert.match(missing.lines[0], /^중단:/);
  const bad = JSON.parse(await readFile(DEFAULT_SNAPSHOT, 'utf8'));
  bad.policy.decisions['GET /notes'] = 'allow';
  const badFile = join(base, 'bad.json');
  await writeFile(badFile, JSON.stringify(bad));
  const result = await run({ base, file: badFile, apply: true, confirm: (await snapshotPin()), readSource: pristine });
  assert.equal(result.code, 1);
  assert.match(result.lines[0], /digest_mismatch/);
  assert.deepEqual(await Promise.all(FILES.map(file => read(base, file))), tampered);
});

test('허용 경로만 달라졌으면 설정의 allowedRoutes만 바뀌고 판정기 파일은 건드리지 않는다', async () => {
  const base = await makeRoot();
  const config = JSON.parse(await read(base, 'aleph.config.json'));
  config.allowedRoutes = config.allowedRoutes.filter(route => route !== 'GET /api/notes/:id');
  const crlfText = `${JSON.stringify(config, null, 2)}\n`.replace(/\n/gu, '\r\n');
  await writeFile(join(base, 'aleph.config.json'), crlfText);
  const decider = await read(base, 'src/decider.mjs');
  const calls = [];
  const result = await run({ base, apply: true, confirm: await snapshotPin(), readSource: async (...args) => { calls.push(args); return pristine(...args); } });
  assert.equal(result.code, 0, result.lines.join('\n'));
  assert.deepEqual(calls, []);
  assert.equal(await read(base, 'src/decider.mjs'), decider);
  const restored = await read(base, 'aleph.config.json');
  assert.ok(restored.includes('\r\n'));
  assert.ok(JSON.parse(restored).allowedRoutes.includes('GET /api/notes/:id'));
  assert.deepEqual(planRestore({ changes: [{ area: 'allowedRoutes' }] }).map(target => target.file), ['aleph.config.json']);
});
