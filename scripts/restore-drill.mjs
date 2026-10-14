// 10단계: 백업 복원 훈련(npm run backup:drill).
// 깃랩 사고처럼 "백업은 있었지만 복원되는지 아무도 시험하지 않은" 일을 막으려고, 사본에서 실제로 복원해 보고 결과를 기록합니다.
// - 인터넷·DB·환경변수 없이 이 저장소만으로 돕니다. 실제 정책 파일과 실제 메모 DB는 건드리지 않습니다.
// - 정책: 안전 정책 사본을 읽어 검증하고, 한 번 더 읽어 같은지 확인한 뒤, 임시 폴더에 침해를 흉내 내고
//   사본에서 복원(policy:restore 와 같은 코드)한 다음 다시 읽어 사본과 같은지 대조합니다.
// - 메모: 실제 복구 코드(src/notes-restore.mjs)를 메모리 저장소로 돌려, 시험 계정 B 메모를 변조·삭제한 뒤
//   미리 보기(복원할 버전·바뀔 항목) → 복원 → 다시 읽어 ID·소유자·내용 해시 대조를 하고,
//   남의 요청·사본 변조·사본 없음이면 멈추는지 확인합니다.
// - 결과는 policy/restore-drill.json 의 runs 끝에 한 건씩 덧붙입니다(이전 기록은 지우지 않습니다).
//   기록에는 통과 여부와 짧은 설명만 담고 메모 내용·키·사용자 정보는 담지 않습니다.
import { cp, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { checkBackupRow, noteContentSha256 } from '../src/note-backup.mjs';
import { createNotesHandlers } from '../src/notes-api.mjs';
import { createRestoreHandler } from '../src/notes-restore.mjs';
import { diffPolicy } from '../src/policy-diff.mjs';
import { DEFAULT_SNAPSHOT, REPO_ROOT, currentPolicyOf, readVerifiedSnapshot } from './policy-diff.mjs';
import { gitSource, run as restorePolicy } from './policy-restore.mjs';

export const DEFAULT_RECORD = resolve(REPO_ROOT, 'policy', 'restore-drill.json');
const POLICY_FILES = ['src/decider.mjs', 'src/resources.mjs', 'aleph.config.json'];

// ---------- 정책 사본 복원 훈련 ----------
async function policyDrill(checks, { snapshotFile }) {
  const first = await readVerifiedSnapshot(snapshotFile);
  checks.push({ name: 'policy_snapshot_verified', ok: first.ok, detail: first.ok ? '사본 모양·지문 검증 통과' : first.line });
  if (!first.ok) return null;
  const again = await readVerifiedSnapshot(snapshotFile);
  const same = again.ok && again.snapshot.sha256 === first.snapshot.sha256;
  checks.push({ name: 'policy_snapshot_reread', ok: same, detail: same ? '다시 읽은 사본의 지문이 처음과 같음' : '다시 읽은 사본이 처음과 다르거나 검증 실패' });
  if (!same) return null;
  const { snapshot } = first;

  // 사본 커밋의 파일을 git에서 읽는다. 얕게 받은 저장소라 그 커밋이 없으면, 현재 정책이 사본과 같다는 것을 확인한 뒤에만 현재 파일을 쓴다.
  let source = (commit, file) => gitSource(REPO_ROOT, commit, file);
  try { await source(snapshot.source.commit, POLICY_FILES[0]); } catch {
    const now = diffPolicy(snapshot.policy, await currentPolicyOf(REPO_ROOT));
    if (!now.same) {
      checks.push({ name: 'policy_restore_drill', ok: false, detail: '사본 커밋을 읽을 수 없고 현재 정책도 사본과 달라 복원 훈련을 하지 못함' });
      return snapshot;
    }
    source = (_commit, file) => readFile(resolve(REPO_ROOT, file), 'utf8');
  }

  const temp = await mkdtemp(join(tmpdir(), 'restore-drill-'));
  try {
    await mkdir(join(temp, 'src'), { recursive: true });
    for (const file of POLICY_FILES) await cp(resolve(REPO_ROOT, file), join(temp, file));
    // 침해 흉내(임시 폴더에서만): 남의 메모 삭제 허용, 미등록 기기 통과, 허용 경로 추가, 설정의 다른 값 변경.
    let decider = await readFile(join(temp, 'src/decider.mjs'), 'utf8');
    decider = decider.replace("['GET /notes/:id', 'PUT /notes/:id']", "['GET /notes/:id', 'PUT /notes/:id', 'DELETE /notes/:id']")
      .replace('request?.deviceRegistered !== true', 'false');
    await writeFile(join(temp, 'src/decider.mjs'), decider);
    const config = JSON.parse(await readFile(join(temp, 'aleph.config.json'), 'utf8'));
    config.allowedRoutes = [...config.allowedRoutes, 'GET /api/notes/export'];
    const keptStep = config.step; const keptIssuer = config.judgeIssuer;
    await writeFile(join(temp, 'aleph.config.json'), `${JSON.stringify(config, null, 2)}\n`);
    const broken = diffPolicy(snapshot.policy, await currentPolicyOf(temp));
    checks.push({ name: 'policy_incident_simulated', ok: !broken.same, detail: `임시 폴더에서 정책 ${broken.changes.length}건을 바꿔 침해를 흉내 냄` });

    const preview = await restorePolicy({ base: temp, file: snapshotFile, readSource: source });
    const shown = preview.lines.some(line => line.startsWith('복원할 정책 버전:')) && preview.lines.some(line => line.startsWith('바뀔 파일·항목:'));
    checks.push({ name: 'policy_preview_before_apply', ok: preview.code === 0 && shown, detail: '실행 전에 복원할 버전과 바뀔 파일·항목을 보여 주고 아무것도 고치지 않음' });

    const wrong = await restorePolicy({ base: temp, file: snapshotFile, readSource: source, apply: true, confirm: 'xxxxxxxxxxxx' });
    const stillBroken = !diffPolicy(snapshot.policy, await currentPolicyOf(temp)).same;
    checks.push({ name: 'policy_wrong_confirm_stops', ok: wrong.code === 1 && stillBroken, detail: '확인 값이 틀리면 멈추고 아무것도 바꾸지 않음' });

    const done = await restorePolicy({ base: temp, file: snapshotFile, readSource: source, apply: true, confirm: snapshot.sha256.slice(0, 12) });
    const after = diffPolicy(snapshot.policy, await currentPolicyOf(temp));
    const kept = JSON.parse(await readFile(join(temp, 'aleph.config.json'), 'utf8'));
    let audit = '';
    try { audit = await readFile(join(temp, 'policy/restore-audit.log'), 'utf8'); } catch { audit = ''; }
    checks.push({ name: 'policy_restored_and_reread', ok: done.code === 0 && after.same, detail: '사본에서 복원한 뒤 다시 읽은 정책이 사본과 같음' });
    checks.push({ name: 'policy_other_values_kept', ok: kept.step === keptStep && kept.judgeIssuer === keptIssuer, detail: '정책 밖의 설정 값(step, judgeIssuer)은 그대로' });
    checks.push({ name: 'policy_audit_appended', ok: audit.trim().split('\n').filter(Boolean).length === 1 && audit.includes('"event":"policy_restore"'), detail: '복원 감사 기록 한 줄이 덧붙여짐' });
  } finally {
    await rm(temp, { recursive: true, force: true });
  }
  const real = diffPolicy(snapshot.policy, await currentPolicyOf(REPO_ROOT));
  checks.push({ name: 'real_policy_untouched', ok: real.same, detail: '훈련 뒤에도 이 저장소의 실제 정책은 사본과 같고 바뀌지 않음' });
  return snapshot;
}

// ---------- 메모 사본 복원 훈련 (메모리 저장소, 실제 복구 코드) ----------
const USER_A = '11111111-1111-4111-8111-111111111111';
const USER_B = '22222222-2222-4222-8222-222222222222';
const NOTE_B = '33333333-3333-4333-8333-333333333333';
const NOTE_A = '44444444-4444-4444-8444-444444444444';

function memoryStore() {
  const rows = new Map();
  const backups = new Map();
  const mine = (id, ownerId) => (rows.get(id)?.owner_id === ownerId ? rows.get(id) : null);
  return {
    rows, backups,
    async list(ownerId) { return [...rows.values()].filter(row => row.owner_id === ownerId); },
    async get(id, ownerId) { return mine(id, ownerId); },
    async peek(id) { const row = rows.get(id); return row ? { id: row.id, owner_id: row.owner_id } : null; },
    async create({ id, ownerId, title, content }) {
      if (rows.has(id)) return { conflict: true };
      rows.set(id, { id, owner_id: ownerId, title, content });
      return { conflict: false };
    },
    async update(id, ownerId, { title, content }) { const row = mine(id, ownerId); if (!row) return null; Object.assign(row, { title, content }); return row; },
    async remove(id, ownerId) { if (!mine(id, ownerId)) return null; rows.delete(id); return { id }; },
    async getBackup(id, ownerId) { const row = backups.get(id); return row?.owner_id === ownerId ? { ...row } : null; },
    async saveBackup({ id, ownerId, title, content, sha256 }) {
      if (backups.has(id)) return { exists: true };
      backups.set(id, { id, owner_id: ownerId, title, content, content_sha256: sha256 });
      return { exists: false };
    },
  };
}

async function call(fn, { method = 'POST', who = USER_B, body, query } = {}) {
  const response = {
    statusCode: null, body: null,
    setHeader() {}, status(code) { this.statusCode = code; return this; }, json(value) { this.body = value; return this; },
  };
  const quiet = console.error; console.error = () => {};
  try { await fn({ method, headers: who ? { authorization: `Bearer ${who}` } : {}, body, query }, response); } finally { console.error = quiet; }
  return response;
}

async function notesDrill(checks) {
  const store = memoryStore();
  const verifyAuthorization = async header => ([USER_A, USER_B].includes(header?.slice(7)) ? { kind: 'student', userId: header.slice(7) } : null);
  const notes = createNotesHandlers({ verifyAuthorization, store });
  const restore = createRestoreHandler({ verifyAuthorization, store });
  const original = { title: '훈련용 가상 제목', body: '훈련용 가상 내용' };
  const made = await call(notes.collection, { body: { id: NOTE_B, ...original } });
  await call(notes.collection, { who: USER_A, body: { id: NOTE_A, title: '다른 메모', body: '다른 내용' } });
  const expected = noteContentSha256(original.title, original.body);

  // 사전 백업을 다시 읽어 검증
  const backup = checkBackupRow(await store.getBackup(NOTE_B, USER_B), { id: NOTE_B, ownerId: USER_B });
  checks.push({ name: 'note_backup_reread_verified', ok: made.statusCode === 201 && backup.ok && backup.sha256 === expected, detail: '메모를 만들 때 생긴 사본을 다시 읽어 ID·소유자·내용 해시가 맞음' });

  // 변조 → 미리 보기 → 복원 → 다시 읽어 대조
  await call(notes.item, { method: 'PUT', query: { id: NOTE_B }, body: { title: '변조', body: '변조된 내용' } });
  const otherBefore = JSON.stringify(store.rows.get(NOTE_A));
  const before = JSON.stringify([[...store.rows], [...store.backups]]);
  const preview = await call(restore, { body: { id: NOTE_B, preview: true } });
  checks.push({ name: 'note_preview_before_restore', ok: preview.statusCode === 200 && preview.body.action === 'update' && preview.body.backupSha256 === expected
    && preview.body.changes?.title === true && preview.body.changes?.content === true && JSON.stringify([[...store.rows], [...store.backups]]) === before,
  detail: '복원 전에 복원할 버전(사본 해시)과 바뀔 항목을 보여 주고 아무것도 바꾸지 않음' });
  const restored = await call(restore, { body: { id: NOTE_B } });
  const row = store.rows.get(NOTE_B);
  const rowHash = row ? noteContentSha256(row.title, row.content) : null;
  checks.push({ name: 'note_tampered_restored_and_reread', ok: restored.statusCode === 200 && restored.body.restored === 'updated'
    && row?.id === NOTE_B && row?.owner_id === USER_B && rowHash === expected, detail: '변조된 B 메모를 복원한 뒤 다시 읽어 ID·소유자·내용 해시가 사본과 같음' });
  checks.push({ name: 'note_other_untouched', ok: JSON.stringify(store.rows.get(NOTE_A)) === otherBefore && store.backups.get(NOTE_B).content_sha256 === expected, detail: '지정한 한 건 밖의 메모와 사본은 그대로' });

  // 삭제 → 복원
  await call(notes.item, { method: 'DELETE', query: { id: NOTE_B } });
  const recreated = await call(restore, { body: { id: NOTE_B } });
  const again = store.rows.get(NOTE_B);
  checks.push({ name: 'note_deleted_restored_and_reread', ok: recreated.statusCode === 200 && recreated.body.restored === 'recreated'
    && again?.owner_id === USER_B && noteContentSha256(again.title, again.content) === expected, detail: '지운 B 메모를 같은 ID·소유자·내용으로 되살림' });

  // 멈춰야 하는 경우
  const snap = () => JSON.stringify([[...store.rows], [...store.backups]]);
  let mark = snap();
  const stranger = await call(restore, { who: USER_A, body: { id: NOTE_B } });
  checks.push({ name: 'note_other_user_refused', ok: stranger.statusCode === 404 && snap() === mark, detail: '남이 B 메모 복원을 요청하면 404, 아무것도 바뀌지 않음' });
  await call(notes.item, { method: 'PUT', query: { id: NOTE_B }, body: { title: '다시 변조', body: '다시 변조' } });
  store.backups.get(NOTE_B).content = '사본이 몰래 바뀜';
  mark = snap();
  const corrupt = await call(restore, { body: { id: NOTE_B } });
  checks.push({ name: 'note_corrupt_backup_stops', ok: corrupt.statusCode === 409 && snap() === mark, detail: '사본 검증에 실패하면 복원하지 않고 409로 멈춤' });
  const anonymous = await call(restore, { who: null, body: { id: NOTE_B } });
  const missing = await call(restore, { body: { id: '99999999-9999-4999-8999-999999999999' } });
  checks.push({ name: 'note_missing_or_anonymous_stops', ok: anonymous.statusCode === 401 && missing.statusCode === 404, detail: '로그인 없으면 401, 사본이 없으면 404로 멈춤' });
}

// ---------- 실행과 기록 ----------
export async function runDrill({ snapshotFile = DEFAULT_SNAPSHOT, recordFile = DEFAULT_RECORD, now = () => new Date(), write = true } = {}) {
  const checks = [];
  let snapshot = null;
  try { snapshot = await policyDrill(checks, { snapshotFile }); } catch (error) {
    checks.push({ name: 'policy_drill_error', ok: false, detail: `정책 훈련 중 오류: ${String(error?.message ?? '').slice(0, 80)}` });
  }
  try { await notesDrill(checks); } catch (error) {
    checks.push({ name: 'note_drill_error', ok: false, detail: `메모 훈련 중 오류: ${String(error?.message ?? '').slice(0, 80)}` });
  }
  const entry = {
    at: now().toISOString(),
    snapshot: snapshot ? { version: snapshot.version, sha256: snapshot.sha256, commit: snapshot.source.commit } : null,
    ok: checks.length > 0 && checks.every(check => check.ok),
    passed: checks.filter(check => check.ok).length, total: checks.length,
    checks,
  };
  if (write) {
    let record = { schema: 'aleph.restore-drill.v1', note: '백업에서 실제로 복원되는지 시험한 기록입니다. 새 결과는 runs 끝에 덧붙이고 이전 기록은 지우지 않습니다.', runs: [] };
    try {
      const old = JSON.parse(await readFile(recordFile, 'utf8'));
      if (old?.schema === record.schema && Array.isArray(old.runs)) record = old;
    } catch { /* 처음 기록 */ }
    record.runs.push(entry);
    await mkdir(dirname(recordFile), { recursive: true });
    await writeFile(recordFile, `${JSON.stringify(record, null, 2)}\n`);
  }
  return entry;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const noWrite = process.argv.includes('--no-write');
  try {
    const entry = await runDrill({ write: !noWrite });
    for (const check of entry.checks) process.stdout.write(`${check.ok ? '통과' : '실패'} · ${check.name} · ${check.detail}\n`);
    process.stdout.write(`복원 훈련: ${entry.passed}/${entry.total} 통과${entry.snapshot ? ` (정책 사본 ${entry.snapshot.version}, 지문 ${entry.snapshot.sha256.slice(0, 12)})` : ''}\n`);
    process.stdout.write(noWrite ? '기록하지 않았습니다(--no-write).\n' : '결과를 policy/restore-drill.json 끝에 덧붙였습니다(이전 기록은 그대로).\n');
    process.exitCode = entry.ok ? 0 : 1;
  } catch (error) {
    process.stderr.write(`복원 훈련 첫 오류: ${error.message}\n`);
    process.exitCode = 1;
  }
}
