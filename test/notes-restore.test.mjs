import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { test } from 'node:test';
import { checkBackupRow, noteContentSha256 } from '../src/note-backup.mjs';
import { createNotesHandlers } from '../src/notes-api.mjs';
import { createRestoreHandler } from '../src/notes-restore.mjs';

// A = 일반 학생 계정, B = 시험 계정. 모든 시험은 가상 메모만 씁니다.
const A = '11111111-1111-4111-8111-111111111111';
const B = '22222222-2222-4222-8222-222222222222';
const IDB = '33333333-3333-4333-8333-333333333333';
const IDA = '44444444-4444-4444-8444-444444444444';
const TOKENS = { 'Bearer a.a.a': { kind: 'student', userId: A }, 'Bearer b.b.b': { kind: 'student', userId: B } };

const fakeResponse = () => ({
  statusCode: null, body: null, headers: {},
  setHeader(name, value) { this.headers[name] = value; },
  status(code) { this.statusCode = code; return this; },
  json(body) { this.body = body; return this; },
});

// 진짜 저장소처럼 메모는 owner_id 가 같은 행에만 적용하고, 사본은 추가만 하며 ID+소유자로만 찾는다.
function memoryStore() {
  const rows = new Map();
  const backups = new Map();
  const mine = (id, ownerId) => (rows.get(id)?.owner_id === ownerId ? rows.get(id) : null);
  return {
    rows, backups, calls: [],
    async list(ownerId) { return [...rows.values()].filter(row => row.owner_id === ownerId); },
    async get(id, ownerId) { return mine(id, ownerId); },
    async peek(id) { const row = rows.get(id); return row ? { id: row.id, owner_id: row.owner_id } : null; },
    async create({ id, ownerId, title, content }) {
      if (rows.has(id)) return { conflict: true };
      rows.set(id, { id, owner_id: ownerId, title, content });
      return { conflict: false };
    },
    async update(id, ownerId, { title, content }) {
      const row = mine(id, ownerId);
      if (!row) return null;
      Object.assign(row, { title, content });
      return row;
    },
    async remove(id, ownerId) { if (!mine(id, ownerId)) return null; rows.delete(id); return { id }; },
    async getBackup(id, ownerId) { const row = backups.get(id); return row?.owner_id === ownerId ? { ...row } : null; },
    async saveBackup({ id, ownerId, title, content, sha256 }) {
      if (backups.has(id)) return { exists: true };
      backups.set(id, { id, owner_id: ownerId, title, content, content_sha256: sha256 });
      return { exists: false };
    },
  };
}

function build(store = memoryStore()) {
  const verifyAuthorization = async authorization => TOKENS[authorization] ?? null;
  return { store, notes: createNotesHandlers({ verifyAuthorization, store }), restore: createRestoreHandler({ verifyAuthorization, store }) };
}
async function call(fn, { method = 'POST', token = 'Bearer b.b.b', body, query } = {}) {
  const response = fakeResponse();
  const silent = console.error; console.error = () => {};
  try { await fn({ method, headers: token ? { authorization: token } : {}, body, query }, response); } finally { console.error = silent; }
  return response;
}
const create = (ctx, { token, id, title, body }) => call(ctx.notes.collection, { token, body: { id, title, body } });
// 시험 계정 B 의 메모를 만들어 사본이 생기게 한다.
async function seedB() {
  const ctx = build();
  assert.equal((await create(ctx, { id: IDB, title: 'B 원본 제목', body: 'B 원본 내용 SAMPLE_B' })).statusCode, 201);
  assert.equal((await create(ctx, { token: 'Bearer a.a.a', id: IDA, title: 'A 메모', body: 'A 내용' })).statusCode, 201);
  return ctx;
}
const snapshotOf = store => JSON.stringify([[...store.rows], [...store.backups]]);

test('내용 해시는 제목+0x00+내용의 sha256이고, 사본 검증은 ID·소유자·해시를 모두 본다', () => {
  // 독립 계산: 제목 바이트 + 0x00 + 내용 바이트의 sha256 (SQL 쪽 채우기와 같은 식)
  assert.equal(noteContentSha256('제목', '내용'), createHash('sha256').update(Buffer.concat([Buffer.from('제목'), Buffer.from([0]), Buffer.from('내용')])).digest('hex'));
  assert.notEqual(noteContentSha256('ab', 'c'), noteContentSha256('a', 'bc')); // 경계가 헷갈리지 않는다
  assert.throws(() => noteContentSha256('a\0b', 'c'));
  const row = { id: IDB, owner_id: B, title: 't', content: 'c', content_sha256: noteContentSha256('t', 'c') };
  assert.deepEqual(checkBackupRow(row, { id: IDB, ownerId: B }), { ok: true, sha256: row.content_sha256 });
  assert.equal(checkBackupRow({ ...row, id: IDA }, { id: IDB, ownerId: B }).reason, 'ID_MISMATCH');
  assert.equal(checkBackupRow(row, { id: IDB, ownerId: A }).reason, 'NOT_OWNER');
  assert.equal(checkBackupRow({ ...row, content: 'x' }, { id: IDB, ownerId: B }).reason, 'BACKUP_HASH_MISMATCH');
  assert.equal(checkBackupRow({ ...row, content_sha256: 'zz' }, { id: IDB, ownerId: B }).reason, 'BACKUP_HASH_INVALID');
  assert.equal(checkBackupRow(null, { id: IDB, ownerId: B }).reason, 'BACKUP_MISSING');
});

test('메모를 만들면 사본이 한 벌 생기고, 같은 ID로 다시 만들려 해도 사본을 덮어쓰지 않는다', async () => {
  const ctx = await seedB();
  const backup = ctx.store.backups.get(IDB);
  assert.deepEqual([backup.id, backup.owner_id, backup.title, backup.content], [IDB, B, 'B 원본 제목', 'B 원본 내용 SAMPLE_B']);
  assert.equal(backup.content_sha256, noteContentSha256('B 원본 제목', 'B 원본 내용 SAMPLE_B'));
  // 수정해도 사본은 그대로
  await call(ctx.notes.item, { method: 'PUT', query: { id: IDB }, body: { title: '바뀐', body: '바뀐 내용' } });
  assert.equal(ctx.store.backups.get(IDB).title, 'B 원본 제목');
  // 같은 ID로 또 만들기는 메모 쪽에서 409라 사본에 닿지 않는다
  assert.equal((await create(ctx, { token: 'Bearer a.a.a', id: IDB, title: '가로채기', body: 'x' })).statusCode, 409);
  assert.equal(ctx.store.backups.get(IDB).owner_id, B);
});

test('사본 저장이 실패해도 메모 추가는 막지 않는다', async () => {
  const store = memoryStore();
  store.saveBackup = async () => { throw new Error('db_failed:42P01'); };
  const ctx = build(store);
  assert.equal((await create(ctx, { id: IDB, title: 't', body: 'c' })).statusCode, 201);
  assert.ok(store.rows.has(IDB));
});

test('시험 계정 B: 메모를 변조한 뒤 복구하면 사본의 ID·소유자·내용 해시와 같아진다', async () => {
  const ctx = await seedB();
  const original = noteContentSha256('B 원본 제목', 'B 원본 내용 SAMPLE_B');
  await call(ctx.notes.item, { method: 'PUT', query: { id: IDB }, body: { title: '변조', body: '변조된 내용' } });
  assert.notEqual(noteContentSha256(ctx.store.rows.get(IDB).title, ctx.store.rows.get(IDB).content), original);
  const other = JSON.stringify(ctx.store.rows.get(IDA));
  const result = await call(ctx.restore, { body: { id: IDB } });
  assert.equal(result.statusCode, 200);
  assert.deepEqual(result.body, { id: IDB, restored: 'updated', contentSha256: original });
  const row = ctx.store.rows.get(IDB);
  assert.deepEqual([row.id, row.owner_id, noteContentSha256(row.title, row.content)], [IDB, B, original]);
  assert.equal(JSON.stringify(ctx.store.rows.get(IDA)), other);   // 다른 메모는 그대로
  assert.equal(ctx.store.backups.get(IDB).content_sha256, original); // 사본도 그대로
  assert.equal(result.headers['Cache-Control'], 'no-store');
});

test('시험 계정 B: 메모를 지운 뒤 복구하면 같은 ID·소유자·내용으로 다시 생긴다', async () => {
  const ctx = await seedB();
  await call(ctx.notes.item, { method: 'DELETE', query: { id: IDB } });
  assert.ok(!ctx.store.rows.has(IDB));
  const result = await call(ctx.restore, { body: { id: IDB.toUpperCase() } });
  assert.equal(result.statusCode, 200);
  assert.equal(result.body.restored, 'recreated');
  const row = ctx.store.rows.get(IDB);
  assert.deepEqual([row.owner_id, row.title, row.content], [B, 'B 원본 제목', 'B 원본 내용 SAMPLE_B']);
  assert.equal(ctx.store.rows.size, 2);
  // 다시 호출해도 같은 결과(이미 같은 내용이면 그대로)
  assert.equal((await call(ctx.restore, { body: { id: IDB } })).body.restored, 'updated');
});

test('남이 B의 메모를 복구하려 하면 404이고 아무것도 바뀌지 않는다', async () => {
  const ctx = await seedB();
  await call(ctx.notes.item, { method: 'PUT', query: { id: IDB }, body: { title: '변조', body: '변조' } });
  const before = snapshotOf(ctx.store);
  for (const body of [{ id: IDB }, { id: '99999999-9999-4999-8999-999999999999' }]) {
    const result = await call(ctx.restore, { token: 'Bearer a.a.a', body });
    assert.equal(result.statusCode, 404);
    assert.deepEqual(result.body, { error: 'NOT_FOUND' });
  }
  assert.equal(snapshotOf(ctx.store), before);
});

test('같은 ID의 메모가 이미 남의 것이면 사본이 있어도 복구하지 않는다', async () => {
  const ctx = await seedB();
  ctx.store.rows.get(IDB).owner_id = A; // 방어 확인: 저장소가 남의 소유로 보여 주는 경우
  const before = snapshotOf(ctx.store);
  const result = await call(ctx.restore, { body: { id: IDB } });
  assert.equal(result.statusCode, 404);
  assert.equal(snapshotOf(ctx.store), before);
});

test('사본의 내용이 바뀌었거나 사본이 없으면 메모를 바꾸지 않는다', async () => {
  const ctx = await seedB();
  await call(ctx.notes.item, { method: 'PUT', query: { id: IDB }, body: { title: '변조', body: '변조' } });
  ctx.store.backups.get(IDB).content = '사본이 몰래 바뀜';
  const before = snapshotOf(ctx.store);
  const broken = await call(ctx.restore, { body: { id: IDB } });
  assert.equal(broken.statusCode, 409);
  assert.deepEqual(broken.body, { error: 'BACKUP_INVALID' });
  ctx.store.backups.delete(IDB);
  const missing = await call(ctx.restore, { body: { id: IDB } });
  assert.equal(missing.statusCode, 404);
  assert.equal(ctx.store.rows.get(IDB).title, '변조');
  assert.notEqual(snapshotOf(ctx.store), before); // (사본을 지운 것은 이 시험이 한 일)
});

test('로그인 없이는 401, 허용 방식은 POST뿐, 본문은 id 하나뿐이다', async () => {
  const ctx = await seedB();
  const before = snapshotOf(ctx.store);
  for (const token of [null, 'Bearer bad.bad.bad']) {
    const r = await call(ctx.restore, { token, body: { id: IDB } });
    assert.equal(r.statusCode, 401);
    assert.deepEqual(r.body, { error: 'LOGIN_REQUIRED' });
  }
  for (const method of ['GET', 'PUT', 'DELETE']) {
    const r = await call(ctx.restore, { method, body: { id: IDB } });
    assert.equal(r.statusCode, 405);
    assert.equal(r.headers.Allow, 'POST');
  }
  const cases = [
    [undefined, 400, 'INVALID_RESTORE_REQUEST'], ['not json', 400, 'INVALID_RESTORE_REQUEST'], [[IDB], 400, 'INVALID_RESTORE_REQUEST'],
    [{}, 400, 'INVALID_RESTORE_REQUEST'], [{ id: IDB, title: 'x' }, 400, 'INVALID_RESTORE_REQUEST'], [{ id: IDB, role: 'admin' }, 400, 'INVALID_RESTORE_REQUEST'],
    [{ id: 'abc' }, 400, 'INVALID_ID'], [{ id: 5 }, 400, 'INVALID_ID'],
    [{ id: IDB, owner_id: A }, 403, 'OWNER_CHANGE_FORBIDDEN'], [{ id: IDB, userId: A }, 403, 'OWNER_CHANGE_FORBIDDEN'],
  ];
  for (const [body, status, error] of cases) {
    const r = await call(ctx.restore, { body });
    assert.deepEqual([r.statusCode, r.body.error], [status, error], JSON.stringify(body));
  }
  assert.equal(snapshotOf(ctx.store), before);
});

test('헤더·쿼리의 role이나 다른 사용자 표시는 읽지 않는다', async () => {
  const ctx = await seedB();
  await call(ctx.notes.item, { method: 'PUT', query: { id: IDB }, body: { title: '변조', body: '변조' } });
  const response = fakeResponse();
  await ctx.restore({ method: 'POST', headers: { authorization: 'Bearer a.a.a', 'x-role': 'admin', 'x-user-id': B }, query: { id: IDB, role: 'admin', owner: B }, body: { id: IDB } }, response);
  assert.equal(response.statusCode, 404);
  assert.equal(ctx.store.rows.get(IDB).title, '변조');
});

test('복구 뒤 다시 읽은 값이 사본과 다르면 원래 상태로 돌려놓고 실패로 답한다', async () => {
  const ctx = await seedB();
  await call(ctx.notes.item, { method: 'PUT', query: { id: IDB }, body: { title: '변조', body: '변조' } });
  const realUpdate = ctx.store.update.bind(ctx.store);
  let first = true;
  ctx.store.update = async (id, ownerId, fields) => {
    if (first) { first = false; return realUpdate(id, ownerId, { title: fields.title, content: '저장 중에 깨진 내용' }); }
    return realUpdate(id, ownerId, fields);
  };
  const result = await call(ctx.restore, { body: { id: IDB } });
  assert.equal(result.statusCode, 500);
  assert.deepEqual(result.body, { error: 'RESTORE_FAILED' });
  assert.deepEqual([ctx.store.rows.get(IDB).title, ctx.store.rows.get(IDB).content], ['변조', '변조']);
});

test('서버 기록에는 이유 코드만 남고 메모 내용·사용자 ID·토큰은 남지 않는다', async () => {
  const ctx = await seedB();
  await call(ctx.notes.item, { method: 'PUT', query: { id: IDB }, body: { title: '변조', body: '변조' } });
  const lines = [];
  const silent = console.error; console.error = (...args) => lines.push(args.join(' '));
  try {
    for (const [token, body] of [['Bearer b.b.b', { id: IDB }], ['Bearer a.a.a', { id: IDB }]]) {
      await ctx.restore({ method: 'POST', headers: { authorization: token }, body }, fakeResponse());
    }
  } finally { console.error = silent; }
  const text = lines.join('\n');
  assert.match(text, /복구 결과=updated/);
  assert.match(text, /복구 거부 사유=BACKUP_MISSING/);
  for (const secret of [A, B, 'SAMPLE_B', '원본', 'Bearer', 'b.b.b']) assert.ok(!text.includes(secret), secret);
});

test('미리 보기: 변조된 메모는 update로 알리고, 복원할 버전과 바뀔 항목만 보여 주며 아무것도 쓰지 않는다', async () => {
  const ctx = await seedB();
  await call(ctx.notes.item, { method: 'PUT', query: { id: IDB }, body: { title: '변조 제목', body: '변조 내용 TAMPERED' } });
  const before = snapshotOf(ctx.store);
  const result = await call(ctx.restore, { body: { id: IDB, preview: true } });
  assert.equal(result.statusCode, 200);
  assert.deepEqual(result.body, {
    id: IDB, preview: true, action: 'update',
    backupSha256: noteContentSha256('B 원본 제목', 'B 원본 내용 SAMPLE_B'),
    currentSha256: noteContentSha256('변조 제목', '변조 내용 TAMPERED'),
    changes: { title: true, content: true },
  });
  assert.equal(snapshotOf(ctx.store), before); // 메모도 사본도 그대로
  const text = JSON.stringify(result.body);
  for (const secret of ['SAMPLE_B', 'TAMPERED', '원본 제목']) assert.ok(!text.includes(secret), secret); // 본문·제목은 응답에 없다
});

test('미리 보기: 지운 메모는 recreate, 이미 같은 메모는 none으로 알리고 다시 만들지 않는다', async () => {
  const ctx = await seedB();
  const same = await call(ctx.restore, { body: { id: IDB, preview: true } });
  assert.equal(same.body.action, 'none');
  assert.deepEqual(same.body.changes, { title: false, content: false });
  assert.equal(same.body.currentSha256, same.body.backupSha256);
  await call(ctx.notes.item, { method: 'DELETE', query: { id: IDB } });
  const before = snapshotOf(ctx.store);
  const gone = await call(ctx.restore, { body: { id: IDB, preview: true } });
  assert.equal(gone.statusCode, 200);
  assert.equal(gone.body.action, 'recreate');
  assert.equal(gone.body.currentSha256, null);
  assert.ok(!ctx.store.rows.has(IDB)); // 미리 보기만으로는 되살아나지 않는다
  assert.equal(snapshotOf(ctx.store), before);
});

test('미리 보기도 실제 복구와 같은 검사를 먼저 통과해야 한다', async () => {
  const ctx = await seedB();
  const before = snapshotOf(ctx.store);
  assert.equal((await call(ctx.restore, { token: null, body: { id: IDB, preview: true } })).statusCode, 401);
  assert.equal((await call(ctx.restore, { token: 'Bearer a.a.a', body: { id: IDB, preview: true } })).statusCode, 404); // 남의 메모
  assert.equal((await call(ctx.restore, { body: { id: IDA, preview: true } })).statusCode, 404);
  assert.equal((await call(ctx.restore, { method: 'GET', body: { id: IDB, preview: true } })).statusCode, 405);
  assert.equal((await call(ctx.restore, { body: { id: IDB, preview: 'yes' } })).statusCode, 400);
  assert.equal((await call(ctx.restore, { body: { id: IDB, preview: true, extra: 1 } })).statusCode, 400);
  assert.equal((await call(ctx.restore, { body: { id: IDB, preview: true, owner_id: A } })).statusCode, 403);
  assert.equal((await call(ctx.restore, { body: { preview: true } })).statusCode, 400);
  // 사본이 변조되어 해시가 맞지 않으면 미리 보기도 409로 멈춘다
  ctx.store.backups.get(IDB).content = '사본 변조';
  const stopped = await call(ctx.restore, { body: { id: IDB, preview: true } });
  assert.equal(stopped.statusCode, 409);
  assert.deepEqual(stopped.body, { error: 'BACKUP_INVALID' });
  ctx.store.backups.get(IDB).content = 'B 원본 내용 SAMPLE_B';
  assert.equal(snapshotOf(ctx.store), before);
  // preview:false 는 실제 복구와 같다
  await call(ctx.notes.item, { method: 'PUT', query: { id: IDB }, body: { title: '변조', body: '변조' } });
  const real = await call(ctx.restore, { body: { id: IDB, preview: false } });
  assert.equal(real.statusCode, 200);
  assert.equal(real.body.restored, 'updated');
});

test('쓰기 직전에 사본을 다시 읽어 검증한다: 실제 복구는 두 번, 미리 보기는 한 번 읽는다', async () => {
  const ctx = await seedB();
  await call(ctx.notes.item, { method: 'PUT', query: { id: IDB }, body: { title: '변조', body: '변조' } });
  const realGet = ctx.store.getBackup.bind(ctx.store);
  let reads = 0;
  ctx.store.getBackup = async (id, ownerId) => { reads += 1; return realGet(id, ownerId); };
  assert.equal((await call(ctx.restore, { body: { id: IDB, preview: true } })).statusCode, 200);
  assert.equal(reads, 1);
  reads = 0;
  const result = await call(ctx.restore, { body: { id: IDB } });
  assert.equal(result.statusCode, 200);
  assert.equal(result.body.restored, 'updated');
  assert.equal(reads, 2);
});

test('다시 읽은 사본이 처음과 다르거나 읽지 못하면 메모를 바꾸지 않고 409로 멈춘다', async () => {
  for (const mode of ['changed', 'tampered', 'throws', 'missing']) {
    const ctx = await seedB();
    await call(ctx.notes.item, { method: 'PUT', query: { id: IDB }, body: { title: '변조', body: '변조' } });
    const realGet = ctx.store.getBackup.bind(ctx.store);
    let reads = 0;
    ctx.store.getBackup = async (id, ownerId) => {
      reads += 1;
      const row = await realGet(id, ownerId);
      if (reads < 2) return row;
      if (mode === 'throws') throw new Error('읽기 실패');
      if (mode === 'missing') return null;
      if (mode === 'tampered') return { ...row, content: '두 번째 읽기에서 바뀐 내용' }; // 해시가 안 맞는 사본
      const other = { title: '다른 제목', content: '다른 내용' };
      return { ...row, ...other, content_sha256: noteContentSha256(other.title, other.content) }; // 해시는 맞지만 처음 사본과 다른 사본
    };
    const before = snapshotOf(ctx.store);
    const result = await call(ctx.restore, { body: { id: IDB } });
    assert.equal(result.statusCode, 409, mode);
    assert.deepEqual(result.body, { error: 'BACKUP_INVALID' }, mode);
    assert.equal(snapshotOf(ctx.store), before, mode); // 메모도 사본도 하나도 바뀌지 않음
  }
});

test('사본을 저장한 직후 다시 읽어 검증하고, 정상이면 아무 경고도 남기지 않는다', async () => {
  const store = memoryStore();
  const realGet = store.getBackup.bind(store);
  let reads = 0;
  store.getBackup = async (id, ownerId) => { reads += 1; return realGet(id, ownerId); };
  const ctx = build(store);
  const lines = [];
  const silent = console.error; console.error = (...args) => lines.push(args.join(' '));
  let result;
  try { result = fakeResponse(); await ctx.notes.collection({ method: 'POST', headers: { authorization: 'Bearer b.b.b' }, body: { id: IDB, title: 'B 원본 제목', body: 'B 원본 내용 SAMPLE_B' } }, result); } finally { console.error = silent; }
  assert.equal(result.statusCode, 201);
  assert.equal(reads, 1);
  assert.ok(!lines.join('\n').includes('BACKUP_'));
});

test('저장 직후 다시 읽은 사본이 틀리거나 읽지 못해도 메모 추가는 막지 않고 이유 코드만 남긴다', async () => {
  for (const mode of ['tampered', 'missing', 'throws']) {
    const store = memoryStore();
    const realGet = store.getBackup.bind(store);
    store.getBackup = async (id, ownerId) => {
      if (mode === 'throws') throw new Error('읽기 실패');
      const row = await realGet(id, ownerId);
      return mode === 'missing' ? null : { ...row, content: '저장 뒤 바뀐 내용' };
    };
    const ctx = build(store);
    const lines = [];
    const silent = console.error; console.error = (...args) => lines.push(args.join(' '));
    let result;
    try { result = fakeResponse(); await ctx.notes.collection({ method: 'POST', headers: { authorization: 'Bearer b.b.b' }, body: { id: IDB, title: 'B 원본 제목', body: 'B 원본 내용 SAMPLE_B' } }, result); } finally { console.error = silent; }
    assert.equal(result.statusCode, 201, mode);
    assert.ok(store.rows.has(IDB), mode);
    const text = lines.join('\n');
    assert.match(text, mode === 'throws' ? /BACKUP_SAVE_FAILED/ : /BACKUP_VERIFY_FAILED/, mode);
    for (const secret of ['SAMPLE_B', '원본', B]) assert.ok(!text.includes(secret), `${mode}:${secret}`);
  }
});
