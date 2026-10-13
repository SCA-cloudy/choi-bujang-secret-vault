import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createNotesHandlers } from '../src/notes-api.mjs';

const A = '11111111-1111-4111-8111-111111111111';
const B = '22222222-2222-4222-8222-222222222222';
const ID1 = '33333333-3333-4333-8333-333333333333';

function fakeResponse() {
  return {
    statusCode: null, body: null, headers: {},
    setHeader(name, value) { this.headers[name] = value; },
    status(code) { this.statusCode = code; return this; },
    json(body) { this.body = body; return this; },
  };
}

// 메모리 안에서만 도는 가짜 저장소. 진짜 저장소처럼 owner_id가 같은 행에만 적용한다.
function memoryStore(seed = []) {
  const rows = new Map(seed.map(row => [row.id, { ...row }]));
  const mine = (id, ownerId) => {
    const row = rows.get(id);
    return row && row.owner_id === ownerId ? row : null;
  };
  return {
    rows,
    async list(ownerId) { return [...rows.values()].filter(row => row.owner_id === ownerId); },
    async get(id, ownerId) { return mine(id, ownerId); },
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
    async remove(id, ownerId) {
      const row = mine(id, ownerId);
      if (!row) return null;
      rows.delete(id);
      return { id };
    },
  };
}

const TOKENS = { 'Bearer a.a.a': { kind: 'student', userId: A }, 'Bearer b.b.b': { kind: 'student', userId: B } };

function build(seed) {
  const store = memoryStore(seed);
  const handlers = createNotesHandlers({
    verifyAuthorization: async authorization => TOKENS[authorization] ?? null,
    store,
  });
  return { handlers, store };
}

async function call(fn, { method = 'GET', token = 'Bearer a.a.a', body, query } = {}) {
  const response = fakeResponse();
  await fn({ method, headers: token ? { authorization: token } : {}, body, query }, response);
  return response;
}

test('로그인 없는 요청은 모든 경로·방식에서 401이고 저장소를 건드리지 않는다', async () => {
  const { handlers, store } = build([{ id: ID1, owner_id: B, title: 't', content: 'c' }]);
  const before = JSON.stringify([...store.rows]);
  for (const token of [null, 'Bearer bad.bad.bad']) {
    for (const method of ['GET', 'POST']) {
      const r = await call(handlers.collection, { method, token, body: { title: 'x', body: 'y' } });
      assert.equal(r.statusCode, 401);
      assert.deepEqual(r.body, { error: 'LOGIN_REQUIRED' });
    }
    for (const method of ['GET', 'PUT', 'DELETE']) {
      const r = await call(handlers.item, { method, token, query: { id: ID1 }, body: { title: 'x', body: 'y' } });
      assert.equal(r.statusCode, 401);
    }
  }
  assert.equal(JSON.stringify([...store.rows]), before);
});

test('로그인 검사 중 예외가 나도 열어 주지 않는다', async () => {
  const handlers = createNotesHandlers({
    verifyAuthorization: async () => { throw new Error('boom'); },
    store: memoryStore(),
  });
  const original = console.error;
  console.error = () => {};
  try {
    const r = await call(handlers.collection);
    assert.equal(r.statusCode, 401);
  } finally { console.error = original; }
});

test('A가 메모를 추가하면 서버가 확인한 A의 ID가 owner_id로 저장된다', async () => {
  const { handlers, store } = build();
  const r = await call(handlers.collection, {
    method: 'POST',
    body: { title: '첫 메모', body: '내용', owner_id: B, userId: B, role: 'admin' },
  });
  assert.equal(r.statusCode, 201);
  assert.match(r.body.id, /^[0-9a-f-]{36}$/u);
  assert.equal(store.rows.get(r.body.id).owner_id, A);
  assert.equal(store.rows.get(r.body.id).title, '첫 메모');
});

test('id를 직접 주면 그 UUID를 쓰고, 이미 있는 id로는 덮어쓰지 않는다(409)', async () => {
  const { handlers, store } = build([{ id: ID1, owner_id: B, title: '원래', content: '원래' }]);
  const fresh = '44444444-4444-4444-8444-444444444444';
  const ok = await call(handlers.collection, { method: 'POST', body: { id: fresh, title: 't', body: 'b' } });
  assert.equal(ok.statusCode, 201);
  assert.deepEqual(ok.body, { id: fresh });
  const dup = await call(handlers.collection, { method: 'POST', body: { id: ID1, title: '탈취', body: 'x' } });
  assert.equal(dup.statusCode, 409);
  assert.equal(store.rows.get(ID1).title, '원래');
  assert.equal(store.rows.get(ID1).owner_id, B);
});

test('잘못된 입력은 400이다', async () => {
  const { handlers } = build();
  const bad = [
    {}, { title: '', body: 'b' }, { title: 't' }, { title: 5, body: 'b' },
    { title: 'x'.repeat(201), body: 'b' }, { title: 't', body: 'x'.repeat(5001) },
    { id: 'not-a-uuid', title: 't', body: 'b' }, 'text', [1], null,
  ];
  for (const body of bad) {
    const r = await call(handlers.collection, { method: 'POST', body });
    assert.equal(r.statusCode, 400, JSON.stringify(body));
  }
  const badId = await call(handlers.item, { query: { id: 'abc' } });
  assert.equal(badId.statusCode, 400);
});

test('목록은 {id,title,body} 배열이고, 한 건 조회·수정·삭제가 된다', async () => {
  const { handlers } = build();
  const created = await call(handlers.collection, { method: 'POST', body: { title: '제목', body: '본문' } });
  const id = created.body.id;

  const list = await call(handlers.collection);
  assert.equal(list.statusCode, 200);
  assert.ok(Array.isArray(list.body));
  assert.deepEqual(list.body, [{ id, title: '제목', body: '본문' }]);

  const one = await call(handlers.item, { query: { id } });
  assert.deepEqual(one.body, { id, title: '제목', body: '본문' });

  const put = await call(handlers.item, { method: 'PUT', query: { id }, body: { id, title: '고침', body: '새 본문' } });
  assert.equal(put.statusCode, 200);
  assert.deepEqual(put.body, { id, title: '고침', body: '새 본문' });
  assert.deepEqual((await call(handlers.item, { query: { id } })).body, { id, title: '고침', body: '새 본문' });

  const del = await call(handlers.item, { method: 'DELETE', query: { id } });
  assert.equal(del.statusCode, 200);
  assert.equal((await call(handlers.item, { query: { id } })).statusCode, 404);
  assert.equal((await call(handlers.item, { method: 'DELETE', query: { id } })).statusCode, 404);
  assert.equal((await call(handlers.item, { method: 'PUT', query: { id }, body: { title: 'a', body: 'b' } })).statusCode, 404);
});

test('PUT 본문의 id가 주소의 id와 다르면 400이다', async () => {
  const { handlers } = build([{ id: ID1, owner_id: A, title: 't', content: 'c' }]);
  const other = '55555555-5555-4555-8555-555555555555';
  const r = await call(handlers.item, { method: 'PUT', query: { id: ID1 }, body: { id: other, title: 'a', body: 'b' } });
  assert.equal(r.statusCode, 400);
});

test('B는 A의 메모를 읽거나 고치거나 지울 수 없고, 없는 메모와 같은 404를 받는다', async () => {
  const { handlers, store } = build([{ id: ID1, owner_id: A, title: 'A의 메모', content: 'c' }]);
  const b = { token: 'Bearer b.b.b', query: { id: ID1 } };
  const read = await call(handlers.item, b);
  assert.equal(read.statusCode, 404);
  assert.deepEqual(read.body, { error: 'NOT_FOUND' });
  const put = await call(handlers.item, { ...b, method: 'PUT', body: { title: '탈취', body: 'x' } });
  assert.equal(put.statusCode, 404);
  const del = await call(handlers.item, { ...b, method: 'DELETE' });
  assert.equal(del.statusCode, 404);
  assert.deepEqual(store.rows.get(ID1), { id: ID1, owner_id: A, title: 'A의 메모', content: 'c' });
  const list = await call(handlers.collection, { token: 'Bearer b.b.b' });
  assert.deepEqual(list.body, []);
});

test('A와 B는 각자 자기 메모를 추가·조회·수정·삭제하고 목록에는 자기 것만 보인다', async () => {
  const { handlers } = build();
  const ids = {};
  for (const [who, token] of [['a', 'Bearer a.a.a'], ['b', 'Bearer b.b.b']]) {
    const created = await call(handlers.collection, { method: 'POST', token, body: { title: `${who}의 제목`, body: `${who}의 본문` } });
    assert.equal(created.statusCode, 201);
    ids[who] = created.body.id;
  }
  for (const [who, token] of [['a', 'Bearer a.a.a'], ['b', 'Bearer b.b.b']]) {
    const list = await call(handlers.collection, { token });
    assert.deepEqual(list.body, [{ id: ids[who], title: `${who}의 제목`, body: `${who}의 본문` }]);
    const put = await call(handlers.item, { method: 'PUT', token, query: { id: ids[who] }, body: { title: '고침', body: '새 본문' } });
    assert.deepEqual(put.body, { id: ids[who], title: '고침', body: '새 본문' });
    const one = await call(handlers.item, { token, query: { id: ids[who] } });
    assert.deepEqual(one.body, { id: ids[who], title: '고침', body: '새 본문' });
    const del = await call(handlers.item, { method: 'DELETE', token, query: { id: ids[who] } });
    assert.equal(del.statusCode, 200);
    assert.equal((await call(handlers.item, { token, query: { id: ids[who] } })).statusCode, 404);
  }
});

test('수정 요청에 owner_id가 있으면 소유자 변경 시도로 403이고, 메모는 그대로이다', async () => {
  const { handlers, store } = build([{ id: ID1, owner_id: A, title: '원래', content: '원래' }]);
  for (const body of [
    { title: 'x', body: 'y', owner_id: B },
    { title: 'x', body: 'y', ownerId: B },
    { title: 'x', body: 'y', owner_id: A },
  ]) {
    const mine = await call(handlers.item, { method: 'PUT', query: { id: ID1 }, body });
    assert.equal(mine.statusCode, 403);
    assert.deepEqual(mine.body, { error: 'OWNER_CHANGE_FORBIDDEN' });
    const theirs = await call(handlers.item, { method: 'PUT', token: 'Bearer b.b.b', query: { id: ID1 }, body });
    assert.equal(theirs.statusCode, 403);
  }
  assert.deepEqual(store.rows.get(ID1), { id: ID1, owner_id: A, title: '원래', content: '원래' });
});

test('허용하지 않는 방식은 로그인 검사 전에 405이다', async () => {
  const { handlers } = build();
  const c = await call(handlers.collection, { method: 'DELETE', token: null });
  assert.equal(c.statusCode, 405);
  assert.equal(c.headers.Allow, 'GET, POST');
  const i = await call(handlers.item, { method: 'POST', token: null, query: { id: ID1 } });
  assert.equal(i.statusCode, 405);
  assert.equal(i.headers['Cache-Control'], 'no-store');
});

test('저장소 오류는 500이고 오류 내용을 응답에 담지 않는다', async () => {
  const store = memoryStore();
  store.list = async () => { throw new Error('db_failed:SECRET-DETAIL'); };
  const handlers = createNotesHandlers({ verifyAuthorization: async () => ({ kind: 'student', userId: A }), store });
  const original = console.error;
  console.error = () => {};
  try {
    const r = await call(handlers.collection);
    assert.equal(r.statusCode, 500);
    assert.deepEqual(r.body, { error: 'NOTES_UNAVAILABLE' });
  } finally { console.error = original; }
});

// 8단계 제작 3: 저장소가 잘못 답해도(남의 행을 돌려줘도) 서버가 owner_id를 한 번 더 대조해 응답에 담지 않는다.
function leakyStore(seed) {
  const base = memoryStore(seed);
  const calls = [];
  return {
    ...base,
    calls,
    async list() { return [...base.rows.values()]; },
    async get(id) { return base.rows.get(id) ?? null; },
    async update(...args) { calls.push('update'); return base.update(...args); },
    async remove(...args) { calls.push('remove'); return base.remove(...args); },
  };
}

function captureErrors(fn) {
  const lines = [];
  const original = console.error;
  console.error = (...args) => { lines.push(args.join(' ')); };
  return fn().then(result => ({ result, lines }), error => { throw error; }).finally(() => { console.error = original; });
}

test('저장소가 남의 메모를 돌려줘도 목록·조회에 나오지 않고, 수정·삭제는 저장소에 닿지 않는다', async () => {
  const seed = [{ id: ID1, owner_id: A, title: 'A의 메모', content: '비공개 본문' }];
  const store = leakyStore(seed);
  const handlers = createNotesHandlers({ verifyAuthorization: async authorization => TOKENS[authorization] ?? null, store });
  const b = { token: 'Bearer b.b.b', query: { id: ID1 } };
  const { result, lines } = await captureErrors(async () => ({
    list: await call(handlers.collection, { token: 'Bearer b.b.b' }),
    read: await call(handlers.item, b),
    put: await call(handlers.item, { ...b, method: 'PUT', body: { title: '탈취', body: 'x' } }),
    del: await call(handlers.item, { ...b, method: 'DELETE' }),
  }));
  assert.deepEqual(result.list.body, []);
  for (const key of ['read', 'put', 'del']) {
    assert.equal(result[key].statusCode, 404, key);
    assert.deepEqual(result[key].body, { error: 'NOT_FOUND' });
  }
  assert.deepEqual(store.calls, []);
  assert.deepEqual(store.rows.get(ID1), seed[0]);
  assert.ok(lines.some(line => line.includes('거부 사유=NOT_OWNER')));
  const written = lines.join('\n');
  assert.ok(!written.includes(A) && !written.includes(B) && !written.includes('비공개 본문') && !written.includes('Bearer'));
});

test('본문·쿼리·헤더에 role이나 강사 표시를 넣어도 다른 구역 자료는 나오지 않는다', async () => {
  const { handlers, store } = build([{ id: ID1, owner_id: A, title: 'A의 메모', content: 'c' }]);
  const claims = { role: 'instructor', is_instructor: true, user_id: A };
  const send = async (extra) => {
    const response = fakeResponse();
    await handlers.item({ method: extra.method ?? 'GET', headers: { authorization: 'Bearer b.b.b', 'x-role': 'instructor', 'x-user-role': 'admin' },
      body: extra.body, query: { id: ID1, role: 'instructor', as: A } }, response);
    return response;
  };
  assert.equal((await send({})).statusCode, 404);
  assert.equal((await send({ method: 'PUT', body: { title: 'x', body: 'y', role: 'instructor', is_instructor: true } })).statusCode, 404);
  assert.equal((await send({ method: 'DELETE', body: claims })).statusCode, 404);
  assert.equal(store.rows.get(ID1).title, 'A의 메모');
  const created = await call(handlers.collection, { method: 'POST', token: 'Bearer b.b.b', body: { title: '새 메모', body: 'z', role: 'instructor' } });
  assert.equal(created.statusCode, 201);
  assert.equal(store.rows.get(created.body.id).owner_id, B);
});

test('내 메모의 정상 읽기·수정·삭제는 그대로 된다', async () => {
  const { handlers } = build([{ id: ID1, owner_id: A, title: 'A의 메모', content: 'c' }]);
  const a = { query: { id: ID1 } };
  assert.equal((await call(handlers.item, a)).statusCode, 200);
  assert.equal((await call(handlers.item, { ...a, method: 'PUT', body: { title: '고침', body: 'd' } })).statusCode, 200);
  assert.equal((await call(handlers.item, { ...a, method: 'DELETE' })).statusCode, 200);
});
