// 로그인한 사람이 자기 가상 메모를 추가·수정·삭제·조회하는 서버 로직.
// - 모든 요청은 먼저 로그인 검사(src/verify-login.mjs)를 통과해야 한다. 통과하지 못하면 자료 없이 401.
// - 추가할 때 owner_id는 요청 내용이 아니라 서버가 확인한 사용자 ID로만 저장한다.
// - 4단계 제작 2: 읽기·수정·삭제는 DB의 owner_id가 서버가 확인한 사용자 ID와 같은 행에만 한다.
//   남의 메모는 없는 메모와 똑같이 404로 답해, 그런 메모가 있는지도 알려 주지 않는다.
//   수정 요청에 owner_id가 들어 있으면 소유자 변경 시도로 보고 403으로 거부한다.
// - SUPABASE_URL과 SUPABASE_SECRET_KEY는 Vercel 환경변수에서만 읽고, 어디에도 내보내지 않는다.
import { randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu;
const MAX_TITLE = 200;
const MAX_BODY = 5000;

const view = row => ({ id: row.id, title: row.title, body: row.content });

// 수정 요청에 이 이름이 있으면 소유자를 바꾸려는 시도로 본다.
const OWNER_FIELDS = ['owner_id', 'ownerId', 'user_id', 'userId'];

function readJsonBody(request) {
  let value = request.body;
  if (typeof value === 'string') {
    try { value = JSON.parse(value); } catch { return null; }
  }
  return value && typeof value === 'object' && !Array.isArray(value) ? value : null;
}

// 제목·본문만 꺼낸다. owner_id, userId, role 같은 값은 요청에 있어도 쓰지 않는다.
function readFields(value) {
  if (typeof value.title !== 'string' || typeof value.body !== 'string') return null;
  const title = value.title.trim();
  if (!title || title.length > MAX_TITLE || value.body.length > MAX_BODY) return null;
  return { title, content: value.body };
}

export function createNotesHandlers({ verifyAuthorization, store }) {
  function prepare(request, response, allowed) {
    response.setHeader('Cache-Control', 'no-store');
    response.setHeader('Vary', 'Authorization');
    if (!allowed.includes(request.method)) {
      response.setHeader('Allow', allowed.join(', '));
      response.status(405).json({ error: 'METHOD_NOT_ALLOWED' });
      return false;
    }
    return true;
  }

  async function login(request, response) {
    let identity = null;
    try {
      identity = await verifyAuthorization(request.headers?.authorization);
    } catch {
      console.error('notes: 로그인 검사를 끝내지 못했습니다.');
    }
    if (!identity) {
      response.setHeader('WWW-Authenticate', 'Bearer');
      response.status(401).json({ error: 'LOGIN_REQUIRED' });
      return null;
    }
    return identity;
  }

  function failed(response, error) {
    console.error('notes: 처리하지 못했습니다.', String(error?.message ?? '').slice(0, 40));
    return response.status(500).json({ error: 'NOTES_UNAVAILABLE' });
  }

  async function collection(request, response) {
    if (!prepare(request, response, ['GET', 'POST'])) return;
    const identity = await login(request, response);
    if (!identity) return;
    try {
      if (request.method === 'GET') {
        const rows = await store.list(identity.userId);
        return response.status(200).json(rows.map(view));
      }
      const value = readJsonBody(request);
      const fields = value && readFields(value);
      if (!fields) return response.status(400).json({ error: 'INVALID_NOTE' });
      let id = randomUUID();
      if (value.id !== undefined) {
        if (typeof value.id !== 'string' || !UUID.test(value.id)) {
          return response.status(400).json({ error: 'INVALID_NOTE' });
        }
        id = value.id.toLowerCase();
      }
      const result = await store.create({ id, ownerId: identity.userId, ...fields });
      if (result?.conflict) return response.status(409).json({ error: 'ID_IN_USE' });
      return response.status(201).json({ id });
    } catch (error) {
      return failed(response, error);
    }
  }

  async function item(request, response) {
    if (!prepare(request, response, ['GET', 'PUT', 'DELETE'])) return;
    const identity = await login(request, response);
    if (!identity) return;
    const raw = request.query?.id;
    const id = typeof raw === 'string' ? raw.toLowerCase() : '';
    if (!UUID.test(id)) return response.status(400).json({ error: 'INVALID_ID' });
    try {
      if (request.method === 'GET') {
        const row = await store.get(id, identity.userId);
        return row ? response.status(200).json(view(row)) : response.status(404).json({ error: 'NOT_FOUND' });
      }
      if (request.method === 'DELETE') {
        const row = await store.remove(id, identity.userId);
        return row ? response.status(200).json({ id }) : response.status(404).json({ error: 'NOT_FOUND' });
      }
      const value = readJsonBody(request);
      if (value && OWNER_FIELDS.some(name => name in value)) {
        return response.status(403).json({ error: 'OWNER_CHANGE_FORBIDDEN' });
      }
      const fields = value && readFields(value);
      if (!fields || (value.id !== undefined && String(value.id).toLowerCase() !== id)) {
        return response.status(400).json({ error: 'INVALID_NOTE' });
      }
      const row = await store.update(id, identity.userId, fields);
      return row ? response.status(200).json(view(row)) : response.status(404).json({ error: 'NOT_FOUND' });
    } catch (error) {
      return failed(response, error);
    }
  }

  return { collection, item };
}

let loginVerifier;

export async function defaultVerifyAuthorization(authorization) {
  if (!loginVerifier) {
    const { createLoginVerifier } = await import('./verify-login.mjs');
    const config = JSON.parse(
      readFileSync(new URL('../aleph.config.json', import.meta.url), 'utf8'),
    );
    loginVerifier = createLoginVerifier({
      config,
      supabaseSecretKey: process.env.SUPABASE_SECRET_KEY,
    });
  }
  return loginVerifier(authorization);
}

export function createSupabaseStore() {
  let db;
  async function table() {
    if (!db) {
      const url = process.env.SUPABASE_URL;
      const key = process.env.SUPABASE_SECRET_KEY;
      if (!url || !key) throw new Error('missing_env');
      const { createClient } = await import('@supabase/supabase-js');
      db = createClient(url, key, { auth: { persistSession: false, autoRefreshToken: false } });
    }
    return db.from('notes');
  }
  const fail = error => { throw new Error(`db_failed:${error.code ?? 'unknown'}`); };
  const columns = 'id, title, content';

  return {
    // 아래 list·get·update·remove는 모두 owner_id가 로그인한 사용자와 같은 행에만 적용한다.
    async list(ownerId) {
      const { data, error } = await (await table()).select(columns).eq('owner_id', ownerId).order('created_at', { ascending: true });
      if (error) fail(error);
      return data;
    },
    async get(id, ownerId) {
      const { data, error } = await (await table()).select(columns).eq('id', id).eq('owner_id', ownerId).maybeSingle();
      if (error) fail(error);
      return data;
    },
    async create({ id, ownerId, title, content }) {
      const { error } = await (await table()).insert({ id, owner_id: ownerId, title, content });
      if (error?.code === '23505') return { conflict: true };
      if (error) fail(error);
      return { conflict: false };
    },
    async update(id, ownerId, { title, content }) {
      const { data, error } = await (await table()).update({ title, content }).eq('id', id).eq('owner_id', ownerId).select(columns).maybeSingle();
      if (error) fail(error);
      return data;
    },
    async remove(id, ownerId) {
      const { data, error } = await (await table()).delete().eq('id', id).eq('owner_id', ownerId).select('id').maybeSingle();
      if (error) fail(error);
      return data;
    },
  };
}

let defaults;
export function defaultNotesHandlers() {
  defaults ??= createNotesHandlers({
    verifyAuthorization: defaultVerifyAuthorization,
    store: createSupabaseStore(),
  });
  return defaults;
}
