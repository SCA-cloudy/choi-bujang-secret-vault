// 로그인한 사람이 자기 가상 메모를 추가·수정·삭제·조회하는 서버 로직.
// - 모든 요청은 먼저 로그인 검사(src/verify-login.mjs)를 통과해야 한다. 통과하지 못하면 자료 없이 401.
// - 추가할 때 owner_id는 요청 내용이 아니라 서버가 확인한 사용자 ID로만 저장한다.
// - 4단계 제작 2: 읽기·수정·삭제는 DB의 owner_id가 서버가 확인한 사용자 ID와 같은 행에만 한다.
//   남의 메모는 없는 메모와 똑같이 404로 답해, 그런 메모가 있는지도 알려 주지 않는다.
//   수정 요청에 owner_id가 들어 있으면 소유자 변경 시도로 보고 403으로 거부한다.
// - 8단계 제작 3: 저장소가 알려 준 owner_id를 서버가 확인한 로그인 사용자 ID와 한 번 더 대조한다.
//   요청 본문·쿼리·헤더·화면 메뉴의 role, 강사 표시 같은 값은 읽지 않는다. 어긋난 행은 응답에 담지 않고,
//   거부 사유 코드(NOT_OWNER 등)만 짧게 서버 기록에 남긴다. 사용자 ID·토큰·메모 내용은 기록하지 않는다.
// - 10단계 제작 3: 메모를 새로 만들 때 서버가 비공개 사본(notes_backup) 한 벌을 함께 저장한다(고치거나 지우지 않는 첫 한 벌).
//   사본 저장에 실패해도 메모 추가는 막지 않고 이유 코드만 기록한다. 복구는 src/notes-restore.mjs가 맡는다.
// - SUPABASE_URL과 SUPABASE_SECRET_KEY는 Vercel 환경변수에서만 읽고, 어디에도 내보내지 않는다.
import { randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { requireDevice } from './device-auth.mjs';
import { noteContentSha256 } from './note-backup.mjs';

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

// deviceCheck: 기본은 승인된 기기의 요청 서명 확인(requireDevice). 메모 논리만 보는 시험에서만 다른 함수를 넣는다.
export function createNotesHandlers({ verifyAuthorization, store, deviceStore, now,
  deviceCheck = (request, response, identity) => requireDevice(request, response, identity, { store: deviceStore ?? store, now }) }) {
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

  // 저장된 owner_id가 로그인한 사용자와 같을 때만 참. owner_id가 없거나 다르면 거짓(닫힌 쪽으로 판단).
  const owns = (row, identity) => typeof row?.owner_id === 'string' && row.owner_id === identity.userId;
  const refuse = reason => console.error(`notes: 거부 사유=${reason}`);

  function failed(response, error) {
    console.error('notes: 처리하지 못했습니다.', String(error?.message ?? '').slice(0, 40));
    return response.status(500).json({ error: 'NOTES_UNAVAILABLE' });
  }

  async function collection(request, response) {
    if (!prepare(request, response, ['GET', 'POST'])) return;
    const identity = await login(request, response);
    if (!identity) return;
    // 11단계: 로그인 다음에 승인된 기기의 요청 서명을 확인한다. 통과하지 못하면 403이고 자료를 주지 않는다.
    if (!(await deviceCheck(request, response, identity))) return;
    try {
      if (request.method === 'GET') {
        const rows = await store.list(identity.userId);
        const mine = rows.filter(row => owns(row, identity));
        if (mine.length !== rows.length) refuse('NOT_OWNER');
        return response.status(200).json(mine.map(view));
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
      try {
        await store.saveBackup?.({ id, ownerId: identity.userId, ...fields, sha256: noteContentSha256(fields.title, fields.content) });
      } catch {
        console.error('notes: 백업 실패=BACKUP_SAVE_FAILED');
      }
      return response.status(201).json({ id });
    } catch (error) {
      return failed(response, error);
    }
  }

  async function item(request, response) {
    if (!prepare(request, response, ['GET', 'PUT', 'DELETE'])) return;
    const identity = await login(request, response);
    if (!identity) return;
    // 11단계: 로그인 다음에 승인된 기기의 요청 서명을 확인한다. 통과하지 못하면 403이고 자료를 주지 않는다.
    if (!(await deviceCheck(request, response, identity))) return;
    const raw = request.query?.id;
    const id = typeof raw === 'string' ? raw.toLowerCase() : '';
    if (!UUID.test(id)) return response.status(400).json({ error: 'INVALID_ID' });
    try {
      if (request.method === 'GET') {
        const row = await store.get(id, identity.userId);
        if (row && !owns(row, identity)) refuse('NOT_OWNER');
        return row && owns(row, identity) ? response.status(200).json(view(row)) : response.status(404).json({ error: 'NOT_FOUND' });
      }
      // 수정·삭제 전에 저장된 소유자를 먼저 대조한다. 내 것이 아니면 저장소를 바꾸지 않고, 없는 메모와 같은 404로 답한다.
      const ownedOrRefuse = async () => {
        const current = await store.get(id, identity.userId);
        if (current && owns(current, identity)) return true;
        refuse(current ? 'NOT_OWNER' : 'NOT_FOUND_OR_NOT_OWNER');
        response.status(404).json({ error: 'NOT_FOUND' });
        return false;
      };
      if (request.method === 'DELETE') {
        if (!(await ownedOrRefuse())) return;
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
      if (!(await ownedOrRefuse())) return;
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
  async function client() {
    if (!db) {
      const url = process.env.SUPABASE_URL;
      const key = process.env.SUPABASE_SECRET_KEY;
      if (!url || !key) throw new Error('missing_env');
      const { createClient } = await import('@supabase/supabase-js');
      db = createClient(url, key, { auth: { persistSession: false, autoRefreshToken: false } });
    }
    return db;
  }
  const table = async () => (await client()).from('notes');
  const backupTable = async () => (await client()).from('notes_backup');
  const deviceTable = async () => (await client()).from('devices');
  const fail = error => { throw new Error(`db_failed:${error.code ?? 'unknown'}`); };
  const columns = 'id, owner_id, title, content';

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
    // 10단계: 아래 세 개는 복구(src/notes-restore.mjs)와 사본 저장에만 쓴다.
    // peek: 같은 ID의 메모가 있는지와 그 소유자만 알려 준다(내용은 읽지 않는다). 응답에는 담지 않는다.
    async peek(id) {
      const { data, error } = await (await table()).select('id, owner_id').eq('id', id).maybeSingle();
      if (error) fail(error);
      return data;
    },
    // 사본은 "ID + 로그인한 사용자"로만 찾는다.
    async getBackup(id, ownerId) {
      const { data, error } = await (await backupTable()).select('id, owner_id, title, content, content_sha256').eq('id', id).eq('owner_id', ownerId).maybeSingle();
      if (error) fail(error);
      return data;
    },
    // 12단계: 작전실 요약용 읽기. 로그인한 사용자의 기기와 사본만 읽는다(내용은 서버 안에서 해시 검사에만 쓰고 응답에 넣지 않음).
    async listDevices(ownerId) {
      const { data, error } = await (await deviceTable()).select('device_id, status, requested_at, approved_at').eq('owner_id', ownerId).order('requested_at', { ascending: true });
      if (error) fail(error);
      return data;
    },
    async listBackups(ownerId) {
      const { data, error } = await (await backupTable()).select('id, owner_id, title, content, content_sha256').eq('owner_id', ownerId).order('saved_at', { ascending: true });
      if (error) fail(error);
      return data;
    },
    // 11단계: 기기 표. 서버는 읽기와 승인 대기 등록만 한다(승인은 SQL Editor에서 학생이 직접).
    async getDevice(deviceId) {
      const { data, error } = await (await deviceTable()).select('device_id, owner_id, public_key, status').eq('device_id', deviceId).maybeSingle();
      if (error) fail(error);
      return data;
    },
    async addDevice({ deviceId, ownerId, publicKey, label }) {
      const { error } = await (await deviceTable()).insert({ device_id: deviceId, owner_id: ownerId, public_key: publicKey, label, status: 'pending' });
      if (error) fail(error);
      return { status: 'pending' };
    },
    // 사본은 추가만 한다. 이미 같은 ID의 사본이 있으면 덮어쓰지 않는다(첫 한 벌 유지).
    async saveBackup({ id, ownerId, title, content, sha256 }) {
      const { error } = await (await backupTable()).insert({ id, owner_id: ownerId, title, content, content_sha256: sha256 });
      if (error?.code === '23505') return { exists: true };
      if (error) fail(error);
      return { exists: false };
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
