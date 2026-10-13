// 10단계 제작 3: POST /api/restore — 비공개 백업 표(notes_backup)의 사본으로 "내 메모 한 건"만 되돌립니다.
// - 먼저 로그인 검사를 통과해야 합니다. 통과하지 못하면 아무것도 보여 주지 않고 401입니다.
// - 요청 본문은 {"id": "<메모 ID>"} 하나이고, 쓰지 않고 미리 보기만 하려면 "preview": true 를 더합니다. 소유자·role·그 밖의 값은 읽지 않으며, 소유자 이름이 있으면 403으로 거부합니다.
// - 미리 보기는 사본을 같은 방법으로 검증한 뒤 복원할 버전(사본 해시)과 바뀔 항목만 알려 주고 아무것도 바꾸지 않습니다.
// - 사본은 "요청한 ID + 서버가 확인한 로그인 사용자"로만 찾습니다. 그래서 남의 메모, 없는 사본은 같은 404이고 존재 여부도 알려 주지 않습니다.
// - 되돌리기 전에 사본의 ID·소유자·내용 해시를 대조합니다. 하나라도 다르면 메모를 바꾸지 않습니다.
// - 쓰기 직전에 사본을 한 번 더 읽어 다시 검증합니다. 처음 검증한 사본과 다르거나 읽지 못하면 메모를 바꾸지 않고 409입니다.
// - 같은 ID의 메모가 이미 다른 사람 것이면 거부합니다. 바꾸는 곳은 그 한 행뿐이며 다른 메모, 사본 표, 서버 기록은 지우거나 고치지 않습니다.
// - 되돌린 뒤 메모를 다시 읽어 ID·소유자·내용 해시가 사본과 같은지 확인하고, 다르면 원래 상태로 돌려놓고 실패로 답합니다.
// - 성공 응답에는 복원한 버전(사본 해시), 복구 전 해시, 바뀐 항목(title·content 참/거짓), 다시 읽어 확인했는지(verified)를 담습니다. 제목·본문은 담지 않습니다.
// - 서버 기록에는 짧은 이유 코드만 남기고 사용자 ID·토큰·메모 내용은 남기지 않습니다.
import { checkBackupRow, noteContentSha256 } from './note-backup.mjs';
import { createSupabaseStore, defaultVerifyAuthorization } from './notes-api.mjs';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu;
const OWNER_FIELDS = ['owner_id', 'ownerId', 'user_id', 'userId'];
const log = text => console.error(`notes: ${text}`);

function readJsonBody(request) {
  let value = request.body;
  if (typeof value === 'string') {
    try { value = JSON.parse(value); } catch { return null; }
  }
  return value && typeof value === 'object' && !Array.isArray(value) ? value : null;
}

export function createRestoreHandler({ verifyAuthorization, store }) {
  return async function restore(request, response) {
    response.setHeader('Cache-Control', 'no-store');
    response.setHeader('Vary', 'Authorization');
    if (request.method !== 'POST') {
      response.setHeader('Allow', 'POST');
      return response.status(405).json({ error: 'METHOD_NOT_ALLOWED' });
    }
    let identity = null;
    try {
      identity = await verifyAuthorization(request.headers?.authorization);
    } catch {
      log('로그인 검사를 끝내지 못했습니다.');
    }
    if (!identity) {
      response.setHeader('WWW-Authenticate', 'Bearer');
      return response.status(401).json({ error: 'LOGIN_REQUIRED' });
    }

    const value = readJsonBody(request);
    if (!value) return response.status(400).json({ error: 'INVALID_RESTORE_REQUEST' });
    if (OWNER_FIELDS.some(name => name in value)) return response.status(403).json({ error: 'OWNER_CHANGE_FORBIDDEN' });
    // 허용하는 이름은 id 와, 쓰지 않고 미리 보기만 하는 preview(true/false) 둘뿐이다.
    const keys = Object.keys(value);
    if (!keys.includes('id') || keys.some(name => name !== 'id' && name !== 'preview')) {
      return response.status(400).json({ error: 'INVALID_RESTORE_REQUEST' });
    }
    if ('preview' in value && typeof value.preview !== 'boolean') {
      return response.status(400).json({ error: 'INVALID_RESTORE_REQUEST' });
    }
    if (typeof value.id !== 'string' || !UUID.test(value.id)) return response.status(400).json({ error: 'INVALID_ID' });
    const preview = value.preview === true;
    const id = value.id.toLowerCase();
    const ownerId = identity.userId;

    try {
      const backup = await store.getBackup(id, ownerId);
      const verdict = checkBackupRow(backup, { id, ownerId });
      if (!verdict.ok) {
        log(`복구 거부 사유=${verdict.reason}`);
        return verdict.reason.startsWith('BACKUP_HASH')
          ? response.status(409).json({ error: 'BACKUP_INVALID' })
          : response.status(404).json({ error: 'NOT_FOUND' });
      }
      const live = await store.peek(id);
      if (live && live.owner_id !== ownerId) {
        log('복구 거부 사유=LIVE_OWNED_BY_OTHER');
        return response.status(404).json({ error: 'NOT_FOUND' });
      }
      // 되돌리기 전 값을 복사해 둔다(검증에 실패하면 이 값으로 돌려놓는다).
      const current = live ? await store.get(id, ownerId) : null;
      const prior = current ? { title: current.title, content: current.content } : null;
      const fields = { title: backup.title, content: backup.content };
      // 복구 전 상태: 응답에 복구 전 해시와 바뀔 항목만 담기 위해 쓰기 전에 계산한다(제목·본문은 담지 않는다).
      let previousSha256 = null;
      try { previousSha256 = current ? noteContentSha256(current.title, current.content) : null; } catch { previousSha256 = null; }
      const changes = { title: !current || current.title !== backup.title, content: !current || current.content !== backup.content };
      if (preview) {
        // 실행 전 보여 주기: 사본 검증은 이미 통과했다. 아무것도 쓰지 않고, 본문 대신 해시와 바뀔 항목만 알려 준다.
        let currentSha256 = null;
        try { currentSha256 = current ? noteContentSha256(current.title, current.content) : null; } catch { currentSha256 = null; }
        const action = !current ? 'recreate' : currentSha256 === verdict.sha256 ? 'none' : 'update';
        log(`복구 미리보기=${action}`);
        return response.status(200).json({
          id, preview: true, action, backupSha256: verdict.sha256, currentSha256,
          changes: { title: !current || current.title !== backup.title, content: !current || current.content !== backup.content },
        });
      }
      // 쓰기 직전에 사본을 다시 읽어 같은 방법으로 검증한다. 처음 검증한 사본과 다르거나 읽지 못하면 아무것도 쓰지 않는다.
      let recheck = { ok: false };
      let again = null;
      try {
        again = await store.getBackup(id, ownerId);
        recheck = checkBackupRow(again, { id, ownerId });
      } catch { recheck = { ok: false }; }
      if (!recheck.ok || recheck.sha256 !== verdict.sha256 || again.title !== backup.title || again.content !== backup.content) {
        log('복구 거부 사유=BACKUP_RECHECK_FAILED');
        return response.status(409).json({ error: 'BACKUP_INVALID' });
      }
      let action;
      if (live) {
        if (!(await store.update(id, ownerId, fields))) return response.status(404).json({ error: 'NOT_FOUND' });
        action = 'updated';
      } else {
        const created = await store.create({ id, ownerId, ...fields });
        if (created?.conflict) {
          log('복구 거부 사유=RESTORE_CONFLICT');
          return response.status(409).json({ error: 'RESTORE_CONFLICT' });
        }
        action = 'recreated';
      }
      const after = await store.get(id, ownerId);
      let verified = false;
      try {
        verified = Boolean(after) && after.id === id && after.owner_id === ownerId
          && noteContentSha256(after.title, after.content) === verdict.sha256;
      } catch { verified = false; }
      if (!verified) {
        if (prior) await store.update(id, ownerId, { title: prior.title, content: prior.content });
        else await store.remove(id, ownerId);
        log('복구 거부 사유=RESTORE_VERIFY_FAILED');
        return response.status(500).json({ error: 'RESTORE_FAILED' });
      }
      log(`복구 결과=${action}`);
      // 복원한 버전(사본 해시)·복구 전 해시·바뀐 항목·사본과 같은지 다시 읽어 확인했는지를 알려 준다.
      return response.status(200).json({
        id, restored: action, contentSha256: verdict.sha256,
        backupSha256: verdict.sha256, previousSha256, changes, verified: true,
      });
    } catch (error) {
      log(`처리하지 못했습니다. ${String(error?.message ?? '').slice(0, 40)}`);
      return response.status(500).json({ error: 'NOTES_UNAVAILABLE' });
    }
  };
}

let defaultHandler;
export function defaultRestoreHandler() {
  defaultHandler ??= createRestoreHandler({ verifyAuthorization: defaultVerifyAuthorization, store: createSupabaseStore() });
  return defaultHandler;
}
