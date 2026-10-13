// 10단계 제작 3: 메모 사본(백업) 한 건을 검증하는 순수 함수. 파일·네트워크·DB를 쓰지 않습니다.
// - 내용 해시는 "제목 + 0x00 + 내용"을 UTF-8 바이트로 이어 sha256 한 값(소문자 16진수 64자)입니다.
//   Postgres 글자에는 0x00이 들어갈 수 없어서 제목과 내용 사이를 헷갈리게 이을 수 없습니다.
//   supabase/005_notes_backup.sql 의 기존 메모 채우기도 같은 식으로 계산합니다.
import { createHash } from 'node:crypto';

const SHA256 = /^[0-9a-f]{64}$/u;

export function noteContentSha256(title, content) {
  if (typeof title !== 'string' || typeof content !== 'string' || title.includes('\0') || content.includes('\0')) {
    throw new TypeError('invalid_note_text');
  }
  return createHash('sha256').update(title, 'utf8').update('\0', 'utf8').update(content, 'utf8').digest('hex');
}

// 사본 한 건이 "요청한 ID, 로그인한 사용자, 저장된 내용 해시"와 모두 맞을 때만 ok.
// 맞지 않으면 짧은 이유 코드만 돌려줍니다(메모 내용은 담지 않습니다).
export function checkBackupRow(row, { id, ownerId }) {
  if (row === null || typeof row !== 'object') return { ok: false, reason: 'BACKUP_MISSING' };
  if (row.id !== id) return { ok: false, reason: 'ID_MISMATCH' };
  if (typeof ownerId !== 'string' || typeof row.owner_id !== 'string' || row.owner_id !== ownerId) {
    return { ok: false, reason: 'NOT_OWNER' };
  }
  if (typeof row.content_sha256 !== 'string' || !SHA256.test(row.content_sha256)) {
    return { ok: false, reason: 'BACKUP_HASH_INVALID' };
  }
  let actual;
  try { actual = noteContentSha256(row.title, row.content); } catch { return { ok: false, reason: 'BACKUP_HASH_MISMATCH' }; }
  if (actual !== row.content_sha256) return { ok: false, reason: 'BACKUP_HASH_MISMATCH' };
  return { ok: true, sha256: actual };
}
