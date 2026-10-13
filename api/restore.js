// POST /api/restore: 로그인한 사람이 자기 메모 한 건을 비공개 사본에서 되돌립니다. 실제 처리는 src/notes-restore.mjs에 있다.
import { defaultRestoreHandler } from '../src/notes-restore.mjs';

export default function handler(request, response) {
  return defaultRestoreHandler()(request, response);
}
