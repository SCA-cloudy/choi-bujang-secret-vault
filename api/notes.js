// /api/notes: 목록 조회(GET)와 추가(POST). 실제 처리는 src/notes-api.mjs에 있다.
import { defaultNotesHandlers } from '../src/notes-api.mjs';

export default function handler(request, response) {
  return defaultNotesHandlers().collection(request, response);
}
