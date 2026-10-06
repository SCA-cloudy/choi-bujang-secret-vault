// /api/notes/:id: 한 건 조회(GET)·수정(PUT)·삭제(DELETE). 실제 처리는 src/notes-api.mjs에 있다.
import { defaultNotesHandlers } from '../../src/notes-api.mjs';

export default function handler(request, response) {
  return defaultNotesHandlers().item(request, response);
}
