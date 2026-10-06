// /api/auth/login: 실제 처리는 src/auth-api.mjs에 있다. 화면은 Supabase를 직접 부르지 않는다.
import { defaultAuthHandlers } from '../../src/auth-api.mjs';

export default function handler(request, response) {
  return defaultAuthHandlers().login(request, response);
}
