// 5단계: 로그인·로그인 연장·로그아웃을 서버 함수가 대신 처리한다.
// 화면 코드에는 Supabase 주소와 공개용(publishable) 키를 두지 않는다. 키는 Vercel 환경변수
// SUPABASE_PUBLISHABLE_KEY에만 있고, 서버가 Supabase 로그인 서버에 요청할 때만 쓴다.
// - 비밀번호·토큰은 로그에 남기지 않고, 응답에도 화면이 쓸 값(출입증·만료 시각·이메일)만 담는다.
// - 이 파일은 메모 자료를 다루지 않는다. 메모는 계속 src/notes-api.mjs의 로그인·주인 검사를 거친다.
const MAX_EMAIL = 254;
const MAX_PASSWORD = 200;
const MAX_TOKEN = 4096;

function readJsonBody(request) {
  let value = request.body;
  if (typeof value === 'string') {
    try { value = JSON.parse(value); } catch { return null; }
  }
  return value && typeof value === 'object' && !Array.isArray(value) ? value : null;
}

// 화면이 쓸 값만 골라 낸다. Supabase가 돌려준 나머지 사용자 정보는 내보내지 않는다.
function sessionView(data) {
  if (typeof data?.access_token !== 'string' || typeof data?.refresh_token !== 'string'
      || !Number.isFinite(data?.expires_at)) return null;
  return {
    accessToken: data.access_token,
    refreshToken: data.refresh_token,
    expiresAt: data.expires_at,
    email: typeof data.user?.email === 'string' ? data.user.email : '',
  };
}

export function createAuthHandlers({ env = process.env, fetchImpl = globalThis.fetch } = {}) {
  function prepare(request, response) {
    response.setHeader('Cache-Control', 'no-store');
    if (request.method !== 'POST') {
      response.setHeader('Allow', 'POST');
      response.status(405).json({ error: 'METHOD_NOT_ALLOWED' });
      return false;
    }
    return true;
  }

  // Supabase 로그인 서버에 보낸다. 설정이 없거나 연결이 안 되면 null.
  async function callAuth(path, { body, token } = {}) {
    const url = env.SUPABASE_URL;
    const key = env.SUPABASE_PUBLISHABLE_KEY;
    if (!url || !key) return null;
    const headers = { apikey: key, 'Content-Type': 'application/json' };
    if (token) headers.Authorization = `Bearer ${token}`;
    try {
      const upstream = await fetchImpl(`${url}/auth/v1${path}`, {
        method: 'POST', headers, body: JSON.stringify(body ?? {}),
        redirect: 'error', signal: AbortSignal.timeout(10000),
      });
      const data = await upstream.json().catch(() => null);
      return { status: upstream.status, data };
    } catch {
      return null;
    }
  }

  const unavailable = response => response.status(502).json({ error: 'AUTH_UNAVAILABLE' });

  async function login(request, response) {
    if (!prepare(request, response)) return;
    const value = readJsonBody(request);
    const email = typeof value?.email === 'string' ? value.email.trim() : '';
    const password = typeof value?.password === 'string' ? value.password : '';
    if (!email || email.length > MAX_EMAIL || !password || password.length > MAX_PASSWORD) {
      return response.status(400).json({ error: 'INVALID_LOGIN' });
    }
    const result = await callAuth('/token?grant_type=password', { body: { email, password } });
    if (!result) return unavailable(response);
    const session = result.status === 200 ? sessionView(result.data) : null;
    if (session) return response.status(200).json(session);
    if (result.status === 429) return response.status(429).json({ error: 'TOO_MANY_ATTEMPTS' });
    const reason = result.data?.error_code ?? result.data?.code;
    if (reason === 'email_not_confirmed') return response.status(401).json({ error: 'EMAIL_NOT_CONFIRMED' });
    if (result.status >= 400 && result.status < 500) return response.status(401).json({ error: 'INVALID_CREDENTIALS' });
    return unavailable(response);
  }

  async function refresh(request, response) {
    if (!prepare(request, response)) return;
    const value = readJsonBody(request);
    const refreshToken = typeof value?.refreshToken === 'string' ? value.refreshToken : '';
    if (!refreshToken || refreshToken.length > MAX_TOKEN) {
      return response.status(400).json({ error: 'INVALID_REFRESH' });
    }
    const result = await callAuth('/token?grant_type=refresh_token', { body: { refresh_token: refreshToken } });
    if (!result) return unavailable(response);
    const session = result.status === 200 ? sessionView(result.data) : null;
    if (session) return response.status(200).json(session);
    if (result.status >= 400 && result.status < 500) return response.status(401).json({ error: 'SESSION_EXPIRED' });
    return unavailable(response);
  }

  async function logout(request, response) {
    if (!prepare(request, response)) return;
    const header = request.headers?.authorization;
    const token = typeof header === 'string' && /^Bearer\s+\S+$/iu.test(header) ? header.split(/\s+/u)[1] : '';
    if (!token || token.length > MAX_TOKEN) return response.status(401).json({ error: 'LOGIN_REQUIRED' });
    const result = await callAuth('/logout?scope=local', { token });
    if (!result) return unavailable(response);
    // 이미 끝난 출입증(401)이어도 화면에서는 로그아웃된 것으로 본다.
    if (result.status < 300 || result.status === 401) return response.status(200).json({ ok: true });
    return unavailable(response);
  }

  return { login, refresh, logout };
}

let defaults;
export function defaultAuthHandlers() {
  defaults ??= createAuthHandlers();
  return defaults;
}
