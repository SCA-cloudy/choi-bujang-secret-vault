// 3단계 제작 2: 로그인한 요청만 메모를 읽을 수 있습니다.
// 토큰 검사는 src/verify-login.mjs(코스가 준 도우미)에 맡기고, 여기서는 고치거나 새로 만들지 않습니다.
// 브라우저가 보낸 userId·role 같은 값은 믿지 않고, 검사를 통과한 결과만 씁니다.
// SUPABASE_URL과 SUPABASE_SECRET_KEY는 Vercel 환경변수에서만 읽고, 어디에도 내보내지 않습니다.
import { readFileSync } from 'node:fs';

let loginVerifier;

async function defaultVerifyAuthorization(authorization) {
  if (!loginVerifier) {
    const { createLoginVerifier } = await import('../src/verify-login.mjs');
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

async function defaultReadNotes() {
  const url = process.env.SUPABASE_URL;
  const key = process.env.SUPABASE_SECRET_KEY;
  if (!url || !key) throw new Error('missing_env');
  const { createClient } = await import('@supabase/supabase-js');
  const db = createClient(url, key, {
    auth: { persistSession: false, autoRefreshToken: false },
  });
  const { data, error } = await db
    .from('notes')
    .select('title, content')
    .order('created_at', { ascending: true });
  if (error) throw new Error(`read_failed:${error.code ?? 'unknown'}`);
  return data;
}

export function createNotesHandler({
  verifyAuthorization = defaultVerifyAuthorization,
  readNotes = defaultReadNotes,
} = {}) {
  return async function handler(request, response) {
    response.setHeader('Cache-Control', 'no-store');
    response.setHeader('Vary', 'Authorization');
    if (request.method !== 'GET') {
      response.setHeader('Allow', 'GET');
      return response.status(405).json({ error: 'METHOD_NOT_ALLOWED' });
    }

    // 토큰이 없거나, 위조·만료·다른 서비스용이면 검사 결과가 null이다. 그때는 자료 없이 거부한다.
    let identity = null;
    try {
      identity = await verifyAuthorization(request.headers?.authorization);
    } catch {
      console.error('notes: 로그인 검사를 끝내지 못했습니다.');
      identity = null;
    }
    if (!identity) {
      response.setHeader('WWW-Authenticate', 'Bearer');
      return response.status(401).json({ error: 'LOGIN_REQUIRED' });
    }

    try {
      const notes = await readNotes();
      return response.status(200).json({ notes });
    } catch (error) {
      console.error('notes: 자료를 읽지 못했습니다.', String(error?.message ?? '').slice(0, 40));
      return response.status(500).json({ error: 'NOTES_UNAVAILABLE' });
    }
  };
}

export default createNotesHandler();
