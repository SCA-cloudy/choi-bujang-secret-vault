// 2단계: 서버에서만 학습용 DB(Supabase)를 읽어 가상 메모를 돌려줍니다.
// SUPABASE_URL과 SUPABASE_SECRET_KEY는 Vercel 환경변수에서만 읽습니다.
// 키 값은 브라우저 파일·응답·로그 어디에도 내보내지 않습니다.
import { createClient } from '@supabase/supabase-js';

export default async function handler(request, response) {
  response.setHeader('Cache-Control', 'no-store');
  if (request.method !== 'GET') {
    response.setHeader('Allow', 'GET');
    return response.status(405).json({ error: 'METHOD_NOT_ALLOWED' });
  }

  const url = process.env.SUPABASE_URL;
  const key = process.env.SUPABASE_SECRET_KEY;
  if (!url || !key) {
    console.error('notes: 서버 환경변수가 설정되지 않았습니다.');
    return response.status(500).json({ error: 'NOTES_UNAVAILABLE' });
  }

  try {
    const db = createClient(url, key, {
      auth: { persistSession: false, autoRefreshToken: false },
    });
    const { data, error } = await db
      .from('notes')
      .select('title, content')
      .order('created_at', { ascending: true });
    if (error) {
      console.error('notes: 읽기 실패', error.code ?? 'unknown');
      return response.status(500).json({ error: 'NOTES_UNAVAILABLE' });
    }
    return response.status(200).json({ notes: data });
  } catch {
    console.error('notes: 자료를 읽지 못했습니다.');
    return response.status(500).json({ error: 'NOTES_UNAVAILABLE' });
  }
}
