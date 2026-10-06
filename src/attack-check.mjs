// The student changes this check as each stage adds an attack to the same app.
// Never return tokens, private keys, real names, or note bodies.
function checkedAppUrl(config) {
  let app;
  try {
    app = new URL(config.publicAppUrl);
  } catch {
    throw new Error('aleph.config.json의 실제 배포 주소를 먼저 넣어 주세요.');
  }
  if (app.protocol !== 'https:' || app.username || app.password || app.search || app.hash
      || app.pathname !== '/' || app.hostname.endsWith('.example')) {
    throw new Error('aleph.config.json의 실제 배포 주소를 먼저 넣어 주세요.');
  }
  return app;
}

// 로그인 정보 없이 요청하고, 상태 코드와 메모 개수만 돌려준다. 메모 본문은 돌려주지 않는다.
async function anonymousNoteCount(app, path) {
  const response = await fetch(new URL(path, app), {
    redirect: 'error', signal: AbortSignal.timeout(10000),
  });
  let noteCount = 0;
  try {
    const data = await response.json();
    if (Array.isArray(data?.notes)) noteCount = data.notes.length;
  } catch {
    // 본문이 JSON이 아니면 메모가 보이지 않는 것으로 기록한다.
  }
  return { status: response.status, noteCount };
}

export async function runAttackChecks(config) {
  if (config.step !== 1 && config.step !== 2) {
    throw new Error('이 단계의 공격 점검을 src/attack-check.mjs에 구현해 주세요.');
  }
  const app = checkedAppUrl(config);
  if (typeof config.sampleMarker !== 'string' || !config.sampleMarker) throw new Error('가상 메모의 확인 표시를 넣어 주세요.');

  if (config.step === 2) {
    const staticData = await anonymousNoteCount(app, '/data.json');
    const api = await anonymousNoteCount(app, '/api/notes');
    return [
      { attackId: 'static_data_json_read',
        expected: '공개 /data.json에는 가상 메모가 없어야 함 (404 또는 0건)',
        observed: `비로그인 요청에서 HTTP ${staticData.status}, 가상 메모 ${staticData.noteCount}건이 보임` },
      { attackId: 'anonymous_api_notes_read',
        expected: '3단계 전이라 /api/notes는 아직 공개 상태. 열려 있는 약점으로 기록',
        observed: `비로그인 요청에서 HTTP ${api.status}, 가상 메모 ${api.noteCount}건이 보임` },
    ];
  }

  const response = await fetch(new URL('/data.json', app), {
    redirect: 'error', signal: AbortSignal.timeout(10000),
  });
  let visible = false;
  if (response.ok) {
    try {
      const data = await response.json();
      visible = data?.sampleMarker === config.sampleMarker && Array.isArray(data.notes)
        && data.notes.length > 0;
    } catch {
      // A non-JSON response is a failed check, not a successful deployment.
    }
  }
  return [{ attackId: 'anonymous_note_read', expected: '비로그인 화면에서 가상 메모를 확인',
    observed: visible ? '비로그인 요청에서 공개 가상 메모 확인 표시가 보임' : `비로그인 요청에서 확인 표시가 보이지 않음 (HTTP ${response.status})` }];
}
