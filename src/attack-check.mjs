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

// 로그인 정보 없이(또는 일부러 틀린 값 없이) 요청하고, 상태 코드·오류 문구·메모 개수만 돌려준다.
// POST 점검은 로그인 검사를 통과하더라도 저장되지 않도록 일부러 비어 있는(잘못된) 본문을 보낸다.
async function anonymousApiResult(app, path, init = {}) {
  const response = await fetch(new URL(path, app), {
    ...init, redirect: 'error', signal: AbortSignal.timeout(10000),
  });
  let noteCount = 0;
  let errorCode = '없음';
  try {
    const data = await response.json();
    if (Array.isArray(data)) noteCount = data.length;
    else if (Array.isArray(data?.notes)) noteCount = data.notes.length;
    if (typeof data?.error === 'string' && /^[A-Z_]{1,40}$/u.test(data.error)) errorCode = data.error;
  } catch {
    // JSON이 아니면 오류 문구 없음, 메모 0건으로 기록한다.
  }
  return { status: response.status, noteCount, errorCode };
}

export async function runAttackChecks(config) {
  if (![1, 2, 3, 4].includes(config.step)) {
    throw new Error('이 단계의 공격 점검을 src/attack-check.mjs에 구현해 주세요.');
  }
  const app = checkedAppUrl(config);
  if (typeof config.sampleMarker !== 'string' || !config.sampleMarker) throw new Error('가상 메모의 확인 표시를 넣어 주세요.');

  if (config.step === 4) {
    // 이 점검은 로그인 정보 없이 보내는 요청만 한다. 두 번째 계정(B)이 A의 메모를 읽거나 고치는 시험은
    // 로그인이 필요해 여기서 하지 않으며, 화면과 콘솔로 직접 확인한 결과를 README에 따로 적는다.
    // 수정·삭제 점검은 실제로 없는 가짜 메모 번호로만 보내 어떤 메모도 바뀌지 않는다.
    const missingId = '00000000-0000-4000-8000-000000000000';
    const staticData = await anonymousNoteCount(app, '/data.json');
    const list = await anonymousApiResult(app, '/api/notes');
    const create = await anonymousApiResult(app, '/api/notes', {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}',
    });
    const update = await anonymousApiResult(app, `/api/notes/${missingId}`, {
      method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: '{}',
    });
    const remove = await anonymousApiResult(app, `/api/notes/${missingId}`, { method: 'DELETE' });
    const seen = result => `비로그인 요청에서 HTTP ${result.status}, 오류 문구 ${result.errorCode}, 가상 메모 ${result.noteCount}건이 보임`;
    return [
      { attackId: 'static_data_json_read',
        expected: '공개 /data.json에는 가상 메모가 없어야 함 (404 또는 0건)',
        observed: `비로그인 요청에서 HTTP ${staticData.status}, 가상 메모 ${staticData.noteCount}건이 보임` },
      { attackId: 'anonymous_notes_list_read',
        expected: '로그인 없이 메모 목록을 요청하면 401 또는 403과 JSON 오류 문구, 메모 0건',
        observed: seen(list) },
      { attackId: 'anonymous_note_create',
        expected: '로그인 없이 메모 추가를 요청하면 401 또는 403으로 거부',
        observed: seen(create) },
      { attackId: 'anonymous_note_update',
        expected: '로그인 없이 메모 수정을 요청하면 401 또는 403으로 거부 (없는 가짜 번호로 시험)',
        observed: seen(update) },
      { attackId: 'anonymous_note_delete',
        expected: '로그인 없이 메모 삭제를 요청하면 401 또는 403으로 거부 (없는 가짜 번호로 시험)',
        observed: seen(remove) },
    ];
  }

  if (config.step === 3) {
    const staticData = await anonymousNoteCount(app, '/data.json');
    const list = await anonymousApiResult(app, '/api/notes');
    const create = await anonymousApiResult(app, '/api/notes', {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}',
    });
    const seen = result => `비로그인 요청에서 HTTP ${result.status}, 오류 문구 ${result.errorCode}, 가상 메모 ${result.noteCount}건이 보임`;
    return [
      { attackId: 'static_data_json_read',
        expected: '공개 /data.json에는 가상 메모가 없어야 함 (404 또는 0건)',
        observed: `비로그인 요청에서 HTTP ${staticData.status}, 가상 메모 ${staticData.noteCount}건이 보임` },
      { attackId: 'anonymous_notes_list_read',
        expected: '로그인 없이 메모 목록을 요청하면 401 또는 403과 JSON 오류 문구, 메모 0건',
        observed: seen(list) },
      { attackId: 'anonymous_note_create',
        expected: '로그인 없이 메모 추가를 요청하면 401 또는 403으로 거부',
        observed: seen(create) },
    ];
  }

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
