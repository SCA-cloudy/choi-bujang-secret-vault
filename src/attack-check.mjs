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
    else if (typeof data?.code === 'string' && /^[A-Z0-9]{1,12}$/u.test(data.code)) errorCode = data.code;
  } catch {
    // JSON이 아니면 오류 문구 없음, 메모 0건으로 기록한다.
  }
  return { status: response.status, noteCount, errorCode };
}

export async function runAttackChecks(config) {
  if (![1, 2, 3, 4, 5, 6, 7, 8].includes(config.step)) {
    throw new Error('이 단계의 공격 점검을 src/attack-check.mjs에 구현해 주세요.');
  }
  const app = checkedAppUrl(config);
  if (typeof config.sampleMarker !== 'string' || !config.sampleMarker) throw new Error('가상 메모의 확인 표시를 넣어 주세요.');

  if (config.step >= 4) {
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
    const results = [
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
    if (config.step === 4) return results;

    // 5단계: 서버 함수를 거치지 않고 데이터 원본 주소를 로그인 없이 직접 읽어 본다.
    // 공개 키는 저장소에 없다. 학생이 셸에 SUPABASE_PUBLISHABLE_KEY를 넣어 둔 때만 그 키를 붙여 보내고,
    // 없으면 키 없이 보낸다. 어느 쪽이든 실제로 보낸 방식을 observed에 적고 키 값은 적지 않는다.
    let original;
    try {
      original = new URL(config.originalApiUrl);
    } catch {
      throw new Error('aleph.config.json의 originalApiUrl에 데이터 원본 HTTPS 주소를 넣어 주세요.');
    }
    if (original.protocol !== 'https:' || original.username || original.password || original.search || original.hash) {
      throw new Error('aleph.config.json의 originalApiUrl에 데이터 원본 HTTPS 주소를 넣어 주세요.');
    }
    const publicKey = typeof process.env.SUPABASE_PUBLISHABLE_KEY === 'string' ? process.env.SUPABASE_PUBLISHABLE_KEY.trim() : '';
    const direct = await anonymousApiResult(app, `${original.href}?select=id`, publicKey ? { headers: { apikey: publicKey } } : {});
    results.push({ attackId: 'original_api_direct_read',
      expected: '서버 함수를 거치지 않고 원본 주소를 로그인 없이 직접 읽으면 401 또는 403으로 거부, 메모 0건',
      observed: `${publicKey ? '공개 키를 붙여' : '키 없이'} 보낸 요청에서 HTTP ${direct.status}, 오류 문구 ${direct.errorCode}, 가상 메모 ${direct.noteCount}건이 보임` });
    if (config.step === 5) return results;

    // 6단계: 판정기(src/decider.mjs)의 기기 등록 규칙을 가상 요청으로 직접 불러 본다.
    // 사이트로 보내는 요청이 아니라 이 컴퓨터에서 판정기 함수를 호출한 결과이며, 심판의 판정이 아니다.
    const { decide } = await import('./decider.mjs');
    const tryDevice = async (deviceRegistered, method) => {
      const route = method === 'GET' ? 'GET /notes/:id' : `${method} /notes/:id`;
      const answer = await decide({ requestId: globalThis.crypto.randomUUID(), deviceRegistered, method, route, path: '/notes/demo' });
      return `${answer.decision} ${answer.reasonCode}`;
    };
    results.push(
      { attackId: 'decider_unregistered_device_denied',
        expected: '미등록 기기(deviceRegistered false)의 가상 읽기 요청은 deny와 device_not_registered로 거부 (판정기 함수를 직접 부른 연습)',
        observed: `판정기에 넣은 가상 요청의 결과: ${await tryDevice(false, 'GET')}` },
      { attackId: 'decider_registered_read_allowed',
        expected: '등록 기기(deviceRegistered true)의 가상 읽기 요청은 allow (판정기 함수를 직접 부른 연습)',
        observed: `판정기에 넣은 가상 요청의 결과: ${await tryDevice(true, 'GET')}` },
      { attackId: 'decider_registered_write_denied',
        expected: '등록 기기의 가상 쓰기 요청(POST)은 이 규칙이 허용하지 않아 deny (판정기 함수를 직접 부른 연습)',
        observed: `판정기에 넣은 가상 요청의 결과: ${await tryDevice(true, 'POST')}` },
    );
    if (config.step === 6) return results;

    // 7단계: 판정기의 추가 확인 규칙(step_up_required)을 가상 요청으로 직접 불러 본다.
    // 6단계와 같이 이 컴퓨터에서 판정기 함수를 부른 연습이며, 사이트로 보낸 요청도 심판의 판정도 아니다.
    // 엔진이 실제로 다시 로그인한 시각을 넘겨주는 흐름은 이 저장소에서 확인하지 못해 실제 자료 차단은 점검하지 않는다.
    const tryAccess = async ({ hour, network, count, stepUp }) => {
      const answer = await decide({
        requestId: globalThis.crypto.randomUUID(), deviceRegistered: true, method: 'GET',
        route: 'GET /notes/:id', path: '/notes/demo',
        signals: { source: 'judge_fixture', region: 'foreign', network, hour },
        stepUp: stepUp ?? { verified: false, authAgeSeconds: null },
        recentEvents: count ? [{ kind: 'risk_signal', ageSeconds: 60, count }] : [],
      });
      return `${answer.decision} ${answer.reasonCode}`;
    };
    const seenLocal = value => `판정기에 넣은 가상 요청의 결과: ${value}`;
    results.push(
      { attackId: 'decider_complex_event_step_up',
        expected: '평소와 다른 시각·처음 보는 네트워크·갑작스러운 대량 읽기가 겹친 가상 요청은 step_up과 step_up_required (판정기 함수를 직접 부른 연습)',
        observed: seenLocal(await tryAccess({ hour: 3, network: 'unusual', count: 20 })) },
      { attackId: 'decider_normal_event_allowed',
        expected: '정상 시각·익숙한 네트워크의 가상 읽기 요청은 allow (판정기 함수를 직접 부른 연습)',
        observed: seenLocal(await tryAccess({ hour: 14, network: 'usual', count: 0 })) },
      { attackId: 'decider_single_signal_allowed',
        expected: '신호가 하나뿐(낯선 지역·시각만 다름)인 가상 읽기 요청은 영구 차단 없이 allow (판정기 함수를 직접 부른 연습)',
        observed: seenLocal(await tryAccess({ hour: 3, network: 'usual', count: 0 })) },
      { attackId: 'decider_reverified_allowed',
        expected: '복합 사건이라도 추가 확인을 마친 뒤(60초 전) 다시 보낸 가상 요청은 allow (판정기 함수를 직접 부른 연습)',
        observed: seenLocal(await tryAccess({ hour: 3, network: 'unusual', count: 20, stepUp: { verified: true, authAgeSeconds: 60 } })) },
    );
    if (config.step === 7) return results;

    // 8단계: 판정기의 구역 규칙(resource_zone)을 가상 요청으로 직접 불러 본다.
    // 7단계와 같이 이 컴퓨터에서 판정기 함수를 부른 연습이며, 사이트로 보낸 요청도 심판의 판정도 아니다.
    // 남의 메모 차단은 요청 계약에 소유자 정보가 없어 판정기가 아니라 자료 API가 맡으므로 여기서 점검하지 않는다.
    const sampleId = '11111111-2222-4333-8444-555555555555';
    const tryZone = async (method, route, path) => {
      const answer = await decide({
        requestId: globalThis.crypto.randomUUID(), deviceRegistered: true, method, route, path,
        stepUp: { verified: false, authAgeSeconds: null },
      });
      return seenLocal(`${answer.decision} ${answer.reasonCode}`);
    };
    results.push(
      { attackId: 'decider_own_note_update_allowed',
        expected: '내 메모 구역(note.own)의 수정(PUT /notes/:id) 가상 요청은 allow (판정기 함수를 직접 부른 연습)',
        observed: await tryZone('PUT', 'PUT /notes/:id', `/notes/${sampleId}`) },
      { attackId: 'decider_notice_update_denied',
        expected: '강사 공지(notice.instructor) 수정(PUT /notices/:id) 가상 요청은 강사 역할을 확인할 수 없어 deny (판정기 함수를 직접 부른 연습)',
        observed: await tryZone('PUT', 'PUT /notices/:id', `/notices/${sampleId}`) },
      { attackId: 'decider_unknown_path_denied',
        expected: '표에 없는 경로와 :id 자리의 기능 이름(/notes/export) 가상 요청은 deny (판정기 함수를 직접 부른 연습)',
        observed: await tryZone('GET', 'GET /notes/:id', '/notes/export') },
    );
    return results;
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
