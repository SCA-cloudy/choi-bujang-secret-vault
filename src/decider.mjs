// ALEPH SDP 엔진이 확인한 요청만 받는 학생 판정기 시작점입니다.
// 6단계부터 규칙을 하나씩 추가합니다. 규칙에 걸리지 않은 요청은 모두 거부합니다.
// 요청 본문의 userId, role, 기기 키, 토큰을 별도로 믿거나 저장하지 마세요.
export const RULE_IDS = Object.freeze(['device_registered', 'step_up_required', 'resource_zone']);

// 7단계 입력 검사: 엔진이 검증해 넘긴 접속 정보(signals·stepUp·recentEvents)만 읽습니다.
// - 판정기가 읽는 값은 요청의 이 세 항목뿐입니다. 요청에 headers, geo 같은 다른 이름이
//   덧붙어 있어도 읽지 않으므로, 위조한 클라이언트 헤더는 접속 정보가 되지 않습니다.
// - signals.source 가 'judge_fixture'(엔진이 넘긴 가상 사건)일 때만 지역·시각·네트워크를 씁니다.
//   'none'이거나 다른 출처이거나 없으면 값이 없는 것으로 보고, 임의의 정상값으로 채우지 않습니다.
// - 형식이 맞지 않는 값은 null(모름)로 두며, 모름은 정상으로 바꾸지 않습니다.
const ENGINE_FIXTURE_SOURCE = 'judge_fixture';
const LABEL = /^[a-z][a-z_]{0,23}$/u;
const isPlain = value => value !== null && typeof value === 'object' && !Array.isArray(value);

export function readAccessInfo(request) {
  const raw = isPlain(request?.signals) ? request.signals : {};
  const fromEngine = raw.source === ENGINE_FIXTURE_SOURCE;
  const label = value => (fromEngine && typeof value === 'string' && value !== 'unknown' && LABEL.test(value) ? value : null);
  const hour = fromEngine && Number.isInteger(raw.hour) && raw.hour >= 0 && raw.hour <= 23 ? raw.hour : null;

  // 추가 확인(stepUp): verified 가 true 이고 나이가 0~900초일 때만 확인된 것으로 봅니다.
  const step = isPlain(request?.stepUp) ? request.stepUp : {};
  const verified = step.verified === true && Number.isInteger(step.authAgeSeconds)
    && step.authAgeSeconds >= 0 && step.authAgeSeconds <= 900;

  // 최근 사건: 최대 12건, 모양이 맞는 항목만 남깁니다.
  const events = Array.isArray(request?.recentEvents) ? request.recentEvents.slice(0, 12) : [];
  const recentEvents = events
    .filter(item => isPlain(item) && typeof item.kind === 'string' && LABEL.test(item.kind)
      && Number.isInteger(item.ageSeconds) && item.ageSeconds >= 0
      && Number.isInteger(item.count) && item.count >= 1 && item.count <= 1000000)
    .map(item => ({ kind: item.kind, ageSeconds: item.ageSeconds, count: item.count }));

  return {
    signals: { source: fromEngine ? 'engine_fixture' : 'none', region: label(raw.region), network: label(raw.network), hour },
    stepUp: { verified, authAgeSeconds: verified ? step.authAgeSeconds : null },
    recentEvents,
  };
}

// 7단계 규칙 step_up_required: 아래 세 신호가 한꺼번에 겹칠 때만 추가 확인(step_up)을 요구합니다.
//  1) 평소와 다른 시각(밤 22시~새벽 5시)  2) 처음 보는 네트워크(network 가 unusual)
//  3) 갑자기 많은 자료 읽기(최근 10분 안의 사건이 합쳐서 10건 이상)
// 지역(region)은 판단에 쓰지 않습니다. 지역 하나만으로는 추가 확인도 차단도 하지 않으며,
// 이 규칙은 영구 차단을 만들지 않습니다. 추가 확인(step_up)을 마치면 요청은 다시 판정됩니다.
// 신호 값이 없거나 믿을 수 없으면(null) 해당 신호는 "없음"으로 보고 이 규칙은 작동하지 않습니다.
const UNUSUAL_HOURS = Object.freeze({ lateFrom: 22, earlyUntil: 5 });
const UNFAMILIAR_NETWORK = 'unusual';
const BULK_READ = Object.freeze({ windowSeconds: 600, minCount: 10 });

function stepUpSignals(info) {
  const { hour, network } = info.signals;
  const bulk = info.recentEvents
    .filter(item => item.ageSeconds <= BULK_READ.windowSeconds)
    .reduce((sum, item) => sum + item.count, 0);
  return {
    unusualHour: hour !== null && (hour >= UNUSUAL_HOURS.lateFrom || hour <= UNUSUAL_HOURS.earlyUntil),
    unfamiliarNetwork: network === UNFAMILIAR_NETWORK,
    bulkRead: bulk >= BULK_READ.minCount,
  };
}

const isComplexAnomaly = info => Object.values(stepUpSignals(info)).every(Boolean);


// 8단계 규칙 resource_zone: 자료를 구역(자원 ID)으로 나누고, 엔진이 확인한 method·route·path만으로 판단합니다.
// - 이 파일 혼자 불러도 동작하도록 표를 안에 둡니다. src/resources.mjs의 표와 같아야 하며 test/decider-zone.test.mjs가 둘을 대조합니다.
// - 자원 ID는 경로 모양(route)에서만 고릅니다. 쿼리(queryLength·querySha256)는 기능을 고르는 데 쓰지 않습니다.
// - 허용하는 것은 내 메모 구역(note.own)의 읽기·수정뿐입니다: GET /notes, GET /notes/:id, PUT /notes/:id.
//   그 밖의 동작(추가·삭제), 알 수 없는 경로, 모양이 다른 경로는 모두 거부합니다.
// - 강사 공지(notice.instructor)는 거부합니다. 요청 계약에 강사 역할이 없어서 판정기가 강사인지 확인할 수 없고,
//   요청 본문·메뉴의 role 같은 값은 믿지 않으므로 공지 수정은 열 수 없습니다.
// - 어떤 메모가 누구의 것인지(소유자)는 요청 계약에 없어서 판정기는 보지 못합니다. 남의 메모 차단은 자료 API가 맡습니다.
const ZONE_RESOURCES = Object.freeze({
  'GET /notes': 'note.own',
  'POST /notes': 'note.own',
  'GET /notes/:id': 'note.own',
  'PUT /notes/:id': 'note.own',
  'DELETE /notes/:id': 'note.own',
  'GET /notices': 'notice.instructor',
  'GET /notices/:id': 'notice.instructor',
  'PUT /notices/:id': 'notice.instructor',
});
const OWN_NOTE_ACTIONS = Object.freeze(['GET /notes', 'GET /notes/:id', 'PUT /notes/:id']);
// :id 자리에 기능 이름이 들어 있으면(예: /notes/export) 자료 번호가 아니라 기능 경로이므로 거부합니다.
const FUNCTION_WORDS = Object.freeze(['export', 'import', 'search', 'list', 'all', 'bulk', 'batch', 'backup', 'download', 'admin', 'me', 'new']);
const ID_SEGMENT = /^[A-Za-z0-9_-]{1,64}$/u;

function inOwnNoteZone(request) {
  if (typeof request?.route !== 'string' || typeof request.path !== 'string' || typeof request.method !== 'string') return false;
  const shape = request.route.replace(/^([A-Z]+) \/api\//u, '$1 /');
  if (!Object.hasOwn(ZONE_RESOURCES, shape) || ZONE_RESOURCES[shape] !== 'note.own') return false;
  if (!OWN_NOTE_ACTIONS.includes(shape) || shape.split(' ')[0] !== request.method) return false;
  const path = request.path.replace(/^\/api\//u, '/');
  if (shape.endsWith(':id')) {
    const match = /^\/notes\/([^/]+)$/u.exec(path);
    return match !== null && ID_SEGMENT.test(match[1]) && !FUNCTION_WORDS.includes(match[1].toLowerCase());
  }
  return path === '/notes';
}

export async function decide(request) {
  // 6단계 규칙 device_registered: 등록된 기기(deviceRegistered 가 true)의 요청만 다음 규칙으로 넘깁니다.
  // 값이 false 이거나 없거나 true 가 아닌 값이면 미등록으로 보고 거부합니다.
  if (request?.deviceRegistered !== true) {
    return {
      schema: 'aleph.decision.v1',
      requestId: request?.requestId,
      decision: 'deny',
      reasonCode: 'device_not_registered',
      ruleIds: [RULE_IDS[0]],
    };
  }
  // 8단계 규칙 resource_zone: 등록 기기라도 내 메모 구역의 읽기·수정이 아니면 거부합니다.
  // (읽기가 아닌 동작 중 추가·삭제, 강사 공지, 알 수 없는 경로, 모양이 다른 경로가 모두 여기서 거부됩니다.)
  if (!inOwnNoteZone(request)) {
    return {
      schema: 'aleph.decision.v1',
      requestId: request.requestId,
      decision: 'deny',
      reasonCode: 'starter_not_ready',
      ruleIds: [RULE_IDS[2]],
    };
  }
  // 7단계 규칙 step_up_required: 복합 이상 신호가 겹쳤고 추가 확인이 아직 없으면 자료를 주지 않고 추가 확인을 요구합니다.
  const info = readAccessInfo(request);
  const anomaly = isComplexAnomaly(info);
  if (anomaly && !info.stepUp.verified) {
    return {
      schema: 'aleph.decision.v1',
      requestId: request.requestId,
      decision: 'step_up',
      reasonCode: 'step_up_required',
      ruleIds: [RULE_IDS[1]],
    };
  }
  return {
    schema: 'aleph.decision.v1',
    requestId: request.requestId,
    decision: 'allow',
    reasonCode: 'approved',
    ruleIds: anomaly ? [RULE_IDS[0], RULE_IDS[2], RULE_IDS[1]] : [RULE_IDS[0], RULE_IDS[2]],
  };
}
