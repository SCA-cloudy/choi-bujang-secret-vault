// ALEPH SDP 엔진이 확인한 요청만 받는 학생 판정기 시작점입니다.
// 6단계부터 규칙을 하나씩 추가합니다. 규칙에 걸리지 않은 요청은 모두 거부합니다.
// 요청 본문의 userId, role, 기기 키, 토큰을 별도로 믿거나 저장하지 마세요.
export const RULE_IDS = Object.freeze(['device_registered']);

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

export async function decide(request) {
  // 6단계 규칙 device_registered: 등록된 기기(deviceRegistered 가 true)의 읽기(GET) 요청만 허용합니다.
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
  // 등록된 기기라도 읽기가 아닌 동작(추가·수정·삭제 등)은 이 규칙이 허용하지 않으므로 거부합니다.
  if (request.method !== 'GET') {
    return {
      schema: 'aleph.decision.v1',
      requestId: request.requestId,
      decision: 'deny',
      reasonCode: 'starter_not_ready',
      ruleIds: [RULE_IDS[0]],
    };
  }
  return {
    schema: 'aleph.decision.v1',
    requestId: request.requestId,
    decision: 'allow',
    reasonCode: 'approved',
    ruleIds: [RULE_IDS[0]],
  };
}
