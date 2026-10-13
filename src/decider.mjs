// ALEPH SDP 엔진이 확인한 요청만 받는 학생 판정기 시작점입니다.
// 6단계부터 규칙을 하나씩 추가합니다. 규칙에 걸리지 않은 요청은 모두 거부합니다.
// 요청 본문의 userId, role, 기기 키, 토큰을 별도로 믿거나 저장하지 마세요.
export const RULE_IDS = Object.freeze(['starter.deny', 'device_registered']);

export async function decide(request) {
  // 6단계 규칙 device_registered: 요청의 deviceRegistered 가 true 일 때만 허용합니다.
  // 값이 false 이거나 없거나 true 가 아닌 값이면 미등록으로 보고 거부합니다.
  if (request?.deviceRegistered === true) {
    return {
      schema: 'aleph.decision.v1',
      requestId: request.requestId,
      decision: 'allow',
      reasonCode: 'approved',
      ruleIds: [RULE_IDS[1]],
    };
  }
  return {
    schema: 'aleph.decision.v1',
    requestId: request?.requestId,
    decision: 'deny',
    reasonCode: 'device_not_registered',
    ruleIds: [RULE_IDS[1]],
  };
}
