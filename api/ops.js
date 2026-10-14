// GET /api/ops: 탈환 작전실 요약(판정기 규칙·탐지·회수 상태·복구 버전). 로그인과 승인된 기기 서명이 필요합니다. 처리는 src/ops-api.mjs.
import { defaultOpsHandler } from '../src/ops-api.mjs';

export default function handler(request, response) {
  return defaultOpsHandler()(request, response);
}
