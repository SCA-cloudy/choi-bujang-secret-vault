// POST /api/device/request: 이 기기의 공개 키를 "승인 대기"로 등록합니다. 권한은 생기지 않습니다. 처리는 src/device-api.mjs.
import { defaultDeviceHandlers } from '../../src/device-api.mjs';

export default function handler(request, response) {
  return defaultDeviceHandlers().requestApproval(request, response);
}
